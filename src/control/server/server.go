//
// (C) Copyright 2018-2023 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package server

import (
	"context"
	"net"
	"os"
	"os/signal"
	"os/user"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/daos-stack/daos/src/control/build"
	"github.com/daos-stack/daos/src/control/common"
	ctlpb "github.com/daos-stack/daos/src/control/common/proto/ctl"
	mgmtpb "github.com/daos-stack/daos/src/control/common/proto/mgmt"
	"github.com/daos-stack/daos/src/control/events"
	"github.com/daos-stack/daos/src/control/lib/control"
	"github.com/daos-stack/daos/src/control/lib/daos"
	"github.com/daos-stack/daos/src/control/lib/hardware"
	"github.com/daos-stack/daos/src/control/lib/hardware/hwprov"
	"github.com/daos-stack/daos/src/control/logging"
	"github.com/daos-stack/daos/src/control/security"
	"github.com/daos-stack/daos/src/control/server/config"
	"github.com/daos-stack/daos/src/control/server/engine"
	"github.com/daos-stack/daos/src/control/server/storage"
	"github.com/daos-stack/daos/src/control/system"
	"github.com/daos-stack/daos/src/control/system/raft"
)

// non-exported package-scope function variable for mocking in unit tests
var osSetenv = os.Setenv

func processConfig(log logging.Logger, cfg *config.Server, fis *hardware.FabricInterfaceSet, mi *common.MemInfo, lookupNetIF ifLookupFn, affSrcs ...config.EngineAffinityFn) error {
	processFabricProvider(cfg)

	if err := cfg.SetEngineAffinities(log, affSrcs...); err != nil {
		return errors.Wrap(err, "failed to set engine affinities")
	}

	if err := cfg.Validate(log); err != nil {
		return errors.Wrapf(err, "%s: validation failed", cfg.Path)
	}

	if err := cfg.SetNrHugepages(log, mi); err != nil {
		return err
	}

	if err := cfg.SetRamdiskSize(log, mi); err != nil {
		return err
	}

	for _, ec := range cfg.Engines {
		if err := checkFabricInterface(ec.Fabric.Interface, lookupNetIF); err != nil {
			return err
		}

		if err := updateFabricEnvars(log, ec, fis); err != nil {
			return errors.Wrap(err, "update engine fabric envars")
		}
	}

	cfg.SaveActiveConfig(log)

	if err := setDaosHelperEnvs(cfg, osSetenv); err != nil {
		return err
	}

	return nil
}

func processFabricProvider(cfg *config.Server) {
	if shouldAppendRXM(cfg.Fabric.Provider) {
		cfg.WithFabricProvider(cfg.Fabric.Provider + ";ofi_rxm")
	}
}

func shouldAppendRXM(provider string) bool {
	return provider == "ofi+verbs"
}

// server struct contains state and components of DAOS Server.
type server struct {
	log         logging.Logger
	cfg         *config.Server
	hostname    string
	runningUser *user.User
	faultDomain *system.FaultDomain
	ctlAddr     *net.TCPAddr
	netDevClass hardware.NetDevClass
	listener    net.Listener

	harness      *EngineHarness
	membership   *system.Membership
	sysdb        *raft.Database
	pubSub       *events.PubSub
	evtForwarder *control.EventForwarder
	evtLogger    *control.EventLogger
	ctlSvc       *ControlService
	mgmtSvc      *mgmtSvc
	grpcServer   *grpc.Server

	cbLock           sync.Mutex
	onEnginesStarted []func(context.Context) error
	onShutdown       []func()
}

func newServer(log logging.Logger, cfg *config.Server, faultDomain *system.FaultDomain) (*server, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, errors.Wrap(err, "get hostname")
	}

	cu, err := user.Current()
	if err != nil {
		return nil, errors.Wrap(err, "get username")
	}

	// todo: 传递容错域信息给engine
	harness := NewEngineHarness(log).WithFaultDomain(faultDomain)

	return &server{
		log:         log,
		cfg:         cfg,
		hostname:    hostname,
		runningUser: cu,
		faultDomain: faultDomain,
		harness:     harness,
	}, nil
}

func track(msg string) (string, time.Time) {
	return msg, time.Now()
}

func (srv *server) logDuration(msg string, start time.Time) {
	srv.log.Debugf("%v: %v\n", msg, time.Since(start))
}

// CreateDatabaseConfig creates a new database configuration.
func CreateDatabaseConfig(cfg *config.Server) (*raft.DatabaseConfig, error) {
	// 获取replica 信息（其实就是daos_server.yml 里 accesslist 解析后的列表）
	// 所以假设一个daos 集群有四个server，那么daos_control.yml 里的hostlist 需要配置四个ip
	// daos_server.yml 里面accesslist 配置三个ip。那么accesslist 中的就是replica，剩下的那个不是replica（即既不是leader，也不是非leader，根本就不参与raft 功能）
	dbReplicas, err := cfgGetReplicas(cfg, net.LookupIP)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve replicas from config")
	}

	// 根据scm 挂载点，生成control_raft 目录
	// /mnt/s0/control_raft
	raftDir := cfgGetRaftDir(cfg)
	if raftDir == "" {
		return nil, errors.New("raft directory not available (missing SCM or control metadata in config?)")
	}

	// 构建db 里的conf 中的Replica 信息
	// 传入raft 的dir 地址
	return &raft.DatabaseConfig{
		Replicas:   dbReplicas,
		RaftDir:    raftDir,
		SystemName: cfg.SystemName,
	}, nil
}

// newManagementDatabase creates a new instance of the raft-backed management database.
// 创建一个基于raft 的db 实例
func newManagementDatabase(log logging.Logger, cfg *config.Server) (*raft.Database, error) {
	// 获取raft db的配置信息
	dbCfg, err := CreateDatabaseConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database config")
	}

	// If this daos_server instance ends up being the MS leader,
	// this will record the DAOS system membership.
	// 根据conf 创建一个db 并返回
	// 调用raft 包中的public 函数，返回一个raft 包下的Database struct 类型的实例
	return raft.NewDatabase(log, dbCfg)
}

// createServices builds scaffolding for rpc and event services.
func (srv *server) createServices(ctx context.Context) (err error) {
	// 先创建system db 的结构体实例
	srv.sysdb, err = newManagementDatabase(srv.log, srv.cfg)
	if err != nil {
		return
	}
	srv.membership = system.NewMembership(srv.log, srv.sysdb)

	// Create rpcClient for inter-server communication.
	cliCfg := control.DefaultConfig()
	cliCfg.TransportConfig = srv.cfg.TransportConfig
	rpcClient := control.NewClient(
		control.WithClientComponent(build.ComponentServer),
		control.WithConfig(cliCfg),
		control.WithClientLogger(srv.log))

	// Create event distribution primitives.
	srv.pubSub = events.NewPubSub(ctx, srv.log)
	srv.OnShutdown(srv.pubSub.Close)
	srv.evtForwarder = control.NewEventForwarder(rpcClient, srv.cfg.AccessPoints)
	srv.evtLogger = control.NewEventLogger(srv.log)

	// nvme 的控制器服务，prepare 和scan 请求都会通过这个控制器服务来完成
	srv.ctlSvc = NewControlService(srv.log, srv.harness, srv.cfg, srv.pubSub,
		hwprov.DefaultFabricScanner(srv.log))
	srv.mgmtSvc = newMgmtSvc(srv.harness, srv.membership, srv.sysdb, rpcClient, srv.pubSub)

	if err := srv.mgmtSvc.systemProps.UpdateCompPropVal(daos.SystemPropertyDaosSystem, func() string {
		return srv.cfg.SystemName
	}); err != nil {
		return err
	}

	return nil
}

// OnEnginesStarted adds callback functions to be called when all engines have
// started up.
func (srv *server) OnEnginesStarted(fns ...func(context.Context) error) {
	srv.cbLock.Lock()
	srv.onEnginesStarted = append(srv.onEnginesStarted, fns...)
	srv.cbLock.Unlock()
}

// OnShutdown adds callback functions to be called when the server shuts down.
func (srv *server) OnShutdown(fns ...func()) {
	srv.cbLock.Lock()
	srv.onShutdown = append(srv.onShutdown, fns...)
	srv.cbLock.Unlock()
}

func (srv *server) shutdown() {
	srv.cbLock.Lock()
	onShutdownCbs := srv.onShutdown
	srv.cbLock.Unlock()
	for _, fn := range onShutdownCbs {
		fn()
	}
}

func (srv *server) setCoreDumpFilter() error {
	if srv.cfg.CoreDumpFilter == 0 {
		return nil
	}

	srv.log.Debugf("setting core dump filter to 0x%x", srv.cfg.CoreDumpFilter)

	// Set core dump filter.
	if err := writeCoreDumpFilter(srv.log, "/proc/self/coredump_filter", srv.cfg.CoreDumpFilter); err != nil {
		return errors.Wrap(err, "failed to set core dump filter")
	}

	return nil
}

// initNetwork resolves local address and starts TCP listener.
func (srv *server) initNetwork() error {
	defer srv.logDuration(track("time to init network"))

	// server conf 里配置的port
	ctlAddr, err := getControlAddr(ctlAddrParams{
		port:           srv.cfg.ControlPort,
		replicaAddrSrc: srv.sysdb,
		lookupHost:     net.LookupIP,
	})
	if err != nil {
		return err
	}

	// 创建listener
	listener, err := createListener(ctlAddr, net.Listen)
	if err != nil {
		return err
	}
	srv.ctlAddr = ctlAddr
	srv.listener = listener

	return nil
}

// 创建引擎
func (srv *server) createEngine(ctx context.Context, idx int, cfg *engine.Config) (*EngineInstance, error) {
	// Closure to join an engine instance to a system using control API.
	// 闭包：添加engine 到system
	joinFn := func(ctxIn context.Context, req *control.SystemJoinReq) (*control.SystemJoinResp, error) {
		req.SetHostList(srv.cfg.AccessPoints)
		req.SetSystem(srv.cfg.SystemName)
		req.ControlAddr = srv.ctlAddr

		return control.SystemJoin(ctxIn, srv.mgmtSvc.rpcClient, req)
	}

	// 创建新engine，创建成功后执行闭包函数 joinFn
	// server 启动engine 是通过runner 来进行，这里新建了一个runner
	engine := NewEngineInstance(srv.log, storage.DefaultProvider(srv.log, idx, &cfg.Storage), joinFn,
		engine.NewRunner(srv.log, cfg)).WithHostFaultDomain(srv.harness.faultDomain)
	// 如果idx 为0，创建control_raft 下的daos_system.db
	if idx == 0 {
		// sysdb 结构体实例已经在 createServices 函数中初始化
		configureFirstEngine(ctx, engine, srv.sysdb, joinFn)
	}

	return engine, nil
}

// addEngines creates and adds engine instances to harness then starts goroutine to execute
// callbacks when all engines are started.
func (srv *server) addEngines(ctx context.Context) error {
	var allStarted sync.WaitGroup
	registerTelemetryCallbacks(ctx, srv)

	iommuEnabled, err := hwprov.DefaultIOMMUDetector(srv.log).IsIOMMUEnabled()
	if err != nil {
		return err
	}

	// todo: prepare 和scan

	// Allocate hugepages and rebind NVMe devices to userspace drivers.
	// 申请大页，重新绑定nvme 到用户空间
	if err := prepBdevStorage(srv, iommuEnabled); err != nil {
		return err
	}

	// Retrieve NVMe device details (before engines are started) so static details can be
	// recovered by the engine storage provider(s) during scan even if devices are in use.
	nvmeScanResp, err := scanBdevStorage(srv)
	if err != nil {
		return err
	}

	if len(srv.cfg.Engines) == 0 {
		return nil
	}

	nrEngineBdevsIdx := -1
	nrEngineBdevs := -1
	// 根据配置文件，依次创建engine
	for i, c := range srv.cfg.Engines {
		// i 是0 时会创建db
		// engine 里有个runner，runner 的start 函数是server 通过命令行启动engine的
		engine, err := srv.createEngine(ctx, i, c)
		if err != nil {
			return errors.Wrap(err, "creating engine instances")
		}

		// todo: 为新创建的engine 分配bdev
		if err := setEngineBdevs(engine, nvmeScanResp, &nrEngineBdevsIdx, &nrEngineBdevs); err != nil {
			return errors.Wrap(err, "setting engine bdevs")
		}

		// 注册事件，关注engine 的启动消息
		registerEngineEventCallbacks(srv, engine, &allStarted)

		if err := srv.harness.AddInstance(engine); err != nil {
			return err
		}
		// increment count of engines waiting to start
		allStarted.Add(1)
	}

	// 等待所有的engine 都启动
	go func() {
		srv.log.Debug("waiting for engines to start...")
		allStarted.Wait()
		srv.log.Debug("engines have started")

		srv.cbLock.Lock()
		onEnginesStartedCbs := srv.onEnginesStarted
		srv.cbLock.Unlock()
		for _, cb := range onEnginesStartedCbs {
			if err := cb(ctx); err != nil {
				srv.log.Errorf("on engines started: %s", err)
			}
		}
	}()

	return nil
}

// setupGrpc creates a new grpc server and registers services.
func (srv *server) setupGrpc() error {
	srvOpts, err := getGrpcOpts(srv.log, srv.cfg.TransportConfig, srv.sysdb.IsLeader)
	if err != nil {
		return err
	}

	srv.grpcServer = grpc.NewServer(srvOpts...)
	ctlpb.RegisterCtlSvcServer(srv.grpcServer, srv.ctlSvc)

	srxSetting, err := getSrxSetting(srv.cfg)
	if err != nil {
		return err
	}
	srv.mgmtSvc.clientNetworkHint = &mgmtpb.ClientNetHint{
		Provider:        srv.cfg.Fabric.Provider,
		CrtCtxShareAddr: srv.cfg.Fabric.CrtCtxShareAddr,
		CrtTimeout:      srv.cfg.Fabric.CrtTimeout,
		NetDevClass:     uint32(srv.netDevClass),
		SrvSrxSet:       srxSetting,
		EnvVars:         srv.cfg.ClientEnvVars,
	}
	mgmtpb.RegisterMgmtSvcServer(srv.grpcServer, srv.mgmtSvc)

	tSec, err := security.DialOptionForTransportConfig(srv.cfg.TransportConfig)
	if err != nil {
		return err
	}
	if err := srv.sysdb.ConfigureTransport(srv.grpcServer, tSec); err != nil {
		return err
	}

	return nil
}

func (srv *server) registerEvents() {
	registerFollowerSubscriptions(srv)

	srv.sysdb.OnLeadershipGained(
		func(ctx context.Context) error {
			srv.log.Infof("MS leader running on %s", srv.hostname)
			srv.mgmtSvc.startLeaderLoops(ctx)
			registerLeaderSubscriptions(srv)
			srv.log.Debugf("requesting immediate GroupUpdate after leader change")
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
						// Wait for at least one engine to be ready to service the
						// GroupUpdate request.
						for _, ei := range srv.harness.Instances() {
							if ei.IsReady() {
								srv.mgmtSvc.reqGroupUpdate(ctx, true)
								return
							}
						}
						srv.log.Debugf("no engines ready for GroupUpdate; waiting %s", groupUpdateInterval)
						time.Sleep(groupUpdateInterval)
					}
				}
			}()
			return nil
		},
		func(ctx context.Context) error {
			return srv.mgmtSvc.checkPools(ctx, true)
		},
	)
	srv.sysdb.OnLeadershipLost(func() error {
		srv.log.Infof("MS leader no longer running on %s", srv.hostname)
		registerFollowerSubscriptions(srv)
		return nil
	})
}

// 从下面大Start 过来的
func (srv *server) start(ctx context.Context) error {
	defer srv.logDuration(track("time server was listening"))

	go func() {
		_ = srv.grpcServer.Serve(srv.listener)
	}()
	defer srv.grpcServer.Stop()

	// noop on release builds
	control.StartPProf(srv.log)

	// daos_server 的监听，使用的是server conf 里配置的port
	// todo: drpc 那么server 和engine 不是各自都需要一个端口吗？conf 里只有一个
	srv.log.Infof("%s v%s (pid %d) listening on %s", build.ControlPlaneName,
		build.DaosVersion, os.Getpid(), srv.ctlAddr)

	drpcSetupReq := &drpcServerSetupReq{
		log:     srv.log,
		sockDir: srv.cfg.SocketDir,
		engines: srv.harness.Instances(),
		tc:      srv.cfg.TransportConfig,
		sysdb:   srv.sysdb,
		events:  srv.pubSub,
	}
	// Single daos_server dRPC server to handle all engine requests
	if err := drpcServerSetup(ctx, drpcSetupReq); err != nil {
		return errors.WithMessage(err, "dRPC server setup")
	}
	defer func() {
		if err := drpcCleanup(srv.cfg.SocketDir); err != nil {
			srv.log.Errorf("error during dRPC cleanup: %s", err)
		}
	}()

	// loop
	srv.mgmtSvc.startAsyncLoops(ctx)

	if srv.cfg.AutoFormat {
		srv.log.Notice("--auto flag set on server start so formatting storage now")
		if _, err := srv.ctlSvc.StorageFormat(ctx, &ctlpb.StorageFormatReq{}); err != nil {
			return errors.WithMessage(err, "attempting to auto format")
		}
	}

	// engine 启动！！！
	// harness 是负责管理engine instance 的
	return errors.Wrapf(srv.harness.Start(ctx, srv.sysdb, srv.cfg),
		"%s harness exited", build.ControlPlaneName)
}

func waitFabricReady(ctx context.Context, log logging.Logger, cfg *config.Server) error {
	ifaces := make([]string, 0, len(cfg.Engines))
	for _, eng := range cfg.Engines {
		ifaces = append(ifaces, eng.Fabric.Interface)
	}

	// Skip wait if no fabric interfaces specified in config.
	if len(ifaces) == 0 {
		return nil
	}

	if err := hardware.WaitFabricReady(ctx, log, hardware.WaitFabricReadyParams{
		StateProvider:  hwprov.DefaultNetDevStateProvider(log),
		FabricIfaces:   ifaces,
		IterationSleep: time.Second,
	}); err != nil {
		return err
	}

	return nil
}

func genFiAffFn(fis *hardware.FabricInterfaceSet) config.EngineAffinityFn {
	return func(l logging.Logger, e *engine.Config) (uint, error) {
		fi, err := fis.GetInterfaceOnNetDevice(e.Fabric.Interface, e.Fabric.Provider)
		if err != nil {
			return 0, err
		}
		return fi.NUMANode, nil
	}
}

func lookupIF(name string) (netInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, errors.Wrapf(err,
			"unable to retrieve interface %q", name)
	}
	return iface, nil
}

// Start is the entry point for a daos_server instance.
// 调用：start.go func (cmd *startCmd) Execute
func Start(log logging.Logger, cfg *config.Server) error {
	if err := common.CheckDupeProcess(); err != nil {
		return err
	}

	// Create the root context here. All contexts should inherit from this one so
	// that they can be shut down from one place.
	ctx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	hwprovFini, err := hwprov.Init(log)
	if err != nil {
		return err
	}
	defer hwprovFini()

	if err := waitFabricReady(ctx, log, cfg); err != nil {
		return err
	}

	scanner := hwprov.DefaultFabricScanner(log)

	// 扫描fabric
	fis, err := scanner.Scan(ctx, cfg.Fabric.Provider)
	if err != nil {
		return errors.Wrap(err, "scan fabric")
	}

	mi, err := common.GetMemInfo()
	if err != nil {
		return errors.Wrapf(err, "retrieve system memory info")
	}

	if err = processConfig(log, cfg, fis, mi, lookupIF, genFiAffFn(fis)); err != nil {
		return err
	}

	// 容错域
	// todo: 跟放置策略和数据恢复有啥关系
	faultDomain, err := getFaultDomain(cfg)
	if err != nil {
		return err
	}
	log.Debugf("fault domain: %s", faultDomain.String())

	// 根据容错域和配置信息新建server
	srv, err := newServer(log, cfg, faultDomain)
	if err != nil {
		return err
	}
	defer srv.shutdown()

	if err := srv.setCoreDumpFilter(); err != nil {
		return err
	}

	if srv.netDevClass, err = getFabricNetDevClass(cfg, fis); err != nil {
		return err
	}

	// 创建server 的服务
	// 包括创建srv 的Database 类型实例，但还没创建daos_system.db 文件（在addEngines 函数里完成）
	// 包括发送给nvme 设备 prepare / scan 请求的控制器服务
	if err := srv.createServices(ctx); err != nil {
		return err
	}

	// 初始化网络
	if err := srv.initNetwork(); err != nil {
		return err
	}

	// 创建conf 中配置的所有engine，并执行join 操作
	// todo: 这里engine 都干了啥
	if err := srv.addEngines(ctx); err != nil {
		return err
	}

	if err := srv.setupGrpc(); err != nil {
		return err
	}

	// 事件注册
	srv.registerEvents()

	// 处理daos_server 进程接收信号
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		srv.log.Debugf("Caught signal: %s", sig)
		shutdown()
	}()

	// 调用小start 启动server，包括server 通过命令行启动engine
	return srv.start(ctx)
}
