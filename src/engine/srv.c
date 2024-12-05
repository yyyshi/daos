/*
 * (C) Copyright 2016-2023 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
/**
 * \file
 *
 * This file is part of the DAOS server. It implements the DAOS service
 * including:
 * - network setup
 * - start/stop execution streams
 * - bind execution streams to core/NUMA node
 */

#define D_LOGFAC       DD_FAC(server)

#include <abt.h>
#include <libgen.h>
#include <daos/common.h>
#include <daos/event.h>
#include <daos/sys_db.h>
#include <daos_errno.h>
#include <daos_mgmt.h>
#include <daos_srv/bio.h>
#include <daos_srv/smd.h>
#include <daos_srv/vos.h>
#include <gurt/list.h>
#include <gurt/telemetry_producer.h>
#include "drpc_internal.h"
#include "srv_internal.h"

// ============= 不同 xstream介绍 ==============
/*
	1. 每个engine 有一组target xs们。每个vos target 都对应一个target xs，目的是避免访问vos 文件时候锁竞争。
	2. 同一个engine 下的所有target xs 中，有一个target xs 是main xs
	3. main xs 作用：1.rpc io 请求处理 2.（ult 们 for）rebuild scanner/puller，rebalance，scrub，pool connect，container open
	（除了main xs 外其余的叫offload xs，含义为分担压力的xs）
	（每一个xs 都会绑定到一个cpu 核）
	4. offload xs 作用：（ult 们 for）1.io 请求分发（tx 协商由第一个offload xs负责）2.ec/checksum/compress（如果有两个offload则由第二个xs负责，否则由第一个xs负责）
	5. 每个engine 有一个sys xs 集合（目前只有一个）。作用：drpc 监听，rbd 请求和元数据服务，管理侧请求，池请求，容器请求，rebuild 请求，rebalance 请求，rebuild 检查，iv，bcast，swim请求

	// 		     	               		 			  engine
	//                              		/                                   \
	//  		   				vos-target-xs                   		 		1. sys xs（drpc 监听，元数据操作）
	//                     /                       \
	//  2. main-xs（rpc io，rebuild scanner puller）   3. offload-xs（io 请求分发，ec，checksum）  

	// todo: 分别跟一下不同xs 对应的操作代码流程  
	// 比如这里main-xs 涉及的rebuild 在sys-xs里也有涉及，是怎么任务划分的
	// 比如元数据访问是哪个流程
	// rbd 请求指的什么功能，是和raft 相关的，或者tx 相关的都属于这里吗
	// 那假如一个流程涉及多个功能，比如读写io 时候要访问元数据，这时候的跨xs 操作是如何实现的?
	// 与spdk 等架构对照，opencas等，主io线程和其余的线程的关系
*/
/**
 * todo: 这个线程模型是怎么工作的，也就是任务来了，是怎么分配给不同的xs 的
 * todo：xs 和target 的关系又是怎么对应的
 * DAOS server threading model:
 * 1) a set of "target XS (xstream) set" per engine (dss_tgt_nr)
 * -t 参数指定的 dss_tgt_nr
 * There is a "-t" option of daos_server to set the number.
 * For DAOS pool, one target XS set per VOS target to avoid extra lock when
 * accessing VOS file.
 * 每个target 一个xs
 * With in each target XS set, there is one "main XS":
 * 在所有的xs 集合中，有一个是 main xs，并且有一组offload xs（即helper）。
 * 1.1) The tasks for main XS:
 *	RPC server of IO request handler,
 *	ULT server for:
 *		rebuild scanner/puller
 *		rebalance,
 *		aggregation,
 *		data scrubbing,
 *		pool service (tgt connect/disconnect etc),
 *		container open/close.
 *
 * And a set of "offload XS" (dss_tgt_offload_xs_nr)
 * 1.2) The tasks for offload XS:
 *	ULT server for:
 *		IO request dispatch (TX coordinator, on 1st offload XS),
 *		Acceleration of EC/checksum/compress (on 2nd offload XS if
 *		dss_tgt_offload_xs_nr is 2, or on 1st offload XS).
 *
 * 2) one "system XS set" per engine (dss_sys_xs_nr)
 * 另外每个engine 还有一个sys xs 集合（目前集合只有一个xs 0 作为sys xs），负责一些系统层面的任务
 * The system XS set (now only one - the XS 0) is for some system level tasks:
 *	RPC server for:
 *		drpc listener,
 *		RDB request and meta-data service,
 *		management request for mgmt module,
 *		pool request,
 *		container request (including the OID allocate),
 *		rebuild request such as REBUILD_OBJECTS_SCAN/REBUILD_OBJECTS,
 *		rebuild status checker,
 *		rebalance request,
 *		IV, bcast, and SWIM message handling.
 * Helper function:
 * daos_rpc_tag() to query the target tag (context ID) of specific RPC request.
 */

/** Number of dRPC xstreams */
#define DRPC_XS_NR	(1)
/** Number of offload XS */
// helper 个数，= 配置文件中helper 个数
unsigned int	dss_tgt_offload_xs_nr;
/** Number of target (XS set) per engine */
// target xs 个数，= 配置文件中target 个数
unsigned int	dss_tgt_nr;
/** Number of system XS */
// todo: （2 + 1）共三个 sys xs ？
unsigned int	dss_sys_xs_nr = DAOS_TGT0_OFFSET + DRPC_XS_NR;
/**
 * Flag of helper XS as a pool.
 * false - the helper XS is near its main IO service XS. When there is one or
 *         2 helper XS for each VOS target (dss_tgt_offload_xs_nr % dss_tgt_nr
 *         == 0), we create each VOS target's IO service XS and then its helper
 *         XS, and each VOS has its own helper XS.
 * true  - When there is no enough cores/XS to create one or two helpers for
 *         VOS target (dss_tgt_offload_xs_nr % dss_tgt_nr != 0), we firstly
 *         create all VOS targets' IO service XS, and then all helper XS that
 *         are shared used by all VOS targets.
 */
// flag 表示来标识是否将helper xs 作为一个pool
// 1. false: 
bool		dss_helper_pool;

/** Bypass for the nvme health check */
bool		dss_nvme_bypass_health_check;

static daos_epoch_t	dss_start_epoch;

unsigned int
dss_ctx_nr_get(void)
{
	return DSS_CTX_NR_TOTAL;
}

#define DSS_SYS_XS_NAME_FMT	"daos_sys_%d"
#define DSS_IO_XS_NAME_FMT	"daos_io_%d"
#define DSS_OFFLOAD_XS_NAME_FMT	"daos_off_%d"

struct dss_xstream_data {
	/** Initializing step, it is for cleanup of global states */
	int			  xd_init_step;
	int			  xd_ult_init_rc;
	bool			  xd_ult_signal;
	/** total number of XS including system XS, main XS and offload XS */
	// sys xs main xs 和helper 的总数
	int			  xd_xs_nr;
	/** created XS pointer array */
	// 保存所有的xs
	struct dss_xstream	**xd_xs_ptrs;
	/** serialize initialization of ULTs */
	ABT_cond		  xd_ult_init;
	/** barrier for all ULTs to enter handling loop */
	ABT_cond		  xd_ult_barrier;
	ABT_mutex		  xd_mutex;
};

// 全局的xs 信息
static struct dss_xstream_data	xstream_data;

int
dss_xstream_set_affinity(struct dss_xstream *dxs)
{
	int rc;

	/**
	 * Set cpu affinity
	 * Try to use strict CPU binding, if supported.
	 */
	// 绑定cpuset
	// todo: 和spdk 中绑核的区别和关联
	rc = hwloc_set_cpubind(dss_topo, dxs->dx_cpuset,
			       HWLOC_CPUBIND_THREAD | HWLOC_CPUBIND_STRICT);
	if (rc) {
		D_INFO("failed to set strict cpu affinity: %d\n", errno);
		rc = hwloc_set_cpubind(dss_topo, dxs->dx_cpuset, HWLOC_CPUBIND_THREAD);
		if (rc) {
			D_ERROR("failed to set cpu affinity: %d\n", errno);
			return rc;
		}
	}

	/**
	 * Set memory affinity, but fail silently if it does not work since some
	 * systems return ENOSYS.
	 */
	// 绑定内存
	rc = hwloc_set_membind(dss_topo, dxs->dx_cpuset, HWLOC_MEMBIND_BIND,
			       HWLOC_MEMBIND_THREAD);
	if (rc)
		D_DEBUG(DB_TRACE, "failed to set memory affinity: %d\n", errno);

	return 0;
}

bool
dss_xstream_exiting(struct dss_xstream *dxs)
{
	ABT_bool state;
	int	 rc;

	rc = ABT_future_test(dxs->dx_shutdown, &state);
	D_ASSERTF(rc == ABT_SUCCESS, "%d\n", rc);
	return state == ABT_TRUE;
}

int
dss_xstream_cnt(void)
{
	return xstream_data.xd_xs_nr;
}

// 按照id 获取对应的xs
struct dss_xstream *
dss_get_xstream(int stream_id)
{
	if (stream_id == DSS_XS_SELF)
		return dss_current_xstream();

	D_ASSERTF(stream_id >= 0 && stream_id < xstream_data.xd_xs_nr,
		  "invalid stream id %d (xstream_data.xd_xs_nr %d).\n",
		  stream_id, xstream_data.xd_xs_nr);

	return xstream_data.xd_xs_ptrs[stream_id];
}

/**
 * sleep milliseconds, then being rescheduled.
 *
 * \param[in]	msec	milliseconds to sleep for
 */
int
dss_sleep(uint64_t msec)
{
	struct sched_req_attr	 attr = { 0 };
	struct sched_request	*req;
	uuid_t			 anonym_uuid;

	uuid_clear(anonym_uuid);
	sched_req_attr_init(&attr, SCHED_REQ_ANONYM, &anonym_uuid);
	req = sched_req_get(&attr, ABT_THREAD_NULL);
	if (req == NULL)
		return -DER_NOMEM;

	sched_req_sleep(req, msec);
	sched_req_put(req);
	return 0;
}

struct dss_rpc_cntr *
dss_rpc_cntr_get(enum dss_rpc_cntr_id id)
{
	struct dss_xstream  *dx = dss_current_xstream();

	D_ASSERT(id < DSS_RC_MAX);
	return &dx->dx_rpc_cntrs[id];
}

/** increase the active and total counters for the RPC type */
void
dss_rpc_cntr_enter(enum dss_rpc_cntr_id id)
{
	struct dss_rpc_cntr *cntr = dss_rpc_cntr_get(id);

	cntr->rc_active_time = sched_cur_msec();
	cntr->rc_active++;
	cntr->rc_total++;

	/* TODO: add interface to calculate average workload and reset stime */
	if (cntr->rc_stime == 0)
		cntr->rc_stime = cntr->rc_active_time;
}

/**
 * Decrease the active counter for the RPC type, also increase error counter
 * if @failed is true.
 */
void
dss_rpc_cntr_exit(enum dss_rpc_cntr_id id, bool error)
{
	struct dss_rpc_cntr *cntr = dss_rpc_cntr_get(id);

	D_ASSERT(cntr->rc_active > 0);
	cntr->rc_active--;
	if (error)
		cntr->rc_errors++;
}

static int
dss_iv_resp_hdlr(crt_context_t *ctx, void *hdlr_arg,
		 void (*real_rpc_hdlr)(void *), void *arg)
{
	struct dss_xstream	*dx = (struct dss_xstream *)arg;

	/*
	 * Current EC aggregation periodically update IV, use
	 * PERIODIC flag to avoid interfering CPU relaxing.
	 */
	return sched_create_thread(dx, real_rpc_hdlr, hdlr_arg,
				   ABT_THREAD_ATTR_NULL, NULL,
				   DSS_ULT_FL_PERIODIC);
}

static int
dss_rpc_hdlr(crt_context_t *ctx, void *hdlr_arg,
	     void (*real_rpc_hdlr)(void *), void *arg)
{
	struct dss_xstream	*dx = (struct dss_xstream *)arg;
	crt_rpc_t		*rpc = (crt_rpc_t *)hdlr_arg;
	unsigned int		 mod_id = opc_get_mod_id(rpc->cr_opc);
	struct dss_module	*module = dss_module_get(mod_id);
	struct sched_req_attr	 attr = { 0 };
	int			 rc;

	if (DAOS_FAIL_CHECK(DAOS_FAIL_LOST_REQ))
		return 0;
	/*
	 * The mod_id for the RPC originated from CART is 0xfe, and 'module'
	 * will be NULL for this case.
	 */
	if (module != NULL && module->sm_mod_ops != NULL &&
	    module->sm_mod_ops->dms_get_req_attr != NULL) {
		rc = module->sm_mod_ops->dms_get_req_attr(rpc, &attr);
		if (rc != 0)
			attr.sra_type = SCHED_REQ_ANONYM;
	} else {
		attr.sra_type = SCHED_REQ_ANONYM;
	}

	return sched_req_enqueue(dx, &attr, real_rpc_hdlr, rpc);
}

static void
dss_nvme_poll_ult(void *args)
{
	struct dss_module_info	*dmi = dss_get_module_info();
	struct dss_xstream	*dx = dss_current_xstream();

	D_ASSERT(dss_xstream_has_nvme(dx));
	while (!dss_xstream_exiting(dx)) {
		bio_nvme_poll(dmi->dmi_nvme_ctxt);
		ABT_thread_yield();
	}
}

/*
 * Wait all other ULTs exited before the srv handler ULT dss_srv_handler()
 * exits, since the per-xstream TLS, comm context, NVMe context, etc. will
 * be destroyed on server handler ULT exiting.
 */
static void
wait_all_exited(struct dss_xstream *dx, struct dss_module_info *dmi)
{
	int	rc;

	D_DEBUG(DB_TRACE, "XS(%d) draining ULTs.\n", dx->dx_xs_id);

	sched_stop(dx);

	while (1) {
		size_t	total_size = 0;
		int	i;

		for (i = 0; i < DSS_POOL_CNT; i++) {
			size_t	pool_size;
			rc = ABT_pool_get_total_size(dx->dx_pools[i],
						     &pool_size);
			D_ASSERTF(rc == ABT_SUCCESS, "%d\n", rc);
			total_size += pool_size;
		}
		/*
		 * Current running srv handler ULT is popped, so it's not
		 * counted in pool size by argobots.
		 */
		if (total_size == 0)
			break;

		/*
		 * Call progress in case any replies are pending in the
		 * queue which might block some ULTs forever.
		 */
		if (dx->dx_comm) {
			rc = crt_progress(dmi->dmi_ctx, 0);
			if (rc != 0 && rc != -DER_TIMEDOUT)
				D_ERROR("failed to progress CART context: %d\n",
					rc);
		}

		ABT_thread_yield();
	}
	D_DEBUG(DB_TRACE, "XS(%d) drained ULTs.\n", dx->dx_xs_id);
}

#define D_MEMORY_TRACK_ENV "D_MEMORY_TRACK"
/*
 * The server handler ULT first sets CPU affinity, initialize the per-xstream
 * TLS, CRT(comm) context, NVMe context, creates the long-run ULTs (GC & NVMe
 * poll), then it starts to poll the network requests in a loop until service
 * shutdown.
 */
// 先设置cpu 亲和性，初始化每个xs 的tls，crt ctx，nvme ctx，创建一个loop ult （用于做gc 和nvme poll），之后poll 网络请求
static void
dss_srv_handler(void *arg)
{
	struct dss_xstream		*dx = (struct dss_xstream *)arg;
	struct dss_thread_local_storage	*dtc;
	struct dss_module_info		*dmi;
	int				 rc;
	bool				 track_mem = false;
	bool				 signal_caller = true;

	// xs 的server handler 线程先设置cpu 亲和性
	// 亲和性说的是numa 架构下cpu 访问同一个numa 节点上的内存速度快于其他numa 节点
	rc = dss_xstream_set_affinity(dx);
	if (rc)
		goto signal;

	d_getenv_bool(D_MEMORY_TRACK_ENV, &track_mem);
	if (unlikely(track_mem))
		d_set_alloc_track_cb(dss_mem_total_alloc_track, dss_mem_total_free_track,
				     &dx->dx_mem_stats);

	/* initialize xstream-local storage */
	// 初始化tls（thread local storage） 相关
	// tgt id 为 -1 表示系统vos target
	dtc = dss_tls_init(dx->dx_tag, dx->dx_xs_id, dx->dx_tgt_id);
	if (dtc == NULL) {
		D_ERROR("failed to initialize TLS\n");
		goto signal;
	}

	// tls 信息
	dmi = dss_get_module_info();
	D_ASSERT(dmi != NULL);
	dmi->dmi_xs_id	= dx->dx_xs_id;
	// target id
	dmi->dmi_tgt_id	= dx->dx_tgt_id;
	dmi->dmi_ctx_id	= -1;
	D_INIT_LIST_HEAD(&dmi->dmi_dtx_batched_cont_open_list);
	D_INIT_LIST_HEAD(&dmi->dmi_dtx_batched_cont_close_list);
	D_INIT_LIST_HEAD(&dmi->dmi_dtx_batched_pool_list);

	(void)pthread_setname_np(pthread_self(), dx->dx_name);

	// 为true 表示需要创建crt ctx，3+20+2 xs 场景只有2为false
	if (dx->dx_comm) {
		/* create private transport context */
		// 创建crt ctx，里面会有注册hg_ 相关
		rc = crt_context_create(&dmi->dmi_ctx);
		if (rc != 0) {
			D_ERROR("failed to create crt ctxt: "DF_RC"\n",
				DP_RC(rc));
			goto tls_fini;
		}

		// 注册rpc服务端处理函数
		rc = crt_context_register_rpc_task(dmi->dmi_ctx, dss_rpc_hdlr,
						   dss_iv_resp_hdlr, dx);
		if (rc != 0) {
			D_ERROR("failed to register process cb "DF_RC"\n",
				DP_RC(rc));
			goto crt_destroy;
		}

		/** Get context index from cart */
		rc = crt_context_idx(dmi->dmi_ctx, &dmi->dmi_ctx_id);
		if (rc != 0) {
			D_ERROR("failed to get xtream index: rc "DF_RC"\n",
				DP_RC(rc));
			goto crt_destroy;
		}
		dx->dx_ctx_id = dmi->dmi_ctx_id;
		/** verify CART assigned the ctx_id ascendantly start from 0 */
		if (dx->dx_xs_id < dss_sys_xs_nr) {
			/*
			 * xs_id: 0 => SYS  XS: ctx_id: 0
			 * xs_id: 1 => SWIM XS: ctx_id: 1
			 * xs_id: 2 => DRPC XS: no ctx_id
			 */
			D_ASSERTF(dx->dx_ctx_id == dx->dx_xs_id,
				  "incorrect ctx_id %d for xs_id %d\n",
				  dx->dx_ctx_id, dx->dx_xs_id);
		} else {
			if (dx->dx_main_xs) {
				D_ASSERTF(dx->dx_ctx_id ==
					  (dx->dx_tgt_id + dss_sys_xs_nr - DRPC_XS_NR),
					  "incorrect ctx_id %d for xs_id %d tgt_id %d\n",
					  dx->dx_ctx_id, dx->dx_xs_id, dx->dx_tgt_id);
			} else {
				if (dss_helper_pool)
					D_ASSERTF(dx->dx_ctx_id == (dx->dx_xs_id - DRPC_XS_NR),
						  "incorrect ctx_id %d for xs_id %d tgt_id %d\n",
						  dx->dx_ctx_id, dx->dx_xs_id, dx->dx_tgt_id);
				else
					D_ASSERTF(dx->dx_ctx_id ==
						  (dx->dx_tgt_id + dss_sys_xs_nr - DRPC_XS_NR +
						   dss_tgt_nr),
						  "incorrect ctx_id %d for xs_id %d "
						  "tgt_id %d tgt_nr %d\n",
						  dx->dx_ctx_id, dx->dx_xs_id,
						  dx->dx_tgt_id, dss_tgt_nr);
			}
		}
	}

	/* Prepare the scheduler for DSC (Server call client API) */
	// tse 的调度服务初始化
	rc = tse_sched_init(&dx->dx_sched_dsc, NULL, dmi->dmi_ctx);
	if (rc != 0) {
		D_ERROR("failed to init the scheduler\n");
		goto crt_destroy;
	}

	// 第一个xs 以及main xs时： dss_xstream_has_nvme 为true
	// todo: 第一个xs 有什么特殊吗？
	if (dss_xstream_has_nvme(dx)) {
		ABT_thread_attr attr;

		/* Initialize NVMe context for main XS which accesses NVME */
		// 初始化main xs 的nvme ctx
		// bio_xsctxt_alloc 函数内部会创建blobstore
		// dmi 是tls 信息，每个线程有各自的值，互相不冲突，即每个main xs 有各自的 dmi_nvme_ctxt 信息
		rc = bio_xsctxt_alloc(&dmi->dmi_nvme_ctxt,
				      dmi->dmi_tgt_id < 0 ? BIO_SYS_TGT_ID : dmi->dmi_tgt_id,
				      false);
		if (rc != 0) {
			D_ERROR("failed to init spdk context for xstream(%d) "
				"rc:%d\n", dmi->dmi_xs_id, rc);
			D_GOTO(tse_fini, rc);
		}

		// 创建nvme poll ult 相关
		rc = ABT_thread_attr_create(&attr);
		if (rc != ABT_SUCCESS) {
			D_ERROR("Create ABT thread attr failed. %d\n", rc);
			D_GOTO(nvme_fini, rc = dss_abterr2der(rc));
		}

		rc = ABT_thread_attr_set_stacksize(attr, DSS_DEEP_STACK_SZ);
		if (rc != ABT_SUCCESS) {
			ABT_thread_attr_free(&attr);
			D_ERROR("Set ABT stack size failed. %d\n", rc);
			D_GOTO(nvme_fini, rc = dss_abterr2der(rc));
		}

		// spdk poll 和故障检测
		// 创建一个线程，自动将work unit 添加到pool 中。当调用ABT_pool_pop 时从pool 中取出
		rc = daos_abt_thread_create(dx->dx_sp, dss_free_stack_cb, dx->dx_pools[DSS_POOL_NVME_POLL],
					    dss_nvme_poll_ult, NULL, attr, NULL);
		ABT_thread_attr_free(&attr);
		if (rc != ABT_SUCCESS) {
			D_ERROR("create NVMe poll ULT failed: %d\n", rc);
			ABT_future_set(dx->dx_shutdown, dx);
			wait_all_exited(dx, dmi);
			D_GOTO(nvme_fini, rc = dss_abterr2der(rc));
		}
	}

	dmi->dmi_xstream = dx;
	ABT_mutex_lock(xstream_data.xd_mutex);
	/* initialized everything for the ULT, notify the creator */
	D_ASSERT(!xstream_data.xd_ult_signal);
	// 通知主线程停止等待
	xstream_data.xd_ult_signal = true;
	xstream_data.xd_ult_init_rc = 0;
	ABT_cond_signal(xstream_data.xd_ult_init);

	/* wait until all xstreams are ready, otherwise it is not safe
	 * to run lock-free dss_collective, although this race is not
	 * realistically possible in the DAOS stack.
	 *
	 * The SWIM xstream, however, needs to start progressing crt quickly to
	 * respond to incoming pings. It is out of the scope of
	 * dss_{thread,task}_collective.
	 */
	if (dx->dx_xs_id != 1 /* DSS_XS_SWIM */)
		ABT_cond_wait(xstream_data.xd_ult_barrier, xstream_data.xd_mutex);
	ABT_mutex_unlock(xstream_data.xd_mutex);

	if (dx->dx_comm)
		dx->dx_progress_started = true;

	signal_caller = false;
	/* main service progress loop */
	for (;;) {
		// 所有的main xs（第一个xs 也会） 将会loop crt_process，其他的xs 在这里空 loop
		if (dx->dx_comm) {
			rc = crt_progress(dmi->dmi_ctx, dx->dx_timeout);
			if (rc != 0 && rc != -DER_TIMEDOUT) {
				D_ERROR("failed to progress CART context: %d\n",
					rc);
				/* XXX Sometimes the failure might be just
				 * temporary, Let's keep progressing for now.
				 */
			}
		}

		if (dss_xstream_exiting(dx))
			break;

		ABT_thread_yield();
	}

	if (dx->dx_comm)
		dx->dx_progress_started = false;

	wait_all_exited(dx, dmi);
	if (dmi->dmi_dp) {
		daos_profile_destroy(dmi->dmi_dp);
		dmi->dmi_dp = NULL;
	}

nvme_fini:
	if (dss_xstream_has_nvme(dx))
		bio_xsctxt_free(dmi->dmi_nvme_ctxt);
tse_fini:
	tse_sched_fini(&dx->dx_sched_dsc);
crt_destroy:
	if (dx->dx_comm)
		crt_context_destroy(dmi->dmi_ctx, true);
tls_fini:
	dss_tls_fini(dtc);
signal:
	if (signal_caller) {
		ABT_mutex_lock(xstream_data.xd_mutex);
		/* initialized everything for the ULT, notify the creator */
		D_ASSERT(!xstream_data.xd_ult_signal);
		xstream_data.xd_ult_signal = true;
		xstream_data.xd_ult_init_rc = rc;
		ABT_cond_signal(xstream_data.xd_ult_init);
		ABT_mutex_unlock(xstream_data.xd_mutex);
	}
}

static inline struct dss_xstream *
dss_xstream_alloc(hwloc_cpuset_t cpus)
{
	struct dss_xstream	*dx;
	int			i;
	int			rc = 0;

	D_ALLOC_PTR(dx);
	if (dx == NULL) {
		return NULL;
	}

#ifdef ULT_MMAP_STACK
	if (daos_ult_mmap_stack == true) {
		rc = stack_pool_create(&dx->dx_sp);
		if (rc != 0) {
			D_ERROR("failed to create stack pool\n");
			D_GOTO(err_free, rc);
		}
	}
#endif

	dx->dx_stopping = ABT_FUTURE_NULL;
	dx->dx_shutdown = ABT_FUTURE_NULL;

	rc = ABT_future_create(1, NULL, &dx->dx_stopping);
	if (rc != 0) {
		D_ERROR("failed to allocate 'stopping' future\n");
		D_GOTO(err_free, rc = dss_abterr2der(rc));
	}

	rc = ABT_future_create(1, NULL, &dx->dx_shutdown);
	if (rc != 0) {
		D_ERROR("failed to allocate 'shutdown' future\n");
		D_GOTO(err_future, rc = dss_abterr2der(rc));
	}

	dx->dx_cpuset = hwloc_bitmap_dup(cpus);
	if (dx->dx_cpuset == NULL) {
		D_ERROR("failed to allocate cpuset\n");
		D_GOTO(err_future, rc = -DER_NOMEM);
	}

	for (i = 0; i < DSS_POOL_CNT; i++)
		dx->dx_pools[i] = ABT_POOL_NULL;

	dx->dx_xstream	= ABT_XSTREAM_NULL;
	dx->dx_sched	= ABT_SCHED_NULL;
	dx->dx_progress	= ABT_THREAD_NULL;

	return dx;

err_future:
	if (dx->dx_shutdown != ABT_FUTURE_NULL)
		ABT_future_free(&dx->dx_shutdown);
	if (dx->dx_stopping != ABT_FUTURE_NULL)
		ABT_future_free(&dx->dx_stopping);
err_free:
	D_FREE(dx);
	return NULL;
}

static inline void
dss_xstream_free(struct dss_xstream *dx)
{
#ifdef ULT_MMAP_STACK
	struct stack_pool *sp = dx->dx_sp;

	if (daos_ult_mmap_stack == true) {
		stack_pool_destroy(sp);
		dx->dx_sp = NULL;
	}
#endif
	hwloc_bitmap_free(dx->dx_cpuset);
	D_FREE(dx);
}

static void
dss_mem_stats_init(struct mem_stats *stats, int xs_id)
{
	int rc;

	rc = d_tm_add_metric(&stats->ms_total_usage, D_TM_GAUGE,
			     "Total memory usage", "byte", "mem/total_mem/xs_%u", xs_id);
	if (rc)
		D_WARN("Failed to create memory telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->ms_mallinfo, D_TM_MEMINFO,
			     "Total memory arena", "", "mem/meminfo/xs_%u", xs_id);
	if (rc)
		D_WARN("Failed to create memory telemetry: "DF_RC"\n", DP_RC(rc));
	stats->ms_current = 0;
}

void
dss_mem_total_alloc_track(void *arg, daos_size_t bytes)
{
	struct mem_stats *stats = arg;

	D_ASSERT(arg != NULL);

	d_tm_inc_gauge(stats->ms_total_usage, bytes);
	/* Only retrieve mallocinfo every 10 allocation */
	if ((stats->ms_current++ % 10) == 0)
		d_tm_record_meminfo(stats->ms_mallinfo);
}

void
dss_mem_total_free_track(void *arg, daos_size_t bytes)
{
	struct mem_stats *stats = arg;

	D_ASSERT(arg != NULL);

	d_tm_dec_gauge(stats->ms_total_usage, bytes);
}

/**
 * Start one xstream.
 *
 * \param[in] cpus	the cpuset to bind the xstream
 * \param[in] tag	The tag for the xstream
 * \param[in] xs_id	the xs_id of xstream (start from 0)
 *
 * \retval	= 0 if starting succeeds.
 * \retval	negative errno if starting fails.
 */
static int
dss_start_one_xstream(hwloc_cpuset_t cpus, int tag, int xs_id)
{
	struct dss_xstream	*dx;
	ABT_thread_attr		attr = ABT_THREAD_ATTR_NULL;
	int			rc = 0;
	// 当前xs 是否需要创建crt ctx
	bool			comm; /* true to create cart ctx for RPC */
	int			xs_offset = 0;

	/** allocate & init xstream configuration data */
	// cpuset 直接赋值给 dss_xstream 中成员
	dx = dss_xstream_alloc(cpus);
	if (dx == NULL)
		return -DER_NOMEM;

	/* Partial XS need the RPC communication ability - system XS, each
	 * main XS and its first offload XS (for IO dispatch).
	 * The 2nd offload XS(if exists) does not need RPC communication
	 * as it is only for EC/checksum/compress offloading.
	 */
	// sys xs，每个main xs 和第一个helper xs（为了io 分发） 都需要rpc 能力。
	// 第二个helper xs 不需要rpc 能力，因为他只负责ec/checksum/compress 工作
	// 当前为 true
	if (dss_helper_pool) {
		// 以3 sys，20 tgt，2 helper为例。只有xs_id == 2 时为false
		comm =  (xs_id == 0) || /* DSS_XS_SYS */
			(xs_id == 1) || /* DSS_XS_SWIM */
			(xs_id >= dss_sys_xs_nr &&
			 xs_id < (dss_sys_xs_nr + 2 * dss_tgt_nr));
	} else {
		int	helper_per_tgt;

		helper_per_tgt = dss_tgt_offload_xs_nr / dss_tgt_nr;
		D_ASSERT(helper_per_tgt == 0 ||
			 helper_per_tgt == 1 ||
			 helper_per_tgt == 2);

		if ((xs_id >= dss_sys_xs_nr) &&
		    (xs_id < (dss_sys_xs_nr + dss_tgt_nr + dss_tgt_offload_xs_nr)))
			xs_offset = (xs_id - dss_sys_xs_nr) % (helper_per_tgt + 1);
		else
			xs_offset = -1;

		comm =  (xs_id == 0) ||		/* DSS_XS_SYS */
			(xs_id == 1) ||		/* DSS_XS_SWIM */
			(xs_offset == 0) ||	/* main XS */
			(xs_offset == 1);	/* first offload XS */
	}

	// 透传tag，id 到 xs
	dx->dx_tag      = tag;
	dx->dx_xs_id	= xs_id;
	dx->dx_ctx_id	= -1;
	dx->dx_comm	= comm;
	// 当前为 true
	if (dss_helper_pool) {
		// 设置当前是否为 main xs（在sys xs 和helper xs 中间的都是main xs，和dss_tgt_nr 相等）
		// todo: main xs 之外还有两种类型sys 和helper，不需要区分吗
		dx->dx_main_xs	= (xs_id >= dss_sys_xs_nr) &&
				  (xs_id < (dss_sys_xs_nr + dss_tgt_nr));
	} else {
		dx->dx_main_xs	= (xs_id >= dss_sys_xs_nr) && (xs_offset == 0);
	}
	dx->dx_dsc_started = false;

	/**
	 * Generate name for each xstreams so that they can be easily identified
	 * and monitored independently (e.g. via ps(1))
	 */
	// 根据xs id 获取target id
	dx->dx_tgt_id = dss_xs2tgt(xs_id);
	// 生成不同类型xs 的名字
	if (xs_id < dss_sys_xs_nr) {
		/** system xtreams are named daos_sys_$num */
		// sys 类型的xs 的名字
		snprintf(dx->dx_name, DSS_XS_NAME_LEN, DSS_SYS_XS_NAME_FMT,
			 xs_id);
	} else if (dx->dx_main_xs) {
		/** primary I/O xstreams are named daos_io_$tgtid */
		snprintf(dx->dx_name, DSS_XS_NAME_LEN, DSS_IO_XS_NAME_FMT,
			 dx->dx_tgt_id);
	} else {
		/** offload xstreams are named daos_off_$num */
		snprintf(dx->dx_name, DSS_XS_NAME_LEN, DSS_OFFLOAD_XS_NAME_FMT,
			 xs_id);
	}

	/** create ABT scheduler in charge of this xstream */
	// dx 参数填充完成，初始化xs 的调度器 dx_sched
	rc = dss_sched_init(dx);
	if (rc != 0) {
		D_ERROR("create scheduler fails: "DF_RC"\n", DP_RC(rc));
		D_GOTO(out_dx, rc);
	}

	// 当前xs 的内存使用
	dss_mem_stats_init(&dx->dx_mem_stats, xs_id);

	/** start XS, ABT rank 0 is reserved for the primary xstream */
	// rank 0 预留给main xs（20 个target 对应的用作 io 的 xs，即除了 sys xs 和helper 之外的xs）
	// 函数作用：用指定的 rank（xs_id + 1） 创建一个xs
	// todo: 预留rank 0 给main 体现在哪里
	rc = ABT_xstream_create_with_rank(dx->dx_sched, xs_id + 1,
					  &dx->dx_xstream);
	if (rc != ABT_SUCCESS) {
		D_ERROR("create xstream fails %d\n", rc);
		D_GOTO(out_sched, rc = dss_abterr2der(rc));
	}

	// 创建线程attr
	rc = ABT_thread_attr_create(&attr);
	if (rc != ABT_SUCCESS) {
		D_ERROR("ABT_thread_attr_create fails %d\n", rc);
		D_GOTO(out_xstream, rc = dss_abterr2der(rc));
	}

	// 设置thread 栈大小 = 64M。ulimit -s 默认为8192（8M）
	rc = ABT_thread_attr_set_stacksize(attr, DSS_DEEP_STACK_SZ);
	if (rc != ABT_SUCCESS) {
		D_ERROR("ABT_thread_attr_set_stacksize fails %d\n", rc);
		D_GOTO(out_xstream, rc = dss_abterr2der(rc));
	}

	/** start progress ULT */
	// 所有的xs 都会起一个ult 跑 dss_srv_handler
	// dss_srv_handler 里会去做绑核操作
	// https://github.com/daos-stack/daos/blob/master/src/engine/README.md
	// 内部调用ABT_thread_create 会创建一个新的线程，该线程的unit 将被放入pool 中，等待ABT_pool_pop 取出并执行
	// 这个新的线程就是 dx_progress
	rc = daos_abt_thread_create(dx->dx_sp, dss_free_stack_cb, dx->dx_pools[DSS_POOL_NET_POLL],
				    dss_srv_handler, dx, attr,
				    &dx->dx_progress);
	if (rc != ABT_SUCCESS) {
		D_ERROR("create progress ULT failed: %d\n", rc);
		D_GOTO(out_xstream, rc = dss_abterr2der(rc));
	}

	// 更新全局的xstream 信息
	ABT_mutex_lock(xstream_data.xd_mutex);

	// 等待上面 dss_srv_handler 执行完成
	if (!xstream_data.xd_ult_signal)
		ABT_cond_wait(xstream_data.xd_ult_init, xstream_data.xd_mutex);
	// 重置single 为false
	xstream_data.xd_ult_signal = false;
	rc = xstream_data.xd_ult_init_rc;
	if (rc != 0) {
		ABT_mutex_unlock(xstream_data.xd_mutex);
		goto out_xstream;
	}
	// 保存当前xs 的xstream
	xstream_data.xd_xs_ptrs[xs_id] = dx;
	// 更新完成
	ABT_mutex_unlock(xstream_data.xd_mutex);
	ABT_thread_attr_free(&attr);

	/*
	root@server01:/home/daos-v2.4.0/daos/src/bio# cat /tmp/daos_engine.0.log | grep 'created xstream name'
	12/05-13:01:19.42 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_sys_0)xs_id(0)/tgt_id(-1)/ctx_id(0)/comm(1)/is_main_xs(0).
	12/05-13:01:19.55 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_sys_1)xs_id(1)/tgt_id(-1)/ctx_id(1)/comm(1)/is_main_xs(0).
	12/05-13:01:19.58 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_sys_2)xs_id(2)/tgt_id(-1)/ctx_id(-1)/comm(0)/is_main_xs(0).
	12/05-13:01:21.01 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_0)xs_id(3)/tgt_id(0)/ctx_id(2)/comm(1)/is_main_xs(1).
	12/05-13:01:21.22 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_1)xs_id(4)/tgt_id(1)/ctx_id(3)/comm(1)/is_main_xs(1).
	12/05-13:01:21.45 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_2)xs_id(5)/tgt_id(2)/ctx_id(4)/comm(1)/is_main_xs(1).
	12/05-13:01:21.72 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_3)xs_id(6)/tgt_id(3)/ctx_id(5)/comm(1)/is_main_xs(1).
	12/05-13:01:21.94 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_4)xs_id(7)/tgt_id(4)/ctx_id(6)/comm(1)/is_main_xs(1).
	12/05-13:01:22.17 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_5)xs_id(8)/tgt_id(5)/ctx_id(7)/comm(1)/is_main_xs(1).
	12/05-13:01:22.46 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_6)xs_id(9)/tgt_id(6)/ctx_id(8)/comm(1)/is_main_xs(1).
	12/05-13:01:22.68 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_7)xs_id(10)/tgt_id(7)/ctx_id(9)/comm(1)/is_main_xs(1).
	12/05-13:01:22.90 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_8)xs_id(11)/tgt_id(8)/ctx_id(10)/comm(1)/is_main_xs(1).
	12/05-13:01:23.13 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_9)xs_id(12)/tgt_id(9)/ctx_id(11)/comm(1)/is_main_xs(1).
	12/05-13:01:23.40 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_10)xs_id(13)/tgt_id(10)/ctx_id(12)/comm(1)/is_main_xs(1).
	12/05-13:01:23.62 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_11)xs_id(14)/tgt_id(11)/ctx_id(13)/comm(1)/is_main_xs(1).
	12/05-13:01:23.84 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_12)xs_id(15)/tgt_id(12)/ctx_id(14)/comm(1)/is_main_xs(1).
	12/05-13:01:24.15 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_13)xs_id(16)/tgt_id(13)/ctx_id(15)/comm(1)/is_main_xs(1).
	12/05-13:01:24.38 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_14)xs_id(17)/tgt_id(14)/ctx_id(16)/comm(1)/is_main_xs(1).
	12/05-13:01:24.61 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_15)xs_id(18)/tgt_id(15)/ctx_id(17)/comm(1)/is_main_xs(1).
	12/05-13:01:24.83 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_16)xs_id(19)/tgt_id(16)/ctx_id(18)/comm(1)/is_main_xs(1).
	12/05-13:01:25.05 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_17)xs_id(20)/tgt_id(17)/ctx_id(19)/comm(1)/is_main_xs(1).
	12/05-13:01:25.27 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_18)xs_id(21)/tgt_id(18)/ctx_id(20)/comm(1)/is_main_xs(1).
	12/05-13:01:25.55 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_io_19)xs_id(22)/tgt_id(19)/ctx_id(21)/comm(1)/is_main_xs(1).
	12/05-13:01:25.68 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_off_23)xs_id(23)/tgt_id(-1)/ctx_id(22)/comm(1)/is_main_xs(0).
	12/05-13:01:25.80 server01 DAOS[2885211/-1/0] server DBUG src/engine/srv.c:781 dss_start_one_xstream() created xstream name(daos_off_24)xs_id(24)/tgt_id(-1)/ctx_id(23)/comm(1)/is_main_xs(0).
	*/
	D_DEBUG(DB_TRACE, "created xstream name(%s)xs_id(%d)/tgt_id(%d)/"
		"ctx_id(%d)/comm(%d)/is_main_xs(%d).\n",
		dx->dx_name, dx->dx_xs_id, dx->dx_tgt_id, dx->dx_ctx_id,
		dx->dx_comm, dx->dx_main_xs);

	return 0;
out_xstream:
	if (attr != ABT_THREAD_ATTR_NULL)
		ABT_thread_attr_free(&attr);
	ABT_xstream_join(dx->dx_xstream);
	ABT_xstream_free(&dx->dx_xstream);
out_sched:
	dss_sched_fini(dx);
out_dx:
	dss_xstream_free(dx);
	return rc;
}

static void
dss_xstreams_fini(bool force)
{
	struct dss_xstream	*dx;
	int			 i;
	int			 rc;
	bool			 started = false;

	D_DEBUG(DB_TRACE, "Stopping execution streams\n");
	dss_xstreams_open_barrier();
	rc = bio_nvme_ctl(BIO_CTL_NOTIFY_STARTED, &started);
	D_ASSERT(rc == 0);

	/* Notify all xstreams to reject new ULT creation first */
	for (i = 0; i < xstream_data.xd_xs_nr; i++) {
		dx = xstream_data.xd_xs_ptrs[i];
		if (dx == NULL)
			continue;
		ABT_future_set(dx->dx_stopping, dx);
	}

	/** Stop & free progress ULTs */
	for (i = 0; i < xstream_data.xd_xs_nr; i++) {
		dx = xstream_data.xd_xs_ptrs[i];
		if (dx == NULL)
			continue;
		ABT_future_set(dx->dx_shutdown, dx);
	}
	for (i = 0; i < xstream_data.xd_xs_nr; i++) {
		dx = xstream_data.xd_xs_ptrs[i];
		if (dx == NULL)
			continue;
		ABT_thread_join(dx->dx_progress);
		ABT_thread_free(&dx->dx_progress);
		ABT_future_free(&dx->dx_shutdown);
		ABT_future_free(&dx->dx_stopping);
	}

	/** Wait for each execution stream to complete */
	for (i = 0; i < xstream_data.xd_xs_nr; i++) {
		dx = xstream_data.xd_xs_ptrs[i];
		if (dx == NULL)
			continue;
		ABT_xstream_join(dx->dx_xstream);
		ABT_xstream_free(&dx->dx_xstream);
	}

	/** housekeeping ... */
	for (i = 0; i < xstream_data.xd_xs_nr; i++) {
		dx = xstream_data.xd_xs_ptrs[i];
		if (dx == NULL)
			continue;
		dss_sched_fini(dx);
		dss_xstream_free(dx);
		xstream_data.xd_xs_ptrs[i] = NULL;
	}

	/* All other xstreams have terminated. */
	xstream_data.xd_xs_nr = 0;
	dss_tgt_nr = 0;

	D_DEBUG(DB_TRACE, "Execution streams stopped\n");
}

void
dss_xstreams_open_barrier(void)
{
	ABT_mutex_lock(xstream_data.xd_mutex);
	ABT_cond_broadcast(xstream_data.xd_ult_barrier);
	ABT_mutex_unlock(xstream_data.xd_mutex);
}

static bool
dss_xstreams_empty(void)
{
	return xstream_data.xd_xs_nr == 0;
}

bool
dss_xstream_is_busy(void)
{
	struct dss_rpc_cntr	*cntr = dss_rpc_cntr_get(DSS_RC_OBJ);
	uint64_t		 cur_msec;

	cur_msec = sched_cur_msec();
	/* No IO requests for more than 5 seconds */
	return cur_msec < (cntr->rc_active_time + 5000);
}

// targs 分为8，249，253，255 几种
// xs_id 从0 到24（3 sys xs + 20 target xs + 2 helper xs 场景）
static int
dss_start_xs_id(int tag, int xs_id)
{
	hwloc_obj_t	obj;
	int		rc;
	int		xs_core_offset;
	unsigned	idx;
	char		*cpuset;

	D_DEBUG(DB_TRACE, "start xs_id called for %d.  ", xs_id);
	/* if we are NUMA aware, use the NUMA information */
	// 如果绑定了numa，使用numa 的信息
	if (numa_obj) {
		// 获取分配给当前 numa 的cpuset 的第一个cpu idx
		// hwloc_bitmap_clr 函数会影响下一次 first 的获取
		// hwloc_bitmap_first 返回位图中设置为 1的最小的索引
		idx = hwloc_bitmap_first(core_allocation_bitmap);
		if (idx == -1) {
			D_ERROR("No core available for XS: %d\n", xs_id);
			return -DER_INVAL;
		}
		D_DEBUG(DB_TRACE,
			"Choosing next available core index %d.", idx);
		/*
		 * All system XS will reuse the first XS' core, but
		 * the SWIM and DRPC XS will use separate core if enough cores
		 */
		// todo: 所有的sys xs 都会复用第一个xs 的core，但是swim 和drpc xs 会使用单独的core
		// dss_core_nr > dss_tgt_nr 表示物理核心数比target 个数多，即有剩余的核心数
		// （实际上只跳过了 xs_id == 1场景）
		if (xs_id > 1 || (xs_id == 0 && dss_core_nr > dss_tgt_nr))
			// 从已分配的 bitmap 中 remove 掉 idx
			// 位图设置为 0
			// 会影响到 hwloc_bitmap_first 获取的idx，设置为 0 ，下一次 hwloc_bitmap_first 会向后移动，否则原地踏步
			// 当xs_id == 1 时，不设置为 0，所以下一次 hwloc_bitmap_first 还会获取到同一个 idx。所以 1 和 2用的是同一个cpuset
			// 所以sys xs 其实配置了3 个，但是只用了两个 core
			hwloc_bitmap_clr(core_allocation_bitmap, idx);

		// 从topo 树的core 这层获取 idx 对应的node
		obj = hwloc_get_obj_by_depth(dss_topo, dss_core_depth, idx);
		if (obj == NULL) {
			D_PRINT("Null core returned by hwloc\n");
			return -DER_INVAL;
		}

		hwloc_bitmap_asprintf(&cpuset, obj->cpuset);
		D_DEBUG(DB_TRACE, "Using CPU set %s\n", cpuset);
		free(cpuset);
	} else {
		D_DEBUG(DB_TRACE, "Using non-NUMA aware core allocation\n");
		/*
		 * All system XS will use the first core, but
		 * the SWIM XS will use separate core if enough cores
		 */
		if (xs_id > 2)
			xs_core_offset = xs_id - ((dss_core_nr > dss_tgt_nr) ? 1 : 2);
		else if (xs_id == 1)
			xs_core_offset = (dss_core_nr > dss_tgt_nr) ? 1 : 0;
		else
			xs_core_offset = 0;
		obj = hwloc_get_obj_by_depth(dss_topo, dss_core_depth,
					     (xs_core_offset + dss_core_offset)
					     % dss_core_nr);
		if (obj == NULL) {
			D_ERROR("Null core returned by hwloc for XS %d\n",
				xs_id);
			return -DER_INVAL;
		}
	}
	// lstopo --cpuset 可以查看当前的cpuset 信息
	/*
	root@server01:~# lstopo --cpuset
	Machine (504GB total) cpuset=0x000000ff,0xffffffff,0xffffffff,0xffffffff
	Package L#0 cpuset=0x00003fff,0xfff00000,0x03ffffff
		NUMANode L#0 (P#0 252GB) cpuset=0x00003fff,0xfff00000,0x03ffffff
		L3 L#0 (39MB) cpuset=0x00003fff,0xfff00000,0x03ffffff
		L2 L#0 (1280KB) cpuset=0x00100000,0x00000001
			L1d L#0 (48KB) cpuset=0x00100000,0x00000001
			L1i L#0 (32KB) cpuset=0x00100000,0x00000001
				Core L#0 cpuset=0x00100000,0x00000001
				PU L#0 (P#0) cpuset=0x00000001
				PU L#1 (P#52) cpuset=0x00100000,0x0
		L2 L#1 (1280KB) cpuset=0x00200000,0x00000002
			L1d L#1 (48KB) cpuset=0x00200000,0x00000002
			L1i L#1 (32KB) cpuset=0x00200000,0x00000002
				Core L#1 cpuset=0x00200000,0x00000002
				PU L#2 (P#1) cpuset=0x00000002
				PU L#3 (P#53) cpuset=0x00200000,0x0
		L2 L#2 (1280KB) cpuset=0x00400000,0x00000004
			L1d L#2 (48KB) cpuset=0x00400000,0x00000004
			L1i L#2 (32KB) cpuset=0x00400000,0x00000004
				Core L#2 cpuset=0x00400000,0x00000004
				PU L#4 (P#2) cpuset=0x00000004
				PU L#5 (P#54) cpuset=0x00400000,0x0
		L2 L#3 (1280KB) cpuset=0x00800000,0x00000008
			L1d L#3 (48KB) cpuset=0x00800000,0x00000008
			L1i L#3 (32KB) cpuset=0x00800000,0x00000008
				Core L#3 cpuset=0x00800000,0x00000008
				PU L#6 (P#3) cpuset=0x00000008
				PU L#7 (P#55) cpuset=0x00800000,0x0
		L2 L#4 (1280KB) cpuset=0x01000000,0x00000010
			L1d L#4 (48KB) cpuset=0x01000000,0x00000010
			L1i L#4 (32KB) cpuset=0x01000000,0x00000010
				Core L#4 cpuset=0x01000000,0x00000010
				PU L#8 (P#4) cpuset=0x00000010
				PU L#9 (P#56) cpuset=0x01000000,0x0
		L2 L#5 (1280KB) cpuset=0x02000000,0x00000020
			L1d L#5 (48KB) cpuset=0x02000000,0x00000020
			L1i L#5 (32KB) cpuset=0x02000000,0x00000020
				Core L#5 cpuset=0x02000000,0x00000020
				PU L#10 (P#5) cpuset=0x00000020
				PU L#11 (P#57) cpuset=0x02000000,0x0
		L2 L#6 (1280KB) cpuset=0x04000000,0x00000040
			L1d L#6 (48KB) cpuset=0x04000000,0x00000040
			L1i L#6 (32KB) cpuset=0x04000000,0x00000040
				Core L#6 cpuset=0x04000000,0x00000040
				PU L#12 (P#6) cpuset=0x00000040
				PU L#13 (P#58) cpuset=0x04000000,0x0
		L2 L#7 (1280KB) cpuset=0x08000000,0x00000080
			L1d L#7 (48KB) cpuset=0x08000000,0x00000080
			L1i L#7 (32KB) cpuset=0x08000000,0x00000080
				Core L#7 cpuset=0x08000000,0x00000080
				PU L#14 (P#7) cpuset=0x00000080
				PU L#15 (P#59) cpuset=0x08000000,0x0
		L2 L#8 (1280KB) cpuset=0x10000000,0x00000100
			L1d L#8 (48KB) cpuset=0x10000000,0x00000100
			L1i L#8 (32KB) cpuset=0x10000000,0x00000100
				Core L#8 cpuset=0x10000000,0x00000100
				PU L#16 (P#8) cpuset=0x00000100
				PU L#17 (P#60) cpuset=0x10000000,0x0
		L2 L#9 (1280KB) cpuset=0x20000000,0x00000200
			L1d L#9 (48KB) cpuset=0x20000000,0x00000200
			L1i L#9 (32KB) cpuset=0x20000000,0x00000200
				Core L#9 cpuset=0x20000000,0x00000200
				PU L#18 (P#9) cpuset=0x00000200
				PU L#19 (P#61) cpuset=0x20000000,0x0
		L2 L#10 (1280KB) cpuset=0x40000000,0x00000400
			L1d L#10 (48KB) cpuset=0x40000000,0x00000400
			L1i L#10 (32KB) cpuset=0x40000000,0x00000400
				Core L#10 cpuset=0x40000000,0x00000400
				PU L#20 (P#10) cpuset=0x00000400
				PU L#21 (P#62) cpuset=0x40000000,0x0
		L2 L#11 (1280KB) cpuset=0x80000000,0x00000800
			L1d L#11 (48KB) cpuset=0x80000000,0x00000800
			L1i L#11 (32KB) cpuset=0x80000000,0x00000800
				Core L#11 cpuset=0x80000000,0x00000800
				PU L#22 (P#11) cpuset=0x00000800
				PU L#23 (P#63) cpuset=0x80000000,0x0
		L2 L#12 (1280KB) cpuset=0x00000001,,0x00001000
			L1d L#12 (48KB) cpuset=0x00000001,,0x00001000
			L1i L#12 (32KB) cpuset=0x00000001,,0x00001000
				Core L#12 cpuset=0x00000001,,0x00001000
				PU L#24 (P#12) cpuset=0x00001000
				PU L#25 (P#64) cpuset=0x00000001,,0x0
		L2 L#13 (1280KB) cpuset=0x00000002,,0x00002000
			L1d L#13 (48KB) cpuset=0x00000002,,0x00002000
			L1i L#13 (32KB) cpuset=0x00000002,,0x00002000
				Core L#13 cpuset=0x00000002,,0x00002000
				PU L#26 (P#13) cpuset=0x00002000
				PU L#27 (P#65) cpuset=0x00000002,,0x0
		L2 L#14 (1280KB) cpuset=0x00000004,,0x00004000
			L1d L#14 (48KB) cpuset=0x00000004,,0x00004000
			L1i L#14 (32KB) cpuset=0x00000004,,0x00004000
				Core L#14 cpuset=0x00000004,,0x00004000
				PU L#28 (P#14) cpuset=0x00004000
				PU L#29 (P#66) cpuset=0x00000004,,0x0
		L2 L#15 (1280KB) cpuset=0x00000008,,0x00008000
			L1d L#15 (48KB) cpuset=0x00000008,,0x00008000
			L1i L#15 (32KB) cpuset=0x00000008,,0x00008000
				Core L#15 cpuset=0x00000008,,0x00008000
				PU L#30 (P#15) cpuset=0x00008000
				PU L#31 (P#67) cpuset=0x00000008,,0x0
		L2 L#16 (1280KB) cpuset=0x00000010,,0x00010000
			L1d L#16 (48KB) cpuset=0x00000010,,0x00010000
			L1i L#16 (32KB) cpuset=0x00000010,,0x00010000
				Core L#16 cpuset=0x00000010,,0x00010000
				PU L#32 (P#16) cpuset=0x00010000
				PU L#33 (P#68) cpuset=0x00000010,,0x0
		L2 L#17 (1280KB) cpuset=0x00000020,,0x00020000
			L1d L#17 (48KB) cpuset=0x00000020,,0x00020000
			L1i L#17 (32KB) cpuset=0x00000020,,0x00020000
				Core L#17 cpuset=0x00000020,,0x00020000
				PU L#34 (P#17) cpuset=0x00020000
				PU L#35 (P#69) cpuset=0x00000020,,0x0
		L2 L#18 (1280KB) cpuset=0x00000040,,0x00040000
			L1d L#18 (48KB) cpuset=0x00000040,,0x00040000
			L1i L#18 (32KB) cpuset=0x00000040,,0x00040000
				Core L#18 cpuset=0x00000040,,0x00040000
				PU L#36 (P#18) cpuset=0x00040000
				PU L#37 (P#70) cpuset=0x00000040,,0x0
		L2 L#19 (1280KB) cpuset=0x00000080,,0x00080000
			L1d L#19 (48KB) cpuset=0x00000080,,0x00080000
			L1i L#19 (32KB) cpuset=0x00000080,,0x00080000
				Core L#19 cpuset=0x00000080,,0x00080000
				PU L#38 (P#19) cpuset=0x00080000
				PU L#39 (P#71) cpuset=0x00000080,,0x0
		L2 L#20 (1280KB) cpuset=0x00000100,,0x00100000
			L1d L#20 (48KB) cpuset=0x00000100,,0x00100000
			L1i L#20 (32KB) cpuset=0x00000100,,0x00100000
				Core L#20 cpuset=0x00000100,,0x00100000
				PU L#40 (P#20) cpuset=0x00100000
				PU L#41 (P#72) cpuset=0x00000100,,0x0
		L2 L#21 (1280KB) cpuset=0x00000200,,0x00200000
			L1d L#21 (48KB) cpuset=0x00000200,,0x00200000
			L1i L#21 (32KB) cpuset=0x00000200,,0x00200000
				Core L#21 cpuset=0x00000200,,0x00200000
				PU L#42 (P#21) cpuset=0x00200000
				PU L#43 (P#73) cpuset=0x00000200,,0x0
		L2 L#22 (1280KB) cpuset=0x00000400,,0x00400000
			L1d L#22 (48KB) cpuset=0x00000400,,0x00400000
			L1i L#22 (32KB) cpuset=0x00000400,,0x00400000
				Core L#22 cpuset=0x00000400,,0x00400000
				PU L#44 (P#22) cpuset=0x00400000
				PU L#45 (P#74) cpuset=0x00000400,,0x0
		L2 L#23 (1280KB) cpuset=0x00000800,,0x00800000
			L1d L#23 (48KB) cpuset=0x00000800,,0x00800000
			L1i L#23 (32KB) cpuset=0x00000800,,0x00800000
				Core L#23 cpuset=0x00000800,,0x00800000
				PU L#46 (P#23) cpuset=0x00800000
				PU L#47 (P#75) cpuset=0x00000800,,0x0
		L2 L#24 (1280KB) cpuset=0x00001000,,0x01000000
			L1d L#24 (48KB) cpuset=0x00001000,,0x01000000
			L1i L#24 (32KB) cpuset=0x00001000,,0x01000000
				Core L#24 cpuset=0x00001000,,0x01000000
				PU L#48 (P#24) cpuset=0x01000000
				PU L#49 (P#76) cpuset=0x00001000,,0x0
		L2 L#25 (1280KB) cpuset=0x00002000,,0x02000000
			L1d L#25 (48KB) cpuset=0x00002000,,0x02000000
			L1i L#25 (32KB) cpuset=0x00002000,,0x02000000
				Core L#25 cpuset=0x00002000,,0x02000000
				PU L#50 (P#25) cpuset=0x02000000
				PU L#51 (P#77) cpuset=0x00002000,,0x0
		HostBridge
		PCI 00:11.5 (SATA)
		PCI 00:17.0 (SATA)
		PCIBridge
			PCIBridge
			PCI 04:00.0 (VGA)
		HostBridge
		PCIBridge
			PCI 17:00.0 (InfiniBand)
			Net "ibs1"
			OpenFabrics "mlx5_0"
		HostBridge
		PCIBridge
			PCI 31:00.0 (RAID)
			Block(Disk) "sda"
		HostBridge
		PCIBridge
			PCI 65:00.0 (NVMExp)
		PCIBridge
			PCI 66:00.0 (NVMExp)
		PCIBridge
			PCI 67:00.0 (NVMExp)
		PCIBridge
			PCI 68:00.0 (NVMExp)
		Block(NVDIMM) "pmem0"
	*/

	// 这个是和lstopo --cpuset 输出结果一样
	/*
	root@server01:~# cat /tmp/daos_engine.0.log | grep 'Using CPU set'
	12/02-15:09:23.24 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00100000,0x00000001   (21,1)
	12/02-15:09:24.62 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00200000,0x00000002   (22,2)
	12/02-15:09:24.73 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00200000,0x00000002   (22,2) 和上边一样？
	12/02-15:09:24.76 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00400000,0x00000004   (23,3)
	12/02-15:09:26.21 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00800000,0x00000008   (24,4)
	12/02-15:09:26.41 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x01000000,0x00000010
	12/02-15:09:26.66 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x02000000,0x00000020
	12/02-15:09:26.88 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x04000000,0x00000040
	12/02-15:09:27.09 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x08000000,0x00000080
	12/02-15:09:27.30 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x10000000,0x00000100
	12/02-15:09:27.60 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x20000000,0x00000200
	12/02-15:09:27.82 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x40000000,0x00000400
	12/02-15:09:28.03 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x80000000,0x00000800
	12/02-15:09:28.22 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000001,,0x00001000
	12/02-15:09:28.42 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000002,,0x00002000
	12/02-15:09:28.68 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000004,,0x00004000
	12/02-15:09:28.88 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000008,,0x00008000
	12/02-15:09:29.17 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000010,,0x00010000
	12/02-15:09:29.38 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000020,,0x00020000
	12/02-15:09:29.58 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000040,,0x00040000
	12/02-15:09:29.78 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000080,,0x00080000
	12/02-15:09:29.98 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000100,,0x00100000
	12/02-15:09:30.17 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000200,,0x00200000
	12/02-15:09:30.37 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000400,,0x00400000
    12/02-15:09:30.47 server01 DAOS[2606652/-1/0] server DBUG src/engine/srv.c:921 dss_start_xs_id() Using CPU set 0x00000800,,0x00800000

	没有用到这两个core：core L#25 Core L#24 cpuset=0x00001000,,0x01000000 和 Core L#25 cpuset=0x00002000,,0x02000000
	// 一共26 个core，1和2用的一个core，所以总共用了 2+20+2= 24个core，剩余两个
	*/
	// 每个xs 的 cpuset 是一个物理核心，对应的两个逻辑核心，这里用的是逻辑核心
	// 当前机器是2个物理cpu，每个cpu 26个物理核，每个物理核两个线程，共有104 个逻辑核心（线程）
	/*
	root@server01:~# numactl --hardware
	available: 2 nodes (0-1)
	node 0 cpus: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77
	node 0 size: 257650 MB
	node 0 free: 209762 MB
	node 1 cpus: 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103
	node 1 size: 257994 MB
	node 1 free: 201980 MB
	node distances:
	node   0   1
	0:  10  20
	1:  20  10
	*/

	/*
	root@server01:~# lscpu
	Architecture:                       x86_64
	CPU op-mode(s):                     32-bit, 64-bit
	Byte Order:                         Little Endian
	Address sizes:                      46 bits physical, 57 bits virtual
	CPU(s):                             104
	On-line CPU(s) list:                0-103
	Thread(s) per core:                 2
	Core(s) per socket:                 26
	Socket(s):                          2
	NUMA node(s):                       2
	Vendor ID:                          GenuineIntel
	CPU family:                         6
	Model:                              106
	Model name:                         Intel(R) Xeon(R) Gold 5320 CPU @ 2.20GHz
	Stepping:                           6
	CPU MHz:                            2200.000
	CPU max MHz:                        2200.0000
	CPU min MHz:                        800.0000
	BogoMIPS:                           4400.00
	Virtualization:                     VT-x
	L1d cache:                          2.4 MiB
	L1i cache:                          1.6 MiB
	L2 cache:                           65 MiB
	L3 cache:                           78 MiB
	NUMA node0 CPU(s):                  0-25,52-77
	NUMA node1 CPU(s):                  26-51,78-103
	Vulnerability Gather data sampling: Mitigation; Microcode
	Vulnerability Itlb multihit:        Not affected
	Vulnerability L1tf:                 Not affected
	Vulnerability Mds:                  Not affected
	Vulnerability Meltdown:             Not affected
	Vulnerability Mmio stale data:      Mitigation; Clear CPU buffers; SMT vulnerable
	Vulnerability Retbleed:             Not affected
	Vulnerability Spec store bypass:    Mitigation; Speculative Store Bypass disabled via prctl and seccomp
	Vulnerability Spectre v1:           Mitigation; usercopy/swapgs barriers and __user pointer sanitization
	Vulnerability Spectre v2:           Mitigation; Enhanced IBRS, IBPB conditional, RSB filling, PBRSB-eIBRS SW sequence
	Vulnerability Srbds:                Not affected
	Vulnerability Tsx async abort:      Not affected
	Flags:                              fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscal
										l nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulq
										dq dtes64 ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer a
										es xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb cat_l3 invpcid_single ssbd mba ibrs ibpb stibp ibrs_enhance
										d tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx512f avx512dq
										rdseed adx smap avx512ifma clflushopt clwb intel_pt avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves cqm_llc
										cqm_occup_llc cqm_mbm_total cqm_mbm_local wbnoinvd dtherm arat pln pts hwp hwp_act_window hwp_epp hwp_pkg_req avx512vbmi umip
										pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg tme avx512_vpopcntdq rdpid md_clear pconfig flush_l1d ar
										ch_capabilities
	*/
	// lstopo -p 和lstopo -l 可以分别输出物理核心和逻辑核心
	/*
	root@server01:~# lstopo -l
	Machine (504GB total)
	Package L#0
		NUMANode L#0 (252GB)
		L3 L#0 (39MB)
		L2 L#0 (1280KB) + L1d L#0 (48KB) + L1i L#0 (32KB) + Core L#0
			PU L#0
			PU L#1
		L2 L#1 (1280KB) + L1d L#1 (48KB) + L1i L#1 (32KB) + Core L#1
			PU L#2
			PU L#3

	root@server01:~# lstopo -p
	Machine (504GB total)
	Package P#0
		NUMANode P#0 (252GB)
		L3 (39MB)
		L2 (1280KB) + L1d (48KB) + L1i (32KB) + Core P#0
			PU P#0
			PU P#52
		L2 (1280KB) + L1d (48KB) + L1i (32KB) + Core P#1
			PU P#1
			PU P#53
		L2 (1280KB) + L1d (48KB) + L1i (32KB) + Core P#2
			PU P#2
			PU P#54
	*/
	/* 
	1. 根据物理核心计算逻辑核心：
	root@server01:~# hwloc-calc --po --physical core:0
	0x00100000,0x00000001

	2. 根据逻辑核心计算物理核心：
	root@server01:~# hwloc-calc --po --physical pu:0
	0x00000001
	*/

	// 以cpusset 指定的物理核心和targs ，xs id 启动xs 服务
	rc = dss_start_one_xstream(obj->cpuset, tag, xs_id);
	if (rc)
		return rc;

	return 0;
}

static int
dss_xstreams_init(void)
{
	char	*env;
	int	rc = 0;
	int	i, xs_id;
	int      tags;

	D_ASSERT(dss_tgt_nr >= 1);

	d_getenv_bool("DAOS_SCHED_PRIO_DISABLED", &sched_prio_disabled);
	if (sched_prio_disabled)
		D_INFO("ULT prioritizing is disabled.\n");

#ifdef ULT_MMAP_STACK
	d_getenv_bool("DAOS_ULT_MMAP_STACK", &daos_ult_mmap_stack);
	if (daos_ult_mmap_stack == false)
		D_INFO("ULT mmap()'ed stack allocation is disabled.\n");
#endif

	d_getenv_int("DAOS_SCHED_RELAX_INTVL", &sched_relax_intvl);
	if (sched_relax_intvl == 0 ||
	    sched_relax_intvl > SCHED_RELAX_INTVL_MAX) {
		D_WARN("Invalid relax interval %u, set to default %u msecs.\n",
		       sched_relax_intvl, SCHED_RELAX_INTVL_DEFAULT);
		sched_relax_intvl = SCHED_RELAX_INTVL_DEFAULT;
	} else {
		D_INFO("CPU relax interval is set to %u msecs\n",
		       sched_relax_intvl);
	}

	env = getenv("DAOS_SCHED_RELAX_MODE");
	if (env) {
		sched_relax_mode = sched_relax_str2mode(env);
		if (sched_relax_mode == SCHED_RELAX_MODE_INVALID) {
			D_WARN("Invalid relax mode [%s]\n", env);
			sched_relax_mode = SCHED_RELAX_MODE_NET;
		}
	}
	D_INFO("CPU relax mode is set to [%s]\n",
	       sched_relax_mode2str(sched_relax_mode));

	d_getenv_int("DAOS_SCHED_UNIT_RUNTIME_MAX", &sched_unit_runtime_max);
	d_getenv_bool("DAOS_SCHED_WATCHDOG_ALL", &sched_watchdog_all);

	/* start the execution streams */
	D_DEBUG(DB_TRACE,
		"%d cores total detected starting %d main xstreams\n",
		dss_core_nr, dss_tgt_nr);

	if (dss_numa_node != -1) {
		D_DEBUG(DB_TRACE,
			"Detected %d cores on NUMA node %d\n",
			dss_num_cores_numa_node, dss_numa_node);
	}

	xstream_data.xd_xs_nr = DSS_XS_NR_TOTAL;
	// 第一次是 253
	tags                  = DAOS_SERVER_TAG - DAOS_TGT_TAG;
	/* start system service XS */
	// 启动sys xs 服务们
	for (i = 0; i < dss_sys_xs_nr; i++) {
		xs_id = i;
		// 启动idx 从 [0 - dss_sys_xs_nr] 个sys xs（从0 到2共3个）
		// 1. 启动sys xs
		// 253
		rc    = dss_start_xs_id(tags, xs_id);
		if (rc)
			D_GOTO(out, rc);
		// 每次都是 249
		tags &= ~DAOS_RDB_TAG;
	}

	/* start main IO service XS */
	// 启动main xs，个数等于配置文件中 target 的个数
	for (i = 0; i < dss_tgt_nr; i++) {
		// id 从sys xs 后继续排列
		xs_id = DSS_MAIN_XS_ID(i);
		// 2. 启动main xs（从3到22共20个）
		// 255
		rc    = dss_start_xs_id(DAOS_SERVER_TAG, xs_id);
		if (rc)
			D_GOTO(out, rc);
	}

	/* start offload XS if any */
	// 3. 启动helper 的xs（从23到24共2个）
	if (dss_tgt_offload_xs_nr > 0) {
		// dss_helper_pool 为 true
		if (dss_helper_pool) {
			for (i = 0; i < dss_tgt_offload_xs_nr; i++) {
				// 从sys xs和main xs 往后排序号
				xs_id = dss_sys_xs_nr + dss_tgt_nr + i;
				// 8
				rc    = dss_start_xs_id(DAOS_OFF_TAG, xs_id);
				if (rc)
					D_GOTO(out, rc);
			}
		} else {
			D_ASSERTF(dss_tgt_offload_xs_nr % dss_tgt_nr == 0,
				  "dss_tgt_offload_xs_nr %d, dss_tgt_nr %d\n",
				  dss_tgt_offload_xs_nr, dss_tgt_nr);
			for (i = 0; i < dss_tgt_nr; i++) {
				int j;

				for (j = 0; j < dss_tgt_offload_xs_nr /
						dss_tgt_nr; j++) {
					xs_id = DSS_MAIN_XS_ID(i) + j + 1;
					rc    = dss_start_xs_id(DAOS_OFF_TAG, xs_id);
					if (rc)
						D_GOTO(out, rc);
				}
			}
		}
	}

	// 所有的xs 都启动完成
	D_DEBUG(DB_TRACE, "%d execution streams successfully started "
		"(first core %d)\n", dss_tgt_nr, dss_core_offset);
out:
	return rc;
}

/**
 * Global TLS
 */

static void *
dss_srv_tls_init(int tags, int xs_id, int tgt_id)
{
	struct dss_module_info *info;

	D_ALLOC_PTR(info);

	return info;
}

static void
dss_srv_tls_fini(int tags, void *data)
{
	struct dss_module_info *info = (struct dss_module_info *)data;

	D_FREE(info);
}

struct dss_module_key daos_srv_modkey = {
	.dmk_tags = DAOS_SERVER_TAG,
	.dmk_index = -1,
	.dmk_init = dss_srv_tls_init,
	.dmk_fini = dss_srv_tls_fini,
};

/** TODO: use daos checksum library to offload checksum calculation */
static int
compute_checksum_ult(void *args)
{
	return 0;
}

/** TODO: use OFI calls to calculate checksum on FPGA */
static int
compute_checksum_acc(void *args)
{
	return 0;
}

/**
 * Generic offload call - abstraction for acceleration with
 *
 * \param[in] at_args	acceleration tasks with both ULT and FPGA
 */
int
dss_acc_offload(struct dss_acc_task *at_args)
{

	int		rc = 0;
	int		tid;

	/**
	 * Currently just launching it in this stream,
	 * ideally will move to a separate exclusive xstream
	 */
	tid = dss_get_module_info()->dmi_tgt_id;
	if (at_args == NULL) {
		D_ERROR("missing arguments for acc_offload\n");
		return -DER_INVAL;
	}

	if (at_args->at_offload_type <= DSS_OFFLOAD_MIN ||
	    at_args->at_offload_type >= DSS_OFFLOAD_MAX) {
		D_ERROR("Unknown type of offload\n");
		return -DER_INVAL;
	}

	switch (at_args->at_offload_type) {
	case DSS_OFFLOAD_ULT:
		rc = dss_ult_execute(compute_checksum_ult,
				at_args->at_params,
				NULL /* user-cb */,
				NULL /* user-cb args */,
				DSS_XS_OFFLOAD, tid,
				0);
		break;
	case DSS_OFFLOAD_ACC:
		/** calls to offload to FPGA*/
		rc = compute_checksum_acc(at_args->at_params);
		break;
	}

	return rc;
}

/**
 * Set parameters on the server.
 *
 * \param[in] key_id		key id
 * \param[in] value		the value of the key.
 * \param[in] value_extra	the extra value of the key.
 *
 * return	0 if setting succeeds.
 *              negative errno if fails.
 */
int
dss_parameters_set(unsigned int key_id, uint64_t value)
{
	int rc = 0;

	switch (key_id) {
	case DMG_KEY_FAIL_LOC:
		daos_fail_loc_set(value);
		break;
	case DMG_KEY_FAIL_VALUE:
		daos_fail_value_set(value);
		break;
	case DMG_KEY_FAIL_NUM:
		daos_fail_num_set(value);
		break;
	default:
		D_ERROR("invalid key_id %d\n", key_id);
		rc = -DER_INVAL;
	}

	return rc;
}

/** initializing steps */
// xs 初始化步骤
enum {
	XD_INIT_NONE,
	XD_INIT_MUTEX,
	XD_INIT_ULT_INIT,
	XD_INIT_ULT_BARRIER,
	XD_INIT_TLS_REG,
	XD_INIT_TLS_INIT,
	XD_INIT_SYS_DB,
	XD_INIT_XSTREAMS,
	XD_INIT_DRPC,
};

static void
dss_sys_db_fini(void)
{
	vos_db_fini();
}

/**
 * Entry point to start up and shutdown the service
 */
int
dss_srv_fini(bool force)
{
	int rc;

	switch (xstream_data.xd_init_step) {
	default:
		D_ASSERT(0);
	case XD_INIT_DRPC:
		rc = drpc_listener_fini();
		if (rc != 0)
			D_ERROR("failed to finalize dRPC listener: "DF_RC"\n", DP_RC(rc));
		/* fall through */
	case XD_INIT_XSTREAMS:
		dss_xstreams_fini(force);
		/* fall through */
	case XD_INIT_SYS_DB:
		dss_sys_db_fini();
		/* fall through */
	case XD_INIT_TLS_INIT:
		vos_standalone_tls_fini();
		/* fall through */
	case XD_INIT_TLS_REG:
		pthread_key_delete(dss_tls_key);
		/* fall through */
	case XD_INIT_ULT_BARRIER:
		ABT_cond_free(&xstream_data.xd_ult_barrier);
		/* fall through */
	case XD_INIT_ULT_INIT:
		ABT_cond_free(&xstream_data.xd_ult_init);
		/* fall through */
	case XD_INIT_MUTEX:
		ABT_mutex_free(&xstream_data.xd_mutex);
		/* fall through */
	case XD_INIT_NONE:
		if (xstream_data.xd_xs_ptrs != NULL)
			D_FREE(xstream_data.xd_xs_ptrs);
		D_DEBUG(DB_TRACE, "Finalized everything\n");
	}
	return 0;
}

static int
dss_sys_db_init()
{
	int	 rc;
	char	*sys_db_path = NULL;
	char	*nvme_conf_path = NULL;

	if (!bio_nvme_configured(SMD_DEV_TYPE_META))
		goto db_init;

	if (dss_nvme_conf == NULL) {
		D_ERROR("nvme conf path not set\n");
		return -DER_INVAL;
	}

	D_STRNDUP(nvme_conf_path, dss_nvme_conf, PATH_MAX);
	if (nvme_conf_path == NULL)
		return -DER_NOMEM;
	D_STRNDUP(sys_db_path, dirname(nvme_conf_path), PATH_MAX);
	D_FREE(nvme_conf_path);
	if (sys_db_path == NULL)
		return -DER_NOMEM;

db_init:
	// /mnt/daos0/daos_sys/sys_db
	// 这个是给smd 模块用的，vos db 是个全局的变量
	rc = vos_db_init(bio_nvme_configured(SMD_DEV_TYPE_META) ? sys_db_path : dss_storage_path);
	if (rc)
		goto out;

	rc = smd_init(vos_db_get());
	if (rc)
		vos_db_fini();
out:
	D_FREE(sys_db_path);

	return rc;
}

// 服务端初始化
int
dss_srv_init(void)
{
	int		 rc;
	bool		 started = true;

	xstream_data.xd_init_step  = XD_INIT_NONE;
	xstream_data.xd_ult_signal = false;

	// 用于保存所有的xs 信息
	D_ALLOC_ARRAY(xstream_data.xd_xs_ptrs, DSS_XS_NR_TOTAL);
	if (xstream_data.xd_xs_ptrs == NULL) {
		D_ERROR("Not enough DRAM to allocate XS array.\n");
		D_GOTO(failed, rc = -DER_NOMEM);
	}
	xstream_data.xd_xs_nr = 0;

	rc = ABT_mutex_create(&xstream_data.xd_mutex);
	if (rc != ABT_SUCCESS) {
		rc = dss_abterr2der(rc);
		D_ERROR("Failed to create XS mutex: "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}
	// xs 初始化状态机
	xstream_data.xd_init_step = XD_INIT_MUTEX;

	rc = ABT_cond_create(&xstream_data.xd_ult_init);
	if (rc != ABT_SUCCESS) {
		rc = dss_abterr2der(rc);
		D_ERROR("Failed to create XS ULT cond(1): "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}
	xstream_data.xd_init_step = XD_INIT_ULT_INIT;

	rc = ABT_cond_create(&xstream_data.xd_ult_barrier);
	if (rc != ABT_SUCCESS) {
		rc = dss_abterr2der(rc);
		D_ERROR("Failed to create XS ULT cond(2): "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}
	xstream_data.xd_init_step = XD_INIT_ULT_BARRIER;

	/* register xstream-local storage key */
	// 每个线程独有的数据的key
	rc = pthread_key_create(&dss_tls_key, NULL);
	if (rc) {
		rc = dss_abterr2der(rc);
		D_ERROR("Failed to register storage key: "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}
	xstream_data.xd_init_step = XD_INIT_TLS_REG;

	/* initialize xstream-local storage */
	rc = vos_standalone_tls_init(DAOS_SERVER_TAG - DAOS_TGT_TAG);
	if (rc) {
		D_ERROR("Not enough DRAM to initialize XS local storage.\n");
		D_GOTO(failed, rc = -DER_NOMEM);
	}
	xstream_data.xd_init_step = XD_INIT_TLS_INIT;

	// 创建 /mnt/daos0/daos_sys/sys_db 等
	// todo: 这个是通过raft 来保证副本一致性的吗？
	// todo: 这个和control_raft 下面的 daos_system.db 各自都是负责存储什么信息的
	// 现在这个是给vos 模块用的，是用的c 的raft 库，control_raft 是用的golang 的raft 库
	rc = dss_sys_db_init();
	if (rc != 0) {
		D_ERROR("Failed to initialize local DB: "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}
	xstream_data.xd_init_step = XD_INIT_SYS_DB;

	// 注册 rdma 相关的操作
	bio_register_bulk_ops(crt_bulk_create, crt_bulk_free);

	/* start xstreams */
	// 初始化启动所有的xs，包括vos target xs 和 sys xs。vos target xs 又分为main xs 和offload xs
	// todo: 哪种类型的rpc 在哪个xs 下调度是怎么处理的
	// 1. sys xs 负责
	/*
	*	RPC server for:
	*		drpc listener,
	*		RDB request and meta-data service,
	*		management request for mgmt module,
	*		pool request,
	*		container request (including the OID allocate),
	*		rebuild request such as REBUILD_OBJECTS_SCAN/REBUILD_OBJECTS,
	*		rebuild status checker,
	*		rebalance request,
	*		IV, bcast, and SWIM message handling.
	*/

	// 2. main xs 负责
	/*
	*	RPC server of IO request handler,
	*	ULT server for:
	*		rebuild scanner/puller
	*		rebalance,
	*		aggregation,
	*		data scrubbing,
	*		pool service (tgt connect/disconnect etc),
	*		container open/close.
	*/

	// 3. helper xs 负责
	/* ULT server for:
	*		IO request dispatch (TX coordinator, on 1st offload XS),
	*		Acceleration of EC/checksum/compress (on 2nd offload XS if
	*		dss_tgt_offload_xs_nr is 2, or on 1st offload XS).
	*/
	// 以上描述的3种xs 提供的不同服务是通过 'static struct crt_proto_rpc_format' 定义的各种接口来设置的
	// 具体定义在每个模块内部的 xxx_rpc.c 或者rpc.c 文件中，比如obj_rpc.c 中的 OBJ_PROTO_CLI_RPC_LIST 
	rc = dss_xstreams_init();
	if (!dss_xstreams_empty()) /* cleanup if we started something */
		xstream_data.xd_init_step = XD_INIT_XSTREAMS;

	if (rc != 0) {
		D_ERROR("Failed to start XS: "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}

	// 操纵全局nvme 状态
	rc = bio_nvme_ctl(BIO_CTL_NOTIFY_STARTED, &started);
	D_ASSERT(rc == 0);

	/* start up drpc listener */
	// todo: server 那边是怎么初始化的
	rc = drpc_listener_init();
	if (rc != 0) {
		D_ERROR("Failed to start dRPC listener: "DF_RC"\n", DP_RC(rc));
		D_GOTO(failed, rc);
	}
	xstream_data.xd_init_step = XD_INIT_DRPC;

	return 0;
failed:
	dss_srv_fini(true);
	return rc;
}

bool
dss_srv_shutting_down(void)
{
	return dss_get_module_info()->dmi_srv_shutting_down;
}

static void
set_draining(void *arg)
{
	dss_get_module_info()->dmi_srv_shutting_down = true;
}

/*
 * Set the dss_module_info.dmi_srv_shutting_down flag for all xstreams, so that
 * after this function returns, any dss_srv_shutting_down call (on any xstream)
 * returns true. See also server_fini.
 */
void
dss_srv_set_shutting_down(void)
{
	int	n = dss_xstream_cnt();
	int	i;
	int	rc;

	/* Could be parallel... */
	for (i = 0; i < n; i++) {
		struct dss_xstream     *dx = dss_get_xstream(i);
		ABT_task		task;

		rc = ABT_task_create(dx->dx_pools[DSS_POOL_GENERIC], set_draining, NULL /* arg */,
				     &task);
		D_ASSERTF(rc == ABT_SUCCESS, "create task: %d\n", rc);
		rc = ABT_task_free(&task);
		D_ASSERTF(rc == ABT_SUCCESS, "join task: %d\n", rc);
	}
}

void
dss_dump_ABT_state(FILE *fp)
{
	int			rc, num_pools, i, idx;
	struct dss_xstream	*dx;
	ABT_sched		sched;
	ABT_pool		pools[DSS_POOL_CNT];

	/* print Argobots config first */
	fprintf(fp, " == ABT config ==\n");
	rc = ABT_info_print_config(fp);
	if (rc != ABT_SUCCESS)
		D_ERROR("ABT_info_print_config() error, rc = %d\n", rc);

	fprintf(fp, " == List of all ESs ==\n");
	rc = ABT_info_print_all_xstreams(fp);
	if (rc != ABT_SUCCESS)
		D_ERROR("ABT_info_print_all_xstreams() error, rc = %d\n", rc);

	ABT_mutex_lock(xstream_data.xd_mutex);
	for (idx = 0; idx < xstream_data.xd_xs_nr; idx++) {
		dx = xstream_data.xd_xs_ptrs[idx];
		fprintf(fp, "== per ES (%p) details ==\n", dx->dx_xstream);
		rc = ABT_info_print_xstream(fp, dx->dx_xstream);
		if (rc != ABT_SUCCESS)
			D_ERROR("ABT_info_print_xstream() error, rc = %d, for "
				"DAOS xstream %p, ABT xstream %p\n", rc, dx,
				dx->dx_xstream);
		/* one progress ULT per xstream */
		if (dx->dx_progress != ABT_THREAD_NULL) {
			fprintf(fp, "== ES (%p) progress ULT (%p) ==\n",
				dx->dx_xstream, dx->dx_progress);
			rc = ABT_info_print_thread(fp, dx->dx_progress);
			if (rc != ABT_SUCCESS)
				D_ERROR("ABT_info_print_thread() error, "
					"rc = %d, for DAOS xstream %p, ABT "
					"xstream %p, progress ULT %p\n", rc, dx,
					dx->dx_xstream, dx->dx_progress);
			/* XXX
			 * do not print stack content as if unwiding with
			 * libunwind is enabled current implementation runs
			 * w/o synchronization/suspend of current ULT which
			 * is highly racy since unwiding will occur using
			 * the same stack
			rc = ABT_info_print_thread_stack(fp, dx->dx_progress);
			if (rc != ABT_SUCCESS)
				D_ERROR("ABT_info_print_thread_stack() error, "
					"rc = %d, for DAOS xstream %p, ABT "
					"xstream %p, progress ULT %p\n", rc, dx,
					dx->dx_xstream, dx->dx_progress);
			 */
		}
		/* only one sched per xstream */
		rc = ABT_xstream_get_main_sched(dx->dx_xstream, &sched);
		if (rc != ABT_SUCCESS) {
			D_ERROR("ABT_xstream_get_main_sched() error, rc = %d, "
				"for DAOS xstream %p, ABT xstream %p\n", rc, dx,
				dx->dx_xstream);
		} else if (sched != dx->dx_sched) {
			/* it's unexpected, unless DAOS will use stacked
			 * schedulers at some point of time, but try to
			 * continue anyway instead to abort
			 */
			D_WARN("DAOS xstream main sched %p differs from ABT "
			       "registered one %p, dumping both\n",
			       dx->dx_sched, sched);
			rc = ABT_info_print_sched(fp, sched);
			if (rc != ABT_SUCCESS)
				D_ERROR("ABT_info_print_sched() error, rc = "
					"%d, for DAOS xstream %p, ABT xstream "
					"%p, sched %p\n", rc, dx,
					dx->dx_xstream, sched);
		}
		rc = ABT_info_print_sched(fp, dx->dx_sched);
		if (rc != ABT_SUCCESS)
			D_ERROR("ABT_info_print_sched() error, rc = %d, for "
				"DAOS xstream %p, ABT xstream %p, sched %p\n",
				rc, dx, dx->dx_xstream, dx->dx_sched);

		rc = ABT_sched_get_num_pools(dx->dx_sched, &num_pools);
		if (rc != ABT_SUCCESS) {
			D_ERROR("ABT_sched_get_num_pools() error, rc = %d, for "
				"DAOS xstream %p, ABT xstream %p, sched %p\n",
				rc, dx, dx->dx_xstream, dx->dx_sched);
			continue;
		}
		if (num_pools != DSS_POOL_CNT)
			D_WARN("DAOS xstream %p, ABT xstream %p, sched %p "
				"number of pools %d != %d\n", dx,
				dx->dx_xstream, dx->dx_sched, num_pools,
				DSS_POOL_CNT);
		rc = ABT_sched_get_pools(dx->dx_sched, num_pools, 0, pools);
		if (rc != ABT_SUCCESS) {
			D_ERROR("ABT_sched_get_pools() error, rc = %d, for "
				"DAOS xstream %p, ABT xstream %p, sched %p\n",
				rc, dx, dx->dx_xstream, dx->dx_sched);
			continue;
		}
		for (i = 0; i < num_pools; i++) {
			fprintf(fp, "== per POOL (%p) details ==\n", pools[i]);
			if (pools[i] == ABT_POOL_NULL) {
				D_WARN("DAOS xstream %p, ABT xstream %p, "
				       "sched %p, no pool[%d]\n", dx,
				       dx->dx_xstream, dx->dx_sched, i);
				continue;
			}
			if (pools[i] != dx->dx_pools[i]) {
				D_WARN("DAOS xstream pool[%d]=%p differs from "
				       "ABT registered one %p for sched %p\n",
				       i, dx->dx_pools[i], pools[i],
				       dx->dx_sched);
			}
			rc = ABT_info_print_pool(fp, pools[i]);
			if (rc != ABT_SUCCESS)
				D_ERROR("ABT_info_print_pool() error, rc = %d, "
					"for DAOS xstream %p, ABT xstream %p, "
					"sched %p, pool[%d]\n", rc, dx,
					dx->dx_xstream, dx->dx_sched, i);
			/* XXX
			 * same concern than with ABT_info_print_thread_stack()
			 * before
			rc = ABT_info_print_thread_stacks_in_pool(fp, pools[i]);
			if (rc != ABT_SUCCESS)
				D_ERROR("ABT_info_print_thread_stacks_in_pool() error, rc = %d, "
					"for DAOS xstream %p, ABT xstream %p, "
					"sched %p, pool[%d]\n", rc, dx,
					dx->dx_xstream, dx->dx_sched, i);
			 */
		}
	}
	ABT_mutex_unlock(xstream_data.xd_mutex);
}

/**
 * Anytime when the server (re)start, the dss_start_epoch will be set as
 * current known highest HLC. In theory it should be the highest one for
 * the whole system, any other transaction with old epoch (HLC) in spite
 * of being generated by which server will be regarded as started before
 * current server (re)start. Current server will refuse such transaction
 * and require its sponsor to restart it with newer epoch.
 */
static daos_epoch_t dss_start_epoch;

daos_epoch_t
dss_get_start_epoch(void)
{
	return dss_start_epoch;
}

void
dss_set_start_epoch(void)
{
	dss_start_epoch = d_hlc_get();
}

/**
 * Currently, we do not have recommendatory ratio for main IO XS vs helper XS.
 * But if helper XS is too less or non-configured, then it may cause system to
 * be very slow as to RPC timeout under heavy load.
 */
bool
dss_has_enough_helper(void)
{
	return dss_tgt_offload_xs_nr > 0;
}

/**
 * Miscellaneous routines
 */
void
dss_bind_to_xstream_cpuset(int tgt_id)
{
	struct dss_xstream *dx;

	dx = dss_get_xstream(DSS_MAIN_XS_ID(tgt_id));
	(void)dss_xstream_set_affinity(dx);
}
