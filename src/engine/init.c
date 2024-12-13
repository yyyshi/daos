/*
 * (C) Copyright 2016-2023 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
/**
 * \file
 *
 * This file is part of the DAOS server. It implements the startup/shutdown
 * routines for the daos_server.
 */

#define D_LOGFAC	DD_FAC(server)

#include <signal.h>
#include <abt.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <execinfo.h>

#include <daos/btree_class.h>
#include <daos/common.h>
#include <daos/placement.h>
#include "srv_internal.h"
#include "drpc_internal.h"
#include <gurt/telemetry_common.h>
#include <gurt/telemetry_producer.h>

#include <daos.h> /* for daos_init() */

#define MAX_MODULE_OPTIONS	64
#if BUILD_PIPELINE

// 加载的列表在这里
#define MODULE_LIST	"vos,rdb,rsvc,security,mgmt,dtx,pool,cont,obj,rebuild,pipeline"
#else
#define MODULE_LIST	"vos,rdb,rsvc,security,mgmt,dtx,pool,cont,obj,rebuild"
#endif

/** List of modules to load */
static char		modules[MAX_MODULE_OPTIONS + 1];

/**
 * Number of target threads the user would like to start.
 */
// target 个数
static unsigned int	nr_threads;

/** DAOS system name (corresponds to crt group ID) */
static char	       *daos_sysname = DAOS_DEFAULT_SYS_NAME;

/** Storage node hostname */
char		        dss_hostname[DSS_HOSTNAME_MAX_LEN];

/** Storage path (hack) */
const char	       *dss_storage_path = "/mnt/daos";

/** NVMe config file */
const char	       *dss_nvme_conf;

/** Socket Directory */
const char	       *dss_socket_dir = "/var/run/daos_server";

/** NVMe mem_size for SPDK memory allocation */
unsigned int		dss_nvme_mem_size = DAOS_NVME_MEM_PRIMARY;

/** NVMe hugepage_size for DPDK/SPDK memory allocation */
unsigned int		dss_nvme_hugepage_size;

/** I/O Engine instance index */
unsigned int		dss_instance_idx;

/** HW topology */
hwloc_topology_t	dss_topo;
/** core depth of the topology */
// 物理核心在topo 结构中的树的高度
int			dss_core_depth;
/** number of physical cores, w/o hyperthreading */
// 物理核心数，没有超线程。w/o 是论文中常见的缩写：without
int			dss_core_nr;
/** start offset index of the first core for service XS */
// xs 服务使用的第一个core 的索引
unsigned int		dss_core_offset;
/** NUMA node to bind to */
int			dss_numa_node = -1;
hwloc_bitmap_t	core_allocation_bitmap;
/** a copy of the NUMA node object in the topology */
hwloc_obj_t		numa_obj;
/** number of cores in the given NUMA node */
int			dss_num_cores_numa_node;
/** Module facility bitmask */
static uint64_t		dss_mod_facs;
/** Number of storage tiers: 2 for SCM and NVMe */
unsigned int		dss_storage_tiers = 2;

/** Flag to indicate Arbogots is initialized */
static bool dss_abt_init;

/* stream used to dump ABT infos and ULTs stacks */
static FILE *abt_infos;

d_rank_t
dss_self_rank(void)
{
	d_rank_t	rank;
	int		rc;

	rc = crt_group_rank(NULL /* grp */, &rank);
	D_ASSERTF(rc == 0, ""DF_RC"\n", DP_RC(rc));

	return rank;
}

struct dss_module_info *
get_module_info(void)
{
	return dss_get_module_info();
}

/* See the comment near where this function is called. */
static uint64_t
hlc_recovery_begin(void)
{
	return d_hlc_epsilon_get_bound(d_hlc_get());
}

/* See the comment near where this function is called. */
static void
hlc_recovery_end(uint64_t bound)
{
	int64_t	diff;

	diff = bound - d_hlc_get();
	if (diff > 0) {
		struct timespec	tv;

		tv.tv_sec = d_hlc2nsec(diff) / NSEC_PER_SEC;
		tv.tv_nsec = d_hlc2nsec(diff) % NSEC_PER_SEC;

		/* XXX: If the server restart so quickly as to all related
		 *	things are handled within HLC epsilon, then it is
		 *	possible that current local HLC after restart may
		 *	be older than some HLC that was generated before
		 *	server restart because of the clock drift between
		 *	servers. So here, we control the server (re)start
		 *	process to guarantee that the restart time window
		 *	will be longer than the HLC epsilon, then new HLC
		 *	generated after server restart will not rollback.
		 */
		D_INFO("nanosleep %lu:%lu before open external service.\n",
		       tv.tv_sec, tv.tv_nsec);
		nanosleep(&tv, NULL);
	}
}

/*
 * Register the dbtree classes used by native server-side modules (e.g.,
 * ds_pool, ds_cont, etc.). Unregistering is currently not supported.
 */
static int
register_dbtree_classes(void)
{
	int rc;

	// 注册多种类型的tree 类型，及对应的系列树操作
	// 不定长k - 不定长v 树
	rc = dbtree_class_register(DBTREE_CLASS_KV, 0 /* feats */,
				   &dbtree_kv_ops);
	if (rc != 0) {
		D_ERROR("failed to register DBTREE_CLASS_KV: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	// int - 不定长v 树
	rc = dbtree_class_register(DBTREE_CLASS_IV,
				   BTR_FEAT_UINT_KEY | BTR_FEAT_DIRECT_KEY,
				   &dbtree_iv_ops);
	if (rc != 0) {
		D_ERROR("failed to register DBTREE_CLASS_IV: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	// int - 定长v 树
	rc = dbtree_class_register(DBTREE_CLASS_IFV, BTR_FEAT_UINT_KEY | BTR_FEAT_DIRECT_KEY,
				   &dbtree_ifv_ops);
	if (rc != 0) {
		D_ERROR("failed to register DBTREE_CLASS_IFV: " DF_RC "\n", DP_RC(rc));
		return rc;
	}

	// name - value 树
	rc = dbtree_class_register(DBTREE_CLASS_NV, BTR_FEAT_DIRECT_KEY,
				   &dbtree_nv_ops);
	if (rc != 0) {
		D_ERROR("failed to register DBTREE_CLASS_NV: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	// uuid - value 树
	rc = dbtree_class_register(DBTREE_CLASS_UV, 0 /* feats */,
				   &dbtree_uv_ops);
	if (rc != 0) {
		D_ERROR("failed to register DBTREE_CLASS_UV: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	// epoch - count 树
	rc = dbtree_class_register(DBTREE_CLASS_EC,
				   BTR_FEAT_UINT_KEY /* feats */,
				   &dbtree_ec_ops);
	if (rc != 0) {
		D_ERROR("failed to register DBTREE_CLASS_EC: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	return rc;
}

static int
modules_load(void)
{
	char		*mod;
	char		*sep;
	char		*run;
	int		 rc = 0;

	// 加载好的模块信息拷贝给sep
	D_STRNDUP(sep, modules, MAX_MODULE_OPTIONS + 1);
	if (sep == NULL)
		return -DER_NOMEM;
	run = sep;

	// 按字符 ， 将sep切割，每次返回切出来的第一个
	mod = strsep(&run, ",");
	// todo: 这里只看到这么几个模块，为啥日志显示那么多
	// ValidateLogSubsystems 子模块
	while (mod != NULL) {
		// 这几个需要换名
		// todo: 为啥换名
		if (strcmp(mod, "object") == 0)
			mod = "obj";
		else if (strcmp(mod, "po") == 0)
			mod = "pool";
		else if (strcmp(mod, "container") == 0 ||
			 strcmp(mod, "co") == 0)
			mod = "cont";
		else if (strcmp(mod, "management") == 0)
			mod = "mgmt";
		else if (strcmp(mod, "vos") == 0)
			mod = "vos_srv";

		// 加载模块
		rc = dss_module_load(mod);
		if (rc != 0) {
			D_ERROR("Failed to load module %s: %d\n", mod, rc);
			break;
		}

		// 再切
		mod = strsep(&run, ",");
	}

	D_FREE(sep);
	return rc;
}

static unsigned int
ncores_needed(unsigned int tgt_nr, unsigned int nr_helpers)
{
	// 每个target/每个helper 都会占用一个物理核心
	return DAOS_TGT0_OFFSET + tgt_nr + nr_helpers;
}

/**
 * Check if the #targets and #nr_xs_helpers is valid to start server, the #nr_xs_helpers possibly
 * be reduced.
 */
// ncores 为提供给当前engine 的物理核心个数，tgt_nr 为配置的target 个数
// oversubscribe 为1 表示在资源不足时，允许强制启动，强制启动会导致daos 性能受损
static int
dss_tgt_nr_check(unsigned int ncores, unsigned int tgt_nr, bool oversubscribe)
{
	D_ASSERT(ncores >= 1);

	/* at most 2 helper XS per target */
	// 这里注释写错了，应该是 per engine
	// dss_tgt_offload_xs_nr 为helper 个数，设置的是 2，tgt_nr 为 20
	if (dss_tgt_offload_xs_nr > 2 * tgt_nr) {
		// helper 个数如果超过2倍的target 个数，强制设置为 2倍
		D_PRINT("#nr_xs_helpers(%d) cannot exceed 2 times #targets (2 x %d = %d).\n",
			dss_tgt_offload_xs_nr, tgt_nr, 2 * tgt_nr);
		dss_tgt_offload_xs_nr = 2 * tgt_nr;
	} else if (dss_tgt_offload_xs_nr == 0) {
		// 至少需要一个helper
		D_WARN("Suggest to config at least 1 helper XS per DAOS engine\n");
	}

	if (oversubscribe) {
		if (ncores_needed(tgt_nr, dss_tgt_offload_xs_nr) > ncores)
			D_PRINT("Force to start engine with %d targets %d xs_helpers on %d cores("
				"%d cores reserved for system service).\n",
				tgt_nr, dss_tgt_offload_xs_nr, ncores, DAOS_TGT0_OFFSET);
		goto out;
	}

	// target 和helper 占用的物理核心数大于总核心数，非法
	if (ncores_needed(tgt_nr, dss_tgt_offload_xs_nr) > ncores) {
		D_ERROR("cannot start engine with %d targets %d xs_helpers on %d cores, may try "
			"with DAOS_TARGET_OVERSUBSCRIBE=1 or reduce #targets/#nr_xs_helpers("
			"%d cores reserved for system service).\n",
			tgt_nr, dss_tgt_offload_xs_nr, ncores, DAOS_TGT0_OFFSET);
		return -DER_INVAL;
	}

out:
	// todo: 还有整倍数这个限制吗，当前设置的offload 是2，target nr 是20，所以为 true
	if (dss_tgt_offload_xs_nr % tgt_nr != 0)
		dss_helper_pool = true;

	return 0;
}

static int
dss_topo_init()
{
	// numa 0 的topo 如下，有26 个物理核，目前是设置了 20 个target 和 2个helper。同时绑定了pmem0 和4个nvme
	/*
	root@server01:/tmp# hwloc-ls
	Machine (504GB total)
	Package L#0
		NUMANode L#0 (P#0 252GB)
		L3 L#0 (39MB)
		L2 L#0 (1280KB) + L1d L#0 (48KB) + L1i L#0 (32KB) + Core L#0
			PU L#0 (P#0)
			PU L#1 (P#52)
		L2 L#1 (1280KB) + L1d L#1 (48KB) + L1i L#1 (32KB) + Core L#1
			PU L#2 (P#1)
			PU L#3 (P#53)
		L2 L#2 (1280KB) + L1d L#2 (48KB) + L1i L#2 (32KB) + Core L#2
			PU L#4 (P#2)
			PU L#5 (P#54)
		L2 L#3 (1280KB) + L1d L#3 (48KB) + L1i L#3 (32KB) + Core L#3
			PU L#6 (P#3)
			PU L#7 (P#55)
		L2 L#4 (1280KB) + L1d L#4 (48KB) + L1i L#4 (32KB) + Core L#4
			PU L#8 (P#4)
			PU L#9 (P#56)
		L2 L#5 (1280KB) + L1d L#5 (48KB) + L1i L#5 (32KB) + Core L#5
			PU L#10 (P#5)
			PU L#11 (P#57)
		L2 L#6 (1280KB) + L1d L#6 (48KB) + L1i L#6 (32KB) + Core L#6
			PU L#12 (P#6)
			PU L#13 (P#58)
		L2 L#7 (1280KB) + L1d L#7 (48KB) + L1i L#7 (32KB) + Core L#7
			PU L#14 (P#7)
			PU L#15 (P#59)
		L2 L#8 (1280KB) + L1d L#8 (48KB) + L1i L#8 (32KB) + Core L#8
			PU L#16 (P#8)
			PU L#17 (P#60)
		L2 L#9 (1280KB) + L1d L#9 (48KB) + L1i L#9 (32KB) + Core L#9
			PU L#18 (P#9)
			PU L#19 (P#61)
		L2 L#10 (1280KB) + L1d L#10 (48KB) + L1i L#10 (32KB) + Core L#10
			PU L#20 (P#10)
			PU L#21 (P#62)
		L2 L#11 (1280KB) + L1d L#11 (48KB) + L1i L#11 (32KB) + Core L#11
			PU L#22 (P#11)
			PU L#23 (P#63)
		L2 L#12 (1280KB) + L1d L#12 (48KB) + L1i L#12 (32KB) + Core L#12
			PU L#24 (P#12)
			PU L#25 (P#64)
		L2 L#13 (1280KB) + L1d L#13 (48KB) + L1i L#13 (32KB) + Core L#13
			PU L#26 (P#13)
			PU L#27 (P#65)
		L2 L#14 (1280KB) + L1d L#14 (48KB) + L1i L#14 (32KB) + Core L#14
			PU L#28 (P#14)
			PU L#29 (P#66)
		L2 L#15 (1280KB) + L1d L#15 (48KB) + L1i L#15 (32KB) + Core L#15
			PU L#30 (P#15)
			PU L#31 (P#67)
		L2 L#16 (1280KB) + L1d L#16 (48KB) + L1i L#16 (32KB) + Core L#16
			PU L#32 (P#16)
			PU L#33 (P#68)
		L2 L#17 (1280KB) + L1d L#17 (48KB) + L1i L#17 (32KB) + Core L#17
			PU L#34 (P#17)
			PU L#35 (P#69)
		L2 L#18 (1280KB) + L1d L#18 (48KB) + L1i L#18 (32KB) + Core L#18
			PU L#36 (P#18)
			PU L#37 (P#70)
		L2 L#19 (1280KB) + L1d L#19 (48KB) + L1i L#19 (32KB) + Core L#19
			PU L#38 (P#19)
			PU L#39 (P#71)
		L2 L#20 (1280KB) + L1d L#20 (48KB) + L1i L#20 (32KB) + Core L#20
			PU L#40 (P#20)
			PU L#41 (P#72)
		L2 L#21 (1280KB) + L1d L#21 (48KB) + L1i L#21 (32KB) + Core L#21
			PU L#42 (P#21)
			PU L#43 (P#73)
		L2 L#22 (1280KB) + L1d L#22 (48KB) + L1i L#22 (32KB) + Core L#22
			PU L#44 (P#22)
			PU L#45 (P#74)
		L2 L#23 (1280KB) + L1d L#23 (48KB) + L1i L#23 (32KB) + Core L#23
			PU L#46 (P#23)
			PU L#47 (P#75)
		L2 L#24 (1280KB) + L1d L#24 (48KB) + L1i L#24 (32KB) + Core L#24
			PU L#48 (P#24)
			PU L#49 (P#76)
		L2 L#25 (1280KB) + L1d L#25 (48KB) + L1i L#25 (32KB) + Core L#25
			PU L#50 (P#25)
			PU L#51 (P#77)
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
	Package L#1
	*/
	int		depth;
	int		numa_node_nr;
	int		num_cores_visited;
	char		*cpuset;
	int		k;
	hwloc_obj_t	corenode;
	bool            tgt_oversub = false;

	// apt install hwloc
	// hwloc-ls 返回的信息和lstopo 返回的信息一摸一样
	hwloc_topology_init(&dss_topo);
	hwloc_topology_load(dss_topo);

	// 1. 获取type 为core 类型的depth，以后调用 hwloc_get_obj_by_depth 需要用到
	// depth 含义：整个topo 可以认为是一棵树，depth 就是所在层的树的高度
	dss_core_depth = hwloc_get_type_depth(dss_topo, HWLOC_OBJ_CORE);
	// 2. 获取type 为core 类型总数量
	dss_core_nr = hwloc_get_nbobjs_by_type(dss_topo, HWLOC_OBJ_CORE);
	// 获取numa 所在topo 树高度
	depth = hwloc_get_type_depth(dss_topo, HWLOC_OBJ_NUMANODE);
	// 设置 numa 个数
	numa_node_nr = hwloc_get_nbobjs_by_depth(dss_topo, depth);
	// 这个参数为 1 表示物理核不够用需要强制启动daos，将会影响daos 性能
	d_getenv_bool("DAOS_TARGET_OVERSUBSCRIBE", &tgt_oversub);
	// target 个数
	dss_tgt_nr = nr_threads;

	/* if no NUMA node was specified, or NUMA data unavailable */
	/* fall back to the legacy core allocation algorithm */
	// 未指定numa 的场景，当前是指定了 numa 的
	if (dss_numa_node == -1 || numa_node_nr <= 0) {
		D_PRINT("Using legacy core allocation algorithm\n");
		if (dss_core_offset >= dss_core_nr) {
			D_ERROR("invalid dss_core_offset %u (set by \"-f\" option), should within "
				"range [0, %u]\n",
				dss_core_offset, dss_core_nr - 1);
			return -DER_INVAL;
		}

		return dss_tgt_nr_check(dss_core_nr, dss_tgt_nr, tgt_oversub);
	}

	// 分配给engine 的numa 不合法
	if (dss_numa_node > numa_node_nr) {
		D_ERROR("Invalid NUMA node selected. Must be no larger than %d\n", numa_node_nr);
		return -DER_INVAL;
	}

	// 分配给engine 的 numa = dss_numa_node 合法，获取numa obj
	numa_obj = hwloc_get_obj_by_depth(dss_topo, depth, dss_numa_node);
	if (numa_obj == NULL) {
		D_ERROR("NUMA node %d was not found in the topology\n", dss_numa_node);
		return -DER_INVAL;
	}

	/* create an empty bitmap, then set each bit as we */
	/* find a core that matches */
	// 创建一个空的bitmap
	core_allocation_bitmap = hwloc_bitmap_alloc();
	if (core_allocation_bitmap == NULL) {
		D_ERROR("Unable to allocate core allocation bitmap\n");
		return -DER_INVAL;
	}

	/*
	root@server01:/tmp# hwloc-info
	depth 0:           1 Machine (type #0)
	depth 1:          2 Package (type #1)
	depth 2:         2 L3Cache (type #6)
	depth 3:        52 L2Cache (type #5)
		depth 4:       52 L1dCache (type #4)
		depth 5:      52 L1iCache (type #9)
		depth 6:     52 Core (type #2)
		depth 7:    104 PU (type #3)
	Special depth -3:  2 NUMANode (type #13)
	Special depth -4:  21 Bridge (type #14)
	Special depth -5:  16 PCIDev (type #15)
	Special depth -6:  9 OSDev (type #16)
	*/
	dss_num_cores_numa_node = 0;
	num_cores_visited = 0;

	// 遍历topo 树中 core  这一层的所有信息
	// 当前机器型号下，dss_core_nr = 26 = 物理核心数
	for (k = 0; k < dss_core_nr; k++) {
		// 依次获取depth 层中每个core
		corenode = hwloc_get_obj_by_depth(dss_topo, dss_core_depth, k);
		if (corenode == NULL)
			continue;
		// 判断numa_obj 对应的numa 的cpuset 指向的所有物理核心中，是否包含 corenode->cpuset 这个核心
		// Test whether bitmap sub_bitmap is part of bitmap super_bitmap.
		// 参数1 是sub bitmap，参数2 是super bitmap。返回1 表示包含
		if (hwloc_bitmap_isincluded(corenode->cpuset,
					    numa_obj->cpuset) != 0) {
			// super 包含sub
			// todo: 启动参数中没有设置起始core idx（dss_core_offset），默认为 0 吗
			if (num_cores_visited++ >= dss_core_offset) {
				// 如果当前操作的 k 个core，比分配的第一个core 的offset 还大，表示合法
				// 将core_allocation_bitmap 中第 k个 bit 位设置为 1，1 表示该位对应的core 可用
				hwloc_bitmap_set(core_allocation_bitmap, k);
				// 将当前操作的第k 个corenode 转化为字符串，保存到 cpuset 变量中
				hwloc_bitmap_asprintf(&cpuset,
						      corenode->cpuset);
			}
			dss_num_cores_numa_node++;
		}
	}
	// 转化为字符串格式
	hwloc_bitmap_asprintf(&cpuset, core_allocation_bitmap);
	// 上面转化，这里就free 了，目的是啥
	free(cpuset);
	// 第一个core 比numa 还大，非法
	if (dss_core_offset >= dss_num_cores_numa_node) {
		D_ERROR("invalid dss_core_offset %d (set by \"-f\" option), should within range "
			"[0, %d]\n",
			dss_core_offset, dss_num_cores_numa_node - 1);
		return -DER_INVAL;
	}
	D_PRINT("Using NUMA core allocation algorithm\n");

	// 逻辑核指的是通过超线程技术，在同一个物理核模拟出来的核心，daos 中绑定target 的都是逻辑核
	// 检查target num 和物理cores 分配是否够用
	// 当前是每个engine 2 x 26 核。target 为 20 个
	// dss_num_cores_numa_node = 26，dss_tgt_nr = 20
	return dss_tgt_nr_check(dss_num_cores_numa_node, dss_tgt_nr, tgt_oversub);
}

static ABT_mutex		server_init_state_mutex;
static ABT_cond			server_init_state_cv;
static enum dss_init_state	server_init_state;

static int
server_init_state_init(void)
{
	int rc;

	rc = ABT_mutex_create(&server_init_state_mutex);
	if (rc != ABT_SUCCESS)
		return dss_abterr2der(rc);
	rc = ABT_cond_create(&server_init_state_cv);
	if (rc != ABT_SUCCESS) {
		ABT_mutex_free(&server_init_state_mutex);
		return dss_abterr2der(rc);
	}
	return 0;
}

static void
server_init_state_fini(void)
{
	server_init_state = DSS_INIT_STATE_INIT;
	ABT_cond_free(&server_init_state_cv);
	ABT_mutex_free(&server_init_state_mutex);
}

static void
server_init_state_wait(enum dss_init_state state)
{
	D_INFO("waiting for server init state %d\n", state);
	ABT_mutex_lock(server_init_state_mutex);
	while (server_init_state != state)
		ABT_cond_wait(server_init_state_cv, server_init_state_mutex);
	ABT_mutex_unlock(server_init_state_mutex);
}

void
dss_init_state_set(enum dss_init_state state)
{
	D_INFO("setting server init state to %d\n", state);
	ABT_mutex_lock(server_init_state_mutex);
	server_init_state = state;
	ABT_cond_broadcast(server_init_state_cv);
	ABT_mutex_unlock(server_init_state_mutex);
}

static int
abt_max_num_xstreams(void)
{
	char   *env;

	// env 看不到以下环境变量
	env = getenv("ABT_MAX_NUM_XSTREAMS");
	if (env == NULL)
		env = getenv("ABT_ENV_MAX_NUM_XSTREAMS");
	if (env != NULL)
		return atoi(env);
	return 0;
}

static int
set_abt_max_num_xstreams(int n)
{
	char   *name = "ABT_MAX_NUM_XSTREAMS";
	char   *value;
	int	rc;

	D_ASSERTF(n > 0, "%d\n", n);
	D_ASPRINTF(value, "%d", n);
	if (value == NULL)
		return -DER_NOMEM;
	D_INFO("Setting %s to %s\n", name, value);
	// 设置到环境变量
	rc = setenv(name, value, 1 /* overwrite */);
	D_FREE(value);
	if (rc != 0)
		return daos_errno2der(errno);
	return 0;
}

static int
abt_init(int argc, char *argv[])
{
	// nrequested = 0
	int	nrequested = abt_max_num_xstreams();
	// 1+ （3 sys） + （20 个target） + （2 个helper）= 26（那个机器一共26个核心，如果多设置一个target 是不是就报错了）
	// todo：main xs 不是应该包含在 20 个target 中了么
	int	nrequired = 1 /* primary xstream */ + DSS_XS_NR_TOTAL;
	int	rc;

	/*
	 * Set ABT_MAX_NUM_XSTREAMS to the larger of nrequested and nrequired.
	 * If we don't do this, Argobots may use a default or requested value
	 * less than nrequired. We may then hit Argobots assertion failures
	 * because xstream_data.xd_mutex's internal queue has fewer slots than
	 * some xstreams' rank numbers need.
	 */
	// 设置max num xs
	rc = set_abt_max_num_xstreams(max(nrequested, nrequired));
	if (rc != 0)
		return daos_errno2der(errno);

	/* Now, initialize Argobots. */
	// abt 初始化
	// 启动参数： /opt/daos/bin/daos_engine -t 20 -x 2 -g daos_server -d /var/run/daos_server -T 2 -n /mnt/daos/2/daos_nvme.conf -p 1 -I 1 -r 20480 -H 2 -s /mnt/daos/2
	// todo: abt 能识别这些参数么
	rc = ABT_init(argc, argv);
	if (rc != ABT_SUCCESS) {
		D_ERROR("failed to init ABT: %d\n", rc);
		return dss_abterr2der(rc);
	}

#ifdef ULT_MMAP_STACK
	FILE *fp;

	/* read vm.max_map_count from /proc instead of using sysctl() API
	 * as it seems the preferred way ...
	 */
	fp = fopen("/proc/sys/vm/max_map_count", "r");
	if (fp == NULL) {
		D_ERROR("Unable to open /proc/sys/vm/max_map_count: %s\n",
			strerror(errno));
	} else {
		int n;

		n = fscanf(fp, "%d", &max_nb_mmap_stacks);
		if (n == EOF) {
			D_ERROR("Unable to read vm.max_map_count value: %s\n",
				strerror(errno));
			/* just in case, to ensure value can be later safely
			 * compared and thus no ULT stack be mmap()'ed
			 */
			max_nb_mmap_stacks = 0;
		} else {
			/* need a minimum value to start mmap() ULT stacks */
			if (max_nb_mmap_stacks < MIN_VM_MAX_MAP_COUNT) {
				D_WARN("vm.max_map_count (%d) value is too low (< %d) to start mmap() ULT stacks\n",
				       max_nb_mmap_stacks, MIN_VM_MAX_MAP_COUNT);
				max_nb_mmap_stacks = 0;
			} else {
				/* consider half can be used to mmap() ULT
				 * stacks
				 */
				max_nb_mmap_stacks /= 2;
				D_INFO("Will be able to mmap() %d ULT stacks\n",
				       max_nb_mmap_stacks);
			}
		}
	}

	rc = ABT_key_create(free_stack, &stack_key);
	if (rc != ABT_SUCCESS) {
		D_ERROR("ABT key for stack create failed: %d\n", rc);
		ABT_finalize();
		return dss_abterr2der(rc);
	}
#endif
	// abt init 完成
	dss_abt_init = true;

	return 0;
}

static void
abt_fini(void)
{
#ifdef ULT_MMAP_STACK
	ABT_key_free(&stack_key);
#endif
	dss_abt_init = false;
	ABT_finalize();
}

static void
dss_crt_event_cb(d_rank_t rank, uint64_t incarnation, enum crt_event_source src,
		 enum crt_event_type type, void *arg)
{
	int			 rc = 0;
	struct engine_metrics	*metrics = &dss_engine_metrics;

	/* We only care about dead ranks for now */
	if (type != CRT_EVT_DEAD) {
		D_DEBUG(DB_MGMT, "ignore: src=%d type=%d\n", src, type);
		return;
	}

	d_tm_record_timestamp(metrics->last_event_time);

	if (src == CRT_EVS_SWIM) {
		d_tm_inc_counter(metrics->dead_rank_events, 1);
		rc = ds_notify_swim_rank_dead(rank, incarnation);
		if (rc)
			D_ERROR("failed to handle %u/%u event: "DF_RC"\n",
				src, type, DP_RC(rc));
	} else if (src == CRT_EVS_GRPMOD) {
		d_rank_t self_rank = dss_self_rank();

		if (rank == dss_self_rank()) {
			D_WARN("raising SIGKILL: exclusion of this engine (rank %u) detected\n",
			       self_rank);
			/*
			 * For now, we just raise a SIGKILL to ourselves; we could
			 * inform daos_server, who would initiate a termination and
			 * decide whether to restart us.
			 */
			rc = kill(getpid(), SIGKILL);
			if (rc != 0)
				D_ERROR("failed to raise SIGKILL: %d\n", errno);
			return;
		}

	}
}

static void
dss_crt_hlc_error_cb(void *arg)
{
	/* Rank will be populated automatically */
	ds_notify_ras_eventf(RAS_ENGINE_CLOCK_DRIFT, RAS_TYPE_INFO,
			     RAS_SEV_ERROR, NULL /* hwid */,
			     NULL /* rank */, NULL /* inc */,
			     NULL /* jobid */, NULL /* pool */,
			     NULL /* cont */, NULL /* objid */,
			     NULL /* ctlop */, NULL /* data */,
			     "clock drift detected");
}

static void
server_id_cb(uint32_t *tid, uint64_t *uid)
{

	if (server_init_state != DSS_INIT_STATE_SET_UP)
		return;

	if (uid != NULL && dss_abt_init) {
		ABT_unit_type type = ABT_UNIT_TYPE_EXT;
		int rc;

		rc = ABT_self_get_type(&type);

		if (rc == 0 && (type == ABT_UNIT_TYPE_THREAD || type == ABT_UNIT_TYPE_TASK))
			ABT_self_get_thread_id(uid);
	}

	if (tid != NULL) {
		struct dss_thread_local_storage *dtc;
		struct dss_module_info *dmi;
		int index = daos_srv_modkey.dmk_index;

		/* Avoid assertion in dss_module_key_get() */
		dtc = dss_tls_get();
		if (dtc != NULL && index >= 0 && index < DAOS_MODULE_KEYS_NR &&
		    dss_module_keys[index] == &daos_srv_modkey) {
			dmi = dss_get_module_info();
			if (dmi != NULL)
				*tid = dmi->dmi_xs_id;
		}
	}
}

static uint64_t
metrics_region_size(int num_tgts)
{
	const uint64_t	est_std_metrics = 1024; /* high estimate to allow for pool links */
	const uint64_t	est_tgt_metrics = 128; /* high estimate */

	return (est_std_metrics + est_tgt_metrics * num_tgts) * D_TM_METRIC_SIZE;
}

// daos 的libbio.so 依赖的部分spdk 模块
// 1. spdk_bdev
// 2. spdk_bdev_nvme
// 3. spdk_nvme
// 4. spdk_vmd
// 5. spdk_event_bdev
/*
daos 等bdev 创建命令是daos_xxx_create，而nvme 类型创建命令是：bdev_nvme_attach_controller
p = subparsers.add_parser('bdev_nvme_attach_controller', aliases=['construct_nvme_bdev']
root@server02:/opt/daos/prereq/release/spdk/lib# ldd libspdk_bdev.so
        linux-vdso.so.1 (0x00007ffeb66ab000)
        libspdk_log.so.4.1 => /opt/daos/prereq/release/spdk/lib/libspdk_log.so.4.1 (0x00007fb6bcfb9000)
        libspdk_util.so.4.1 => /opt/daos/prereq/release/spdk/lib/libspdk_util.so.4.1 (0x00007fb6bcfa6000)
        libspdk_thread.so.6.1 => /opt/daos/prereq/release/spdk/lib/libspdk_thread.so.6.1 (0x00007fb6bcf97000)
        libspdk_json.so.3.3 => /opt/daos/prereq/release/spdk/lib/libspdk_json.so.3.3 (0x00007fb6bcf8b000)
        libspdk_jsonrpc.so.3.0 => /opt/daos/prereq/release/spdk/lib/libspdk_jsonrpc.so.3.0 (0x00007fb6bcf81000)
        libspdk_rpc.so.3.0 => /opt/daos/prereq/release/spdk/lib/libspdk_rpc.so.3.0 (0x00007fb6bcf78000)
        libspdk_notify.so.3.0 => /opt/daos/prereq/release/spdk/lib/libspdk_notify.so.3.0 (0x00007fb6bcf32000)
        libspdk_trace.so.5.1 => /opt/daos/prereq/release/spdk/lib/libspdk_trace.so.5.1 (0x00007fb6bcf29000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb6bcd22000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007fb6bcd19000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fb6bcbca000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fb6bcfe1000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fb6bcba3000)
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007fb6bcb99000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fb6bcb76000)

*/
static int
server_init(int argc, char *argv[])
{
	uint64_t		bound;
	unsigned int		ctx_nr;
	int			rc;
	struct engine_metrics	*metrics;

	/*
	 * Begin the HLC recovery as early as possible. Do not read the HLC
	 * before the hlc_recovery_end call below.
	 */
	// hlc 时钟begin
	bound = hlc_recovery_begin();

	gethostname(dss_hostname, DSS_HOSTNAME_MAX_LEN);

	daos_debug_set_id_cb(server_id_cb);
	rc = daos_debug_init_ex(DAOS_LOG_DEFAULT, DLOG_INFO);
	if (rc != 0)
		return rc;

	/** initialize server topology data - this is needed to set up the number of targets */
	// 初始化硬件topo 信息，即在服务器上架完成后，numa 架构的信息已经确定，即哪个numa 绑定了哪些pmem 设备，nvme 设备以及ib 网卡，需要与conf 保持一致
	// 可以使用lstopo，hwloc-ls 命令查看
	// 检查当前的硬件topo 信息以及daos_server 传递来的物理核心等参数，是否符合资源分配要求
	rc = dss_topo_init();
	if (rc != 0)
		D_GOTO(exit_debug_init, rc);

	// 普罗米修斯相关初始化
	rc = d_tm_init(dss_instance_idx, metrics_region_size(dss_tgt_nr), D_TM_SERVER_PROCESS);
	if (rc != 0)
		goto exit_debug_init;

	// metrics 初始化
	rc = dss_engine_metrics_init();
	if (rc != 0)
		D_WARN("Unable to initialize engine metrics, " DF_RC "\n",
		       DP_RC(rc));

	metrics = &dss_engine_metrics;
	/** Report timestamp when engine was started */
	// engine 启动时报告时间戳给metrics
	d_tm_record_timestamp(metrics->started_time);

	// 判断daos_server -d参数传递来的用于drpc 通信的sockst 路径是否存在
	rc = drpc_init();
	if (rc != 0) {
		D_ERROR("Failed to initialize dRPC: "DF_RC"\n", DP_RC(rc));
		goto exit_metrics_init;
	}

	// 注册一些要用到的dbtree 的类型，如kv 都是变长字节流的tree，int-边长字节流tree 等
	rc = register_dbtree_classes();
	if (rc != 0)
		D_GOTO(exit_drpc_fini, rc);

	// abt 库的初始化
	// 启动参数： /opt/daos/bin/daos_engine -t 20 -x 2 -g daos_server -d /var/run/daos_server -T 2 -n /mnt/daos/2/daos_nvme.conf -p 1 -I 1 -r 20480 -H 2 -s /mnt/daos/2
	rc = abt_init(argc, argv);
	if (rc != 0)
		goto exit_drpc_fini;

	/* initialize the modular interface */
	// daos server 模块初始化：其实就判断了 registry_table 是否为空，真正向 table 中添加数据是在 dss_module_init_all 中
	rc = dss_module_init();
	if (rc)
		goto exit_abt_init;
	D_INFO("Module interface successfully initialized\n");

	/* initialize the network layer */
	// 获取ctx 总数
	ctx_nr = dss_ctx_nr_get();
	// crt 的初始化，client 和server 都要调用
	rc = crt_init_opt(daos_sysname,
			  CRT_FLAG_BIT_SERVER,
			  daos_crt_init_opt_get(true, ctx_nr));
	if (rc)
		D_GOTO(exit_mod_init, rc);
	D_INFO("Network successfully initialized\n");

	// dss_mod_facs 在 dss_module_init_all 里才会加载
	if (dss_mod_facs & DSS_FAC_LOAD_CLI) {
		// daos 客户端库
		rc = daos_init();
		if (rc) {
			D_ERROR("daos_init (client) failed, rc: "DF_RC"\n",
				DP_RC(rc));
			D_GOTO(exit_crt, rc);
		}
		D_INFO("Client stack enabled\n");
	} else {
		rc = daos_hhash_init();
		if (rc) {
			D_ERROR("daos_hhash_init failed, rc: "DF_RC"\n",
				DP_RC(rc));
			D_GOTO(exit_crt, rc);
		}
		rc = pl_init();
		if (rc != 0) {
			daos_hhash_fini();
			goto exit_crt;
		}
		D_INFO("handle hash table and placement initialized\n");
	}
	/* server-side uses D_HTYPE_PTR handle */
	d_hhash_set_ptrtype(daos_ht.dht_hhash);

	// 构造iv 类型 topo 树。k 为int，v 为可变长字节流
	// todo: iv 服务是啥，根crt 相关
	ds_iv_init();

	/* load modules. Split load and init so first call to dlopen()
	 * is from the engine to avoid DAOS-4557
	 */
	// 所有模块加载
	rc = modules_load();
	if (rc)
		/* Some modules may have been loaded successfully. */
		D_GOTO(exit_mod_loaded, rc);
	// 日志：Module vos,rdb,rsvc,security,mgmt,dtx,pool,cont,obj,rebuild successfully loaded
	// 全局变量，保存所有模块名字
	D_INFO("Module %s successfully loaded\n", modules);

	/*
	 * End the HLC recovery so that module init callbacks (e.g.,
	 * vos_mod_init) invoked by the dss_module_init_all call below can read
	 * the HLC.
	 */
	// hlc 时钟end
	hlc_recovery_end(bound);
	dss_set_start_epoch();

	/* init nvme */
	// bio nvme 初始化
	// dss_nvme_conf 是daos_server 启动engine 传递进来的nvme list
	// nvme list, 该engien 使用的numa idx，spdk 申请内存大小，大页个数，target 个数
	// dss_nvme_bypass_health_check = false
	/*
	/opt/daos/bin/daos_engine -t 20 -x 2 -g daos_server -d /var/run/daos_server -T 2 -n /mnt/daos/2/daos_nvme.conf -p 1 -I 1 -r 20480 -H 2 -s /mnt/daos/2
	/opt/daos/bin/daos_engine -t 20 -x 2 -g daos_server -d /var/run/daos_server -T 2 -n /mnt/daos/1/daos_nvme.conf -p 0 -I 0 -r 20480 -H 2 -s /mnt/daos/1
	*/
	rc = bio_nvme_init(dss_nvme_conf, dss_numa_node, dss_nvme_mem_size,
			   dss_nvme_hugepage_size, dss_tgt_nr, dss_nvme_bypass_health_check);
	if (rc)
		D_GOTO(exit_mod_loaded, rc);

	/* init modules */
	rc = dss_module_init_all(&dss_mod_facs);
	if (rc)
		/* Some modules may have been loaded successfully. */
		D_GOTO(exit_nvme_init, rc);
	D_INFO("Module %s successfully initialized\n", modules);

	/* initialize service */
	// daos server 服务模块初始化
	rc = dss_srv_init();
	if (rc)
		D_GOTO(exit_mod_loaded, rc);
	D_INFO("Service initialized\n");

	rc = server_init_state_init();
	if (rc != 0) {
		D_ERROR("failed to init server init state: "DF_RC"\n",
			DP_RC(rc));
		goto exit_srv_init;
	}

	// engine 以上内容都执行完后，给server 上报ready 信息，告诉server自己已经就绪了
	// daos_server 在收到就绪notify 消息后会继续下发 MethodSetUp-ds_mgmt_drpc_set_up 类型drpc 请求给engine
	rc = drpc_notify_ready();
	if (rc != 0) {
		D_ERROR("Failed to notify daos_server: "DF_RC"\n", DP_RC(rc));
		goto exit_init_state;
	}

	server_init_state_wait(DSS_INIT_STATE_SET_UP);

	// crt 注册
	rc = crt_register_event_cb(s, NULL);
	if (rc)
		D_GOTO(exit_init_state, rc);

	rc = crt_register_hlc_error_cb(dss_crt_hlc_error_cb, NULL);
	if (rc)
		D_GOTO(exit_init_state, rc);

	dss_xstreams_open_barrier();
	D_INFO("Service fully up\n");

	/** Report timestamp when engine was open for business */
	d_tm_record_timestamp(metrics->ready_time);

	/** Report rank */
	// 上报rank id
	d_tm_set_gauge(metrics->rank_id, dss_self_rank());

	D_PRINT("DAOS I/O Engine (v%s) process %u started on rank %u "
		"with %u target, %d helper XS, firstcore %d, host %s.\n",
		DAOS_VERSION, getpid(), dss_self_rank(), dss_tgt_nr,
		dss_tgt_offload_xs_nr, dss_core_offset, dss_hostname);

	if (numa_obj)
		D_PRINT("Using NUMA node: %d", dss_numa_node);

	return 0;

exit_init_state:
	server_init_state_fini();
exit_srv_init:
	dss_srv_fini(true);
exit_nvme_init:
	bio_nvme_fini();
exit_mod_loaded:
	ds_iv_fini();
	dss_module_unload_all();
	if (dss_mod_facs & DSS_FAC_LOAD_CLI) {
		daos_fini();
	} else {
		pl_fini();
		daos_hhash_fini();
	}
exit_crt:
	crt_finalize();
exit_mod_init:
	dss_module_fini(true);
exit_abt_init:
	abt_fini();
exit_drpc_fini:
	drpc_fini();
exit_metrics_init:
	dss_engine_metrics_fini();
	d_tm_fini();
exit_debug_init:
	daos_debug_fini();
	return rc;
}

static void
server_fini(bool force)
{
	D_INFO("Service is shutting down\n");
	/*
	 * The first thing to do is to inform every xstream that the engine is
	 * shutting down, so that we can avoid allocating new resources or
	 * taking new references on existing ones if necessary. Note that
	 * xstreams won't start shutting down until we call dss_srv_fini below.
	 */
	dss_srv_set_shutting_down();
	crt_unregister_event_cb(dss_crt_event_cb, NULL);
	D_INFO("unregister event callbacks done\n");
	/*
	 * Cleaning up modules needs to create ULTs on other xstreams; must be
	 * called before shutting down the xstreams.
	 */
	dss_module_cleanup_all();
	D_INFO("dss_module_cleanup_all() done\n");
	server_init_state_fini();
	D_INFO("server_init_state_fini() done\n");
	/*
	 * All other xstreams start shutting down here. ULT/tasklet creations
	 * on them are no longer possible.
	 */
	dss_srv_fini(force);
	D_INFO("dss_srv_fini() done\n");
	bio_nvme_fini();
	D_INFO("bio_nvme_fini() done\n");
	ds_iv_fini();
	D_INFO("ds_iv_fini() done\n");
	dss_module_unload_all();
	D_INFO("dss_module_unload_all() done\n");
	/*
	 * Client stuff finalization needs be done after all ULTs drained
	 * in dss_srv_fini().
	 */
	if (dss_mod_facs & DSS_FAC_LOAD_CLI) {
		daos_fini();
	} else {
		pl_fini();
		daos_hhash_fini();
	}
	D_INFO("daos_fini() or pl_fini() done\n");
	crt_finalize();
	D_INFO("crt_finalize() done\n");
	dss_module_fini(force);
	D_INFO("dss_module_fini() done\n");
	abt_fini();
	D_INFO("abt_fini() done\n");
	drpc_fini();
	D_INFO("drpc_fini() done\n");
	dss_engine_metrics_fini();
	D_INFO("dss_engine_metrics_fini() done\n");
	d_tm_fini();
	D_INFO("d_tm_fini() done\n");
	daos_debug_fini();
	D_INFO("daos_debug_fini() done\n");
}

static void
usage(char *prog, FILE *out)
{
	fprintf(out, "\
Usage:\n\
  %s -h\n\
  %s [-m modules] [-c ncores] [-g group] [-s path]\n\
Options:\n\
  --modules=modules, -m modules\n\
      List of server modules to load (default \"%s\")\n\
  --cores=ncores, -c ncores\n\
      Number of targets to use (deprecated, please use -t instead)\n\
  --targets=ntgts, -t ntargets\n\
      Number of targets to use (use all cores by default)\n\
  --xshelpernr=nhelpers, -x helpers\n\
      Number of helper XS -per vos target (default 1)\n\
  --firstcore=firstcore, -f firstcore\n\
      index of first core for service thread (default 0)\n\
  --group=group, -g group\n\
      Server group name (default \"%s\")\n\
  --storage=path, -s path\n\
      Storage path (default \"%s\")\n\
  --socket_dir=socket_dir, -d socket_dir\n\
      Directory where daos_server sockets are located (default \"%s\")\n\
  --nvme=config, -n config\n\
      NVMe config file (default \"%s\")\n\
  --instance_idx=idx, -I idx\n\
      Identifier for this server instance (default %u)\n\
  --pinned_numa_node=numanode, -p numanode\n\
      Bind to cores within the specified NUMA node\n\
  --bypass_health_chk, -b\n\
      Boolean set to inhibit collection of NVME health data\n\
  --mem_size=mem_size, -r mem_size\n\
      Allocates mem_size MB for SPDK when using primary process mode\n\
  --hugepage_size=hugepage_size, -H hugepage_size\n\
      Passes the configured hugepage size(2MB or 1GB)\n\
  --storage_tiers=ntiers, -T ntiers\n\
      Number of storage tiers\n\
  --help, -h\n\
      Print this description\n",
		prog, prog, modules, daos_sysname, dss_storage_path,
		dss_socket_dir, dss_nvme_conf, dss_instance_idx);
}

static int arg_strtoul(const char *str, unsigned int *value, const char *opt)
{
	char *ptr_parse_end = NULL;

	*value = strtoul(str, &ptr_parse_end, 0);
	if (ptr_parse_end && *ptr_parse_end != '\0') {
		printf("invalid numeric value: %s (set by %s)\n", str, opt);
		return -DER_INVAL;
	}

	return 0;
}

static int
parse(int argc, char **argv)
{
	// /opt/daos/bin/daos_engine -t 20 -x 2 -g daos_server -d /var/run/daos_server -T 2 -n /mnt/daos/2/daos_nvme.conf -p 1 -I 1 -r 20480 -H 2 -s /mnt/daos/2
	// 每个engine 启动接受的参数，控制台看到的启动参数如上面展示：
	// 绑定的核心
	// drpc 对应的 sockst
	// 第一个core
	// 所属group
	// 所属模块
	// nvme 列表文件：会在pmem 对应的目录下生成conf 文件
	// numa 索引
	// pmem size
	// 大页
	// tgt 个数，也是线程数
	// storage 保存元数据的pmem 设备挂载地址，/mnt/daos/1
	// helper 个数
	// 当前engine 实例索引
	struct	option opts[] = {
		{ "cores",		required_argument,	NULL,	'c' },
		{ "socket_dir",		required_argument,	NULL,	'd' },
		{ "firstcore",		required_argument,	NULL,	'f' },
		{ "group",		required_argument,	NULL,	'g' },
		{ "help",		no_argument,		NULL,	'h' },
		{ "modules",		required_argument,	NULL,	'm' },
		{ "nvme",		required_argument,	NULL,	'n' },
		{ "pinned_numa_node",	required_argument,	NULL,	'p' },
		{ "mem_size",		required_argument,	NULL,	'r' },
		{ "hugepage_size",	required_argument,	NULL,	'H' },
		{ "targets",		required_argument,	NULL,	't' },
		{ "storage",		required_argument,	NULL,	's' },
		{ "xshelpernr",		required_argument,	NULL,	'x' },
		{ "instance_idx",	required_argument,	NULL,	'I' },
		{ "bypass_health_chk",	no_argument,		NULL,	'b' },
		{ "storage_tiers",	required_argument,	NULL,	'T' },
		{ NULL,			0,			NULL,	0}
	};
	int	rc = 0;
	int	c;

	/* load all of modules by default */
	// 加载默认的模块们
	sprintf(modules, "%s", MODULE_LIST);
	// 传递上面参数，设置对应的值，都是些全局变量
	while ((c = getopt_long(argc, argv, "c:d:f:g:hi:m:n:p:r:H:t:s:x:I:bT:",
				opts, NULL)) != -1) {
		switch (c) {
		// 模块，没有这个参数
		case 'm':
			if (strlen(optarg) > MAX_MODULE_OPTIONS) {
				rc = -DER_INVAL;
				usage(argv[0], stderr);
				break;
			}
			// 加载的模块
			snprintf(modules, sizeof(modules), "%s", optarg);
			break;
		// 核心，传参没有这个
		case 'c':
			printf("\"-c\" option is deprecated, please use \"-t\" "
			       "instead.\n");
		// 线程数，这个是不是和target 个数是一样的？
		case 't':
			rc = arg_strtoul(optarg, &nr_threads, "\"-t\"");
			break;
		// helper 个数
		case 'x':
			rc = arg_strtoul(optarg, &dss_tgt_offload_xs_nr,
					 "\"-x\"");
			break;
		// 指定的第一个物理core
		case 'f':
			rc = arg_strtoul(optarg, &dss_core_offset, "\"-f\"");
			break;
		// 所属group，group 是 'daos_server'
		case 'g':
			if (strnlen(optarg, DAOS_SYS_NAME_MAX + 1) >
			    DAOS_SYS_NAME_MAX) {
				printf("DAOS system name must be at most "
				       "%d bytes\n", DAOS_SYS_NAME_MAX);
				rc = -DER_INVAL;
				break;
			}
			daos_sysname = optarg;
			break;
		// storage 路径，保存元数据的pmem 设备挂载路径
		case 's':
			dss_storage_path = optarg;
			break;
		// socket 目录，是 /var/run/daos_server
		case 'd':
			dss_socket_dir = optarg;
			break;
		// 是 /mnt/daos/1/daos_nvme.conf
		case 'n':
			dss_nvme_conf = optarg;
			break;
		// numa 索引，使用lstopo 可以看到numa 绑定的ib网卡，pmem 设备和nvme 设备信息
		// 服务器上架完成后，numa 和其他设备的绑定就已经确定了，后续的daos_server.yml 中需要按照numa 绑定来配置
		case 'p':
			dss_numa_node = atoi(optarg);
			break;
		// spdk 申请的内存大小 = 20480
		case 'r':
			rc = arg_strtoul(optarg, &dss_nvme_mem_size, "\"-r\"");
			break;
		// 是 2
		case 'H':
			rc = arg_strtoul(optarg, &dss_nvme_hugepage_size,
					 "\"-H\"");
			break;
		case 'h':
			usage(argv[0], stdout);
			break;
		case 'I':
			rc = arg_strtoul(optarg, &dss_instance_idx, "\"-I\"");
			break;
		case 'b':
			dss_nvme_bypass_health_check = true;
			break;
		// 是 storage tier = 2
		case 'T':
			rc = arg_strtoul(optarg, &dss_storage_tiers, "\"-T\"");
			if (dss_storage_tiers < 1 || dss_storage_tiers > 4) {
				printf("Requires 1 to 4 tiers\n");
				rc = -DER_INVAL;
			}
			break;
		default:
			usage(argv[0], stderr);
			rc = -DER_INVAL;
		}
		if (rc < 0)
			return rc;
	}

	return 0;
}

// engine 的main
// 从 exec.go 的 func (r *Runner) run 中进入
int
main(int argc, char **argv)
{
	sigset_t	set;
	int		sig;
	int		rc;

	/** parse command line arguments */
	// 启动中间状态会执行setup.sh 脚本reset 操作：
	/*
	root@server01:~# ps -ef | grep daos
	root     2984613       1  3 15:14 ?        00:00:00 /opt/daos/bin/daos_server start -o /opt/daos/etc/daos_server.yml
	root     2984648 2984613  0 15:14 ?        00:00:00 /opt/daos/bin/daos_server_helper
	root     2984656 2984648  0 15:14 ?        00:00:00 bash /opt/daos/share/daos/control/setup_spdk.sh reset
	*/
	// 启动参数解析，保存到engine 的全局变量中
	// 举例： /opt/daos/bin/daos_engine -t 20 -x 2 -g daos_server -d /var/run/daos_server -T 2 -n /mnt/daos/2/daos_nvme.conf -p 1 -I 1 -r 20480 -H 2 -s /mnt/daos/2
	rc = parse(argc, argv);
	if (rc)
		exit(EXIT_FAILURE);

	/** block all possible signals but faults */
	sigfillset(&set);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGBUS);
	sigdelset(&set, SIGSEGV);
	/** also allow abort()/assert() to trigger */
	sigdelset(&set, SIGABRT);

	rc = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (rc) {
		perror("failed to mask signals");
		exit(EXIT_FAILURE);
	}

	/* register our own handler for faults and abort()/assert() */
	// 自定义的信号处理函数
	d_signal_stack_enable(true);
	d_signal_register();

	/** server initialization */
	// engine 根据daos_server 传递来的参数初始化。后面这两个参数将会被直接透传给abt 库做初始化
	rc = server_init(argc, argv);
	if (rc)
		exit(EXIT_FAILURE);

	/** wait for shutdown signal */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	// loop 直到收到shutdown 信号
	while (1) {
		rc = sigwait(&set, &sig);
		if (rc) {
			D_ERROR("failed to wait for signals: %d\n", rc);
			break;
		}

		/* open specific file to dump ABT infos and ULTs stacks */
		// dump 堆栈信息
		if (sig == SIGUSR1 || sig == SIGUSR2) {
			struct timeval tv;
			struct tm *tm = NULL;

			rc = gettimeofday(&tv, NULL);
			if (rc == 0)
				tm = localtime(&tv.tv_sec);
			else
				D_ERROR("failure to gettimeofday(): %s (%d)\n",
					strerror(errno), errno);

			 if (abt_infos == NULL) {
				// dump 文件格式
				/* filename format is
				 * "/tmp/daos_dump_<PID>_YYYYMMDD_hh_mm.txt"
				 */
				char name[50];

				if (rc != -1 && tm != NULL)
					snprintf(name, 50,
						 "/tmp/daos_dump_%d_%04d%02d%02d_%02d_%02d.txt",
						 getpid(), tm->tm_year + 1900,
						 tm->tm_mon + 1, tm->tm_mday,
						 tm->tm_hour, tm->tm_min);
				else
					snprintf(name, 50,
						 "/tmp/daos_dump_%d.txt",
						 getpid());

				// 以append 方式打开dump 文件
				abt_infos = fopen(name, "a");
				if (abt_infos == NULL) {
					D_ERROR("failed to open file to dump ABT infos and ULTs stacks: %s (%d)\n",
						strerror(errno), errno);
					abt_infos = stderr;
				}
			}

			/* print header msg with date */
			// 写入头信息
			fprintf(abt_infos,
				"=== Dump of ABT infos and ULTs stacks in %s mode (",
				sig == SIGUSR1 ? "unattended" : "attended");
			if (rc == -1 || tm == NULL)
				fprintf(abt_infos, "time unavailable");
			else
				// 写入当时时间
				fprintf(abt_infos,
					"%04d/%02d/%02d-%02d:%02d:%02d.%02ld",
					tm->tm_year + 1900, tm->tm_mon + 1,
					tm->tm_mday, tm->tm_hour, tm->tm_min,
					tm->tm_sec,
					(long int)tv.tv_usec / 10000);
			fprintf(abt_infos, ")\n");
		}

		// 导出dump 信息：  killall -SIGUSR1 /opt/daos/bin/daos_engine 会触发dump 生成
		/* use this engine main thread's context to dump Argobots
		 * internal infos and ULTs stacks without internal synchro
		 */
		// SIGUSR1 和 SIGUSR2 都是用户自定义信号，默认处理方式都是结束进程
		// 1. 这里自定义为：如果收到信号1，使用主线程做dump，会锁 xd_mutex
		// 2. 如果收到信号2 的话直接使用abt 的函数做dump，使用abt 内部的同步机制
		if (sig == SIGUSR1) {
			D_INFO("got SIGUSR1, dumping Argobots infos and ULTs stacks\n");
			dss_dump_ABT_state(abt_infos);
			continue;
		}

		/* trigger dump of all Argobots ULTs stacks with internal
		 * synchro (timeout of 10s)
		 */
		if (sig == SIGUSR2) {
			D_INFO("got SIGUSR2, attempting to trigger dump of all Argobots ULTs stacks\n");
			ABT_info_trigger_print_all_thread_stacks(abt_infos,
								 10.0, NULL,
								 NULL);
			continue;
		}

		/* SIGINT/SIGTERM cause server shutdown */
		// 别的信号会直接shutdown
		break;
	}

	/** shutdown */
	server_fini(true);

	exit(EXIT_SUCCESS);
}
