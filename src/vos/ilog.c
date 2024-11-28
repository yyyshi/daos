/**
 * (C) Copyright 2019-2023 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
/**
 * VOS Object/Key incarnation log
 * vos/ilog.c
 *
 * Author: Jeff Olivier <jeffrey.v.olivier@intel.com>
 */
#define D_LOGFAC DD_FAC(vos)
#include <daos/common.h>
#include <daos_srv/vos.h>
#include <daos/btree.h>
#include "vos_internal.h"
#include "vos_layout.h"
#include "vos_ts.h"
#include "ilog.h"

#define ILOG_TREE_ORDER 11

enum {
	ILOG_ITER_NONE,
	ILOG_ITER_INIT,
	ILOG_ITER_READY,
	ILOG_ITER_FINI,
};

/** The ilog is split into two parts.   If there is one entry, the ilog
 *  is embedded into the root df struct.   If not, a b+tree is used.
 *  The tree is used more like a set where only the key is used.
 */
// ilog 被拆分成两部分。如果只有一个entry，ilog 被放到root df 中。否则的话使用b+ 树。
// 这个tree 看起来更像是一个set 结构，因为只有key 被使用
struct ilog_tree {
	umem_off_t	it_root;
	uint64_t	it_embedded;
};

struct ilog_array {
	/** Current length of array */
	uint32_t	ia_len;
	/** Allocated length of array */
	uint32_t	ia_max_len;
	/** Pad to 16 bytes */
	uint64_t	ia_pad;
	/** Entries in array */
	struct ilog_id	ia_id[0];
};

struct ilog_array_cache {
	/** Pointer to entries */
	struct ilog_id		*ac_entries;
	/** Pointer to array, if applicable */
	struct ilog_array	*ac_array;
	/** Number of entries */
	uint32_t		 ac_nr;
};

// ilog 树根
struct ilog_root {
	union {
		// 1. 这个是单条entry 场景下，保存的entry 记录
		struct ilog_id		lr_id;
		// 2. 这个就是多条entry 情况下，保存多条 entry 的b+ 树结构
		struct ilog_tree	lr_tree;
	};
	uint32_t			lr_ts_idx;
	uint32_t			lr_magic;
};

struct ilog_context {
	// ilog 的root
	/** Root pointer */
	struct ilog_root		*ic_root;
	/** Cache the callbacks */
	struct ilog_desc_cbs		 ic_cbs;
	/** umem offset of root pointer */
	umem_off_t			 ic_root_off;
	/** umem instance */
	struct umem_instance            *ic_umm;
	/** ref count for iterator */
	uint32_t			 ic_ref;
	/** In pmdk transaction marker */
	bool				 ic_in_txn;
	/** version needs incrementing */
	bool				 ic_ver_inc;
};

D_CASSERT(sizeof(struct ilog_id) == sizeof(struct ilog_tree));
D_CASSERT(sizeof(struct ilog_root) == sizeof(struct ilog_df));

static inline struct vos_container *
ilog_ctx2cont(struct ilog_context *lctx)
{
	daos_handle_t	coh;

	if (lctx->ic_cbs.dc_is_same_tx_args == NULL)
		return NULL;

	coh.cookie = (unsigned long)lctx->ic_cbs.dc_is_same_tx_args;

	return vos_hdl2cont(coh);
}

/**
 * Customized functions for btree.
 */
static inline int
ilog_is_same_tx(struct ilog_context *lctx, const struct ilog_id *id, bool *same)
{
	struct ilog_desc_cbs	*cbs = &lctx->ic_cbs;

	*same = true;

	if (!cbs->dc_is_same_tx_cb)
		return 0;

	return cbs->dc_is_same_tx_cb(lctx->ic_umm, id->id_tx_id, id->id_epoch, same,
				     cbs->dc_is_same_tx_args);
}

static int16_t
ilog_status_get(struct ilog_context *lctx, const struct ilog_id *id, uint32_t intent, bool retry)
{
	struct ilog_desc_cbs	*cbs = &lctx->ic_cbs;
	int			 rc;

	if (!cbs->dc_log_status_cb)
		return ILOG_COMMITTED;

	rc = cbs->dc_log_status_cb(lctx->ic_umm, id->id_tx_id, id->id_epoch, intent, retry,
				   cbs->dc_log_status_args);

	if ((intent == DAOS_INTENT_UPDATE || intent == DAOS_INTENT_PUNCH)
	    && rc == -DER_INPROGRESS)
		return ILOG_UNCOMMITTED;

	return rc;
}

static inline int
ilog_log_add(struct ilog_context *lctx, struct ilog_id *id)
{
	struct ilog_desc_cbs	*cbs = &lctx->ic_cbs;
	int			 rc;

	if (!cbs->dc_log_add_cb)
		return 0;

	D_ASSERT(id->id_epoch != 0);

	// == vos_ilog_add，内部调用 vos_dtx_register_record
	// 调用cb 函数，添加ilog id
	// 传入umm 地址，umm off，tx id，epoch，args
	rc = cbs->dc_log_add_cb(lctx->ic_umm, lctx->ic_root_off, &id->id_tx_id, id->id_epoch,
				cbs->dc_log_add_args);
	if (rc != 0) {
		D_ERROR("Failed to register incarnation log entry: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	D_DEBUG(DB_TRACE, "Registered ilog="DF_X64" epoch="DF_X64" lid=%d\n",
		lctx->ic_root_off, id->id_epoch, id->id_tx_id);

	return 0;
}

static inline int
ilog_log_del(struct ilog_context *lctx, const struct ilog_id *id,
	     bool deregister)
{
	struct ilog_desc_cbs	*cbs = &lctx->ic_cbs;
	int			 rc;

	if (!cbs->dc_log_del_cb)
		return 0;

	rc = cbs->dc_log_del_cb(lctx->ic_umm, lctx->ic_root_off, id->id_tx_id, id->id_epoch,
				deregister, cbs->dc_log_del_args);
	if (rc != 0) {
		D_ERROR("Failed to deregister incarnation log entry: "DF_RC"\n",
			DP_RC(rc));
		return rc;
	}

	D_DEBUG(DB_TRACE, "%s ilog="DF_X64" epoch="DF_X64
		" lid=%d\n", deregister ? "Deregistered" : "Removed",
		lctx->ic_root_off, id->id_epoch, id->id_tx_id);

	return 0;
}

int
ilog_init(void)
{
	return 0;
}

/* 4 bit magic number + version */
#define ILOG_MAGIC		0x00000006
#define ILOG_MAGIC_BITS		4
#define ILOG_MAGIC_MASK		((1 << ILOG_MAGIC_BITS) - 1)
#define ILOG_VERSION_INC	(1 << ILOG_MAGIC_BITS)
#define ILOG_VERSION_MASK	~(ILOG_VERSION_INC - 1)
#define ILOG_MAGIC_VALID(magic)	(((magic) & ILOG_MAGIC_MASK) == ILOG_MAGIC)

static inline uint32_t
ilog_mag2ver(uint32_t magic) {
	if (!ILOG_MAGIC_VALID(magic))
		return 0;

	return (magic & ILOG_VERSION_MASK) >> ILOG_MAGIC_BITS;
}

/** Increment the version of the log.   The object tree in particular can
 *  benefit from cached state of the tree.  In order to detect when to
 *  update the case, we keep a version.
 */
static inline uint32_t
ilog_ver_inc(struct ilog_context *lctx)
{
	uint32_t        magic = lctx->ic_root->lr_magic;

	D_ASSERT(ILOG_MAGIC_VALID(magic));

	if ((magic & ILOG_VERSION_MASK) == ILOG_VERSION_MASK)
		magic = (magic & ~ILOG_VERSION_MASK) + ILOG_VERSION_INC;
	else
		magic += ILOG_VERSION_INC;

	/* This is only called when we will persist the new version so no need
	* to update the version when finishing the transaction.
	*/
	lctx->ic_ver_inc = false;

	return magic;
}

/** Called when we know a txn is needed.  Subsequent calls are a noop. */
static inline int
ilog_tx_begin(struct ilog_context *lctx)
{
	int	rc = 0;

	if (lctx->ic_in_txn)
		return 0;

	rc = umem_tx_begin(lctx->ic_umm, NULL);
	if (rc != 0)
		return rc;

	lctx->ic_in_txn = true;
	lctx->ic_ver_inc = true;
	return 0;
}

/** Only invokes transaction end if we've started a txn */
static inline int
ilog_tx_end(struct ilog_context *lctx, int rc)
{
	if (!lctx->ic_in_txn)
		return rc;

	if (rc != 0)
		goto done;

	if (lctx->ic_ver_inc) {
		rc = umem_tx_add_ptr(lctx->ic_umm, &lctx->ic_root->lr_magic,
				     sizeof(lctx->ic_root->lr_magic));
		if (rc != 0) {
			D_ERROR("Failed to add to undo log: "DF_RC"\n",
				DP_RC(rc));
			goto done;
		}

		lctx->ic_root->lr_magic = ilog_ver_inc(lctx);
	}

done:
	lctx->ic_in_txn = false;
	return umem_tx_end(lctx->ic_umm, rc);
}

static inline bool
ilog_empty(struct ilog_root *root)
{
	return !root->lr_tree.it_embedded &&
		root->lr_tree.it_root == UMOFF_NULL;
}

static void
ilog_addref(struct ilog_context *lctx)
{
	lctx->ic_ref++;
}

static void
ilog_decref(struct ilog_context *lctx)
{
	lctx->ic_ref--;
	if (lctx->ic_ref == 0)
		D_FREE(lctx);
}

static int
ilog_ctx_create(struct umem_instance *umm, struct ilog_root *root,
		const struct ilog_desc_cbs *cbs, struct ilog_context **lctxp)
{
	D_ALLOC_PTR(*lctxp);
	if (*lctxp == NULL) {
		return -DER_NOMEM;
	}

	(*lctxp)->ic_root = root;
	(*lctxp)->ic_root_off = umem_ptr2off(umm, root);
	(*lctxp)->ic_umm      = umm;
	(*lctxp)->ic_cbs = *cbs;
	ilog_addref(*lctxp);
	return 0;
}

static daos_handle_t
ilog_lctx2hdl(struct ilog_context *lctx)
{
	daos_handle_t	hdl;

	// todo: ilog 的cookie
	hdl.cookie = (uint64_t)lctx;

	return hdl;
}

static struct ilog_context *
ilog_hdl2lctx(daos_handle_t hdl)
{
	struct ilog_context	*lctx;

	if (daos_handle_is_inval(hdl))
		return NULL;

	// todo: 从cookie 中获得ctx 信息是什么操作
	lctx = (struct ilog_context *)hdl.cookie;

	if (!ILOG_MAGIC_VALID(lctx->ic_root->lr_magic))
		return NULL;

	return lctx;
}

static int
ilog_ptr_set_full(struct ilog_context *lctx, void *dest, const void *src,
		  size_t len)
{
	int	rc = 0;

	// ilog 事务相关
	rc = ilog_tx_begin(lctx);
	if (rc != 0) {
		D_ERROR("Failed to start PMDK transaction: " DF_RC "\n", DP_RC(rc));
		goto done;
	}

	rc = umem_tx_add_ptr(lctx->ic_umm, dest, len);
	if (rc != 0) {
		D_ERROR("Failed to add to undo log\n");
		goto done;
	}

	memcpy(dest, src, len);
done:
	return rc;
}

#define ilog_ptr_set(lctx, dest, src)	\
	ilog_ptr_set_full(lctx, dest, src, sizeof(*(src)))

int
ilog_create(struct umem_instance *umm, struct ilog_df *root)
{
	struct ilog_context lctx = {
	    .ic_root     = (struct ilog_root *)root,
	    .ic_root_off = umem_ptr2off(umm, root),
	    .ic_umm      = umm,
	    .ic_ref      = 0,
	    .ic_in_txn   = 0,
	};
	struct ilog_root	tmp = {0};
	int			rc = 0;

	tmp.lr_magic = ILOG_MAGIC + ILOG_VERSION_INC;

	rc = ilog_ptr_set(&lctx, root, &tmp);
	lctx.ic_ver_inc = false;

	rc = ilog_tx_end(&lctx, rc);
	return rc;
}

#define ILOG_ASSERT_VALID(root_df)					\
	do {								\
		struct ilog_root	*_root;				\
									\
		_root = (struct ilog_root *)(root_df);			\
		D_ASSERTF((_root != NULL) &&				\
			  ILOG_MAGIC_VALID(_root->lr_magic),		\
			  "Invalid ilog root detected %p magic=%#x\n",	\
			  _root, _root == NULL ? 0 : _root->lr_magic);	\
	} while (0)

// 实际上是创建ctx
int
ilog_open(struct umem_instance *umm, struct ilog_df *root,
	  const struct ilog_desc_cbs *cbs, daos_handle_t *loh)
{
	struct ilog_context	*lctx;
	int			 rc;

	ILOG_ASSERT_VALID(root);

	rc = ilog_ctx_create(umm, (struct ilog_root *)root, cbs, &lctx);
	if (rc != 0)
		return rc;

	// todo: ilog cookie 相关
	*loh = ilog_lctx2hdl(lctx);

	return 0;
}

int
ilog_close(daos_handle_t loh)
{
	struct ilog_context *lctx = ilog_hdl2lctx(loh);

	D_ASSERTF(lctx != NULL,
		  "Trying to close invalid incarnation log handle\n");
	if (lctx == NULL)
		return -DER_INVAL;

	ilog_decref(lctx);

	return 0;
}

static void
ilog_log2cache(struct ilog_context *lctx, struct ilog_array_cache *cache)
{
	struct ilog_array	*array;

	// 1. ilog 为空
	if (ilog_empty(lctx->ic_root)) {
		cache->ac_entries = NULL;
		cache->ac_array = NULL;
		cache->ac_nr = 0;
	} else if (!lctx->ic_root->lr_tree.it_embedded) {
		// 2. ilog entry 为多条，entry 都保存在b+树中
		// todo: 这里的entry 数据量会不会超级多
		array             = umem_off2ptr(lctx->ic_umm, lctx->ic_root->lr_tree.it_root);
		// 上面从b+ 树中获取到ilog entrys，这里将获取到的entry 填充到 cache 中
		cache->ac_array = array;
		cache->ac_entries = &array->ia_id[0];
		cache->ac_nr = array->ia_len;
	} else {
		// 3. ilog entry 为一条，不保存在b+ 树中
		cache->ac_entries = &lctx->ic_root->lr_id;
		cache->ac_nr = 1;
		cache->ac_array = NULL;
	}
}


int
ilog_destroy(struct umem_instance *umm,
	     struct ilog_desc_cbs *cbs, struct ilog_df *root)
{
	struct ilog_context lctx = {
	    .ic_root     = (struct ilog_root *)root,
	    .ic_root_off = umem_ptr2off(umm, root),
	    .ic_umm      = umm,
	    .ic_ref      = 1,
	    .ic_cbs      = *cbs,
	    .ic_in_txn   = 0,
	};
	uint32_t		 tmp = 0;
	int			 i;
	int			 rc = 0;
	struct ilog_array_cache	 cache = {0};

	ILOG_ASSERT_VALID(root);

	rc = ilog_tx_begin(&lctx);
	if (rc != 0) {
		D_ERROR("Failed to start PMDK transaction: " DF_RC "\n", DP_RC(rc));
		return rc;
	}

	/* No need to update the version on destroy */
	lctx.ic_ver_inc = false;

	rc = ilog_ptr_set(&lctx, &lctx.ic_root->lr_magic, &tmp);
	if (rc != 0)
		goto fail;

	ilog_log2cache(&lctx, &cache);

	for (i = 0; i < cache.ac_nr; i++) {
		rc = ilog_log_del(&lctx, &cache.ac_entries[i], true);
		if (rc != 0)
			goto fail;
	}

	if (cache.ac_nr > 1)
		rc = umem_free(umm, lctx.ic_root->lr_tree.it_root);

fail:
	rc = ilog_tx_end(&lctx, rc);

	return rc;
}

#define ILOG_ARRAY_INIT_NR	3
#define ILOG_ARRAY_APPEND_NR	4
#define ILOG_ARRAY_CHUNK_SIZE	64
D_CASSERT(sizeof(struct ilog_array) + sizeof(struct ilog_id) * ILOG_ARRAY_INIT_NR ==
	  ILOG_ARRAY_CHUNK_SIZE);
D_CASSERT(sizeof(struct ilog_id) * ILOG_ARRAY_APPEND_NR == ILOG_ARRAY_CHUNK_SIZE);

static int
ilog_root_migrate(struct ilog_context *lctx, const struct ilog_id *id_in)
{
	struct ilog_root	 tmp = {0};
	umem_off_t		 tree_root;
	struct ilog_root	*root;
	struct ilog_array	*array;
	int			 rc = 0;
	int			 idx;

	// 再拿到tree root
	root = lctx->ic_root;

	rc = ilog_tx_begin(lctx);
	if (rc != 0) {
		D_ERROR("Failed to start PMDK transaction: " DF_RC "\n", DP_RC(rc));
		return rc;
	}

	// 获取pmem 地址
	tree_root = umem_zalloc(lctx->ic_umm, ILOG_ARRAY_CHUNK_SIZE);

	if (tree_root == UMOFF_NULL)
		return lctx->ic_umm->umm_nospc_rc;

	// 获取root 对应的保存entry 的array
	array = umem_off2ptr(lctx->ic_umm, tree_root);

	lctx->ic_ver_inc = true;

	// 谁大谁在array 前头
	if (root->lr_id.id_epoch > id_in->id_epoch)
		idx = 1;
	else
		idx = 0;

	// 先保存小的到array
	array->ia_id[idx].id_value = root->lr_id.id_value;
	array->ia_id[idx].id_epoch = root->lr_id.id_epoch;

	// 再保存大得到到array
	idx = 1 - idx;
	array->ia_id[idx].id_value = id_in->id_value;
	array->ia_id[idx].id_epoch = id_in->id_epoch;
	// 更新size 为 2，即此时保存了2条记录
	array->ia_len = 2;
	array->ia_max_len = ILOG_ARRAY_INIT_NR;

	// 22-2. append 新的记录（注册 record）
	rc = ilog_log_add(lctx, &array->ia_id[idx]);
	if (rc != 0)
		return rc;

	// 更新tree 信息
	tmp.lr_tree.it_root = tree_root;
	// 此时entry length 为2，设置flag 为 false
	tmp.lr_tree.it_embedded = 0;
	// 递增版本
	tmp.lr_magic = ilog_ver_inc(lctx);
	tmp.lr_ts_idx = root->lr_ts_idx;

	// 22-3. 树根信息有变化，需要再次更新tree root信息
	return ilog_ptr_set(lctx, root, &tmp);
}

static int
check_equal(struct ilog_context *lctx, struct ilog_id *id_out, const struct ilog_id *id_in,
	    bool update, bool *is_equal)
{
	int	rc;

	*is_equal = false;

	// epoch 需要相等
	if (id_in->id_epoch != id_out->id_epoch)
		return 0;

	if (update) {
		// 如果是更新的话，tx 需要相等
		rc = ilog_is_same_tx(lctx, id_out, is_equal);
		if (rc != 0)
			return rc;
	} else if (id_in->id_tx_id == id_out->id_tx_id) {
		*is_equal = true;
	}

	// 1. 如果epoch 和tx 都相等，那么直接返回，is_equal == true
	if (!*is_equal) {
		if (!update) {
			D_DEBUG(DB_IO, "No entry found, done\n");
			return 0;
		}
		// 2. 如果epoch 相等 & tx 不相等，先判断id_in 是否已经被提交
		if (dtx_is_committed(id_in->id_tx_id, ilog_ctx2cont(lctx), id_in->id_epoch)) {
			/** Need to differentiate between updates that are
			 * overwrites and others that are conflicts.  Return
			 * a different error code in this case if the result
			 * would be the same (e.g. not mixing update with
			 * punch
			 */
			if (id_in->id_punch_minor_eph &&
			    id_out->id_punch_minor_eph >
			    id_out->id_update_minor_eph)
				return -DER_ALREADY;

			if (id_in->id_update_minor_eph &&
			    id_out->id_update_minor_eph >
			    id_out->id_punch_minor_eph)
				return -DER_ALREADY;
		}
		D_DEBUG(DB_IO, "Access of incarnation log from multiple DTX"
			" at same time is not allowed: rc=DER_TX_RESTART\n");
		return -DER_TX_RESTART;
	}

	return 0;
}

enum {
	ILOG_OP_UPDATE,
	ILOG_OP_PERSIST,
	ILOG_OP_ABORT,
};

static int
update_inplace(struct ilog_context *lctx, struct ilog_id *id_out, const struct ilog_id *id_in,
	       int opc, bool *is_equal)
{
	// 构建新的 saved id
	struct ilog_id	saved_id;
	int		rc;

	// 如果epoch 和tx 都相同，那么表示相等
	rc = check_equal(lctx, id_out, id_in, opc == ILOG_OP_UPDATE, is_equal);
	// 1. 如果明确相等，直接返回了
	// 2. 如果存在错误，直接返回了
	// 3. 如果opc == abort，直接返回了
	if (rc != 0 || !*is_equal || opc == ILOG_OP_ABORT)
		return rc;

	// 先赋值为 旧id
	saved_id.id_value = id_out->id_value;
	if (opc == ILOG_OP_PERSIST) {
		D_DEBUG(DB_TRACE, "Setting "DF_X64" to persistent\n",
			id_in->id_epoch);
		saved_id.id_tx_id = 0;
		goto set_id;
	}

	if (saved_id.id_punch_minor_eph > saved_id.id_update_minor_eph &&
	    id_in->id_punch_minor_eph)
		return 0; /** Already a punch */
	if (saved_id.id_update_minor_eph > saved_id.id_punch_minor_eph &&
	    id_in->id_update_minor_eph)
		return 0; /** Already an update */
	// 如果新punch id 大，覆盖旧id
	if (saved_id.id_punch_minor_eph < id_in->id_punch_minor_eph)
		saved_id.id_punch_minor_eph = id_in->id_punch_minor_eph;
	else if (saved_id.id_update_minor_eph < id_in->id_update_minor_eph)
		// 如果新update id 大，覆盖旧id
		saved_id.id_update_minor_eph = id_in->id_update_minor_eph;

	// 1. 如果要保存的id 和旧的一样，那么不需要重新持久化到pmem，直接结束
	if (saved_id.id_value == id_out->id_value)
		return 0; /* Nothing to do */

	/* New operation has a new minor epoch.  Update the old entry
	 * accordingly.
	 */
	// 2. 如果存在更新，将新的id 持久化到pmem
	D_DEBUG(DB_TRACE, "Updating "DF_X64
		" lid=%d punch=(%d->%d) update=(%d-%d)\n", id_in->id_epoch,
		id_out->id_tx_id, id_out->id_punch_minor_eph,
		saved_id.id_punch_minor_eph, id_out->id_update_minor_eph,
		saved_id.id_update_minor_eph);

set_id:
	if (saved_id.id_update_minor_eph == saved_id.id_punch_minor_eph) {
		D_ERROR("Matching punch/update minor epoch not allowed\n");
		return -DER_NO_PERM;
	}

	// 将 id_value 保存到umm，
	return ilog_ptr_set(lctx, &id_out->id_value, &saved_id.id_value);
}

static int
reset_root(struct ilog_context *lctx, struct ilog_array_cache *cache, int i)
{
	struct ilog_root	 tmp = {0};
	umem_off_t		 tree = UMOFF_NULL;
	int			 rc;

	rc = ilog_tx_begin(lctx);
	if (rc != 0)
		return rc;

	tmp.lr_magic = ilog_ver_inc(lctx);
	if (cache->ac_nr >= 2)
		tree = lctx->ic_root->lr_tree.it_root;


	if (i != -1) {
		tmp.lr_id.id_value = cache->ac_entries[i].id_value;
		tmp.lr_id.id_epoch = cache->ac_entries[i].id_epoch;
		tmp.lr_ts_idx = lctx->ic_root->lr_ts_idx;
	}

	rc = ilog_ptr_set(lctx, lctx->ic_root, &tmp);
	if (rc != 0)
		return rc;

	if (tree != UMOFF_NULL)
		return umem_free(lctx->ic_umm, tree);

	return 0;
}

static int
remove_entry(struct ilog_context *lctx, struct ilog_array_cache *cache, int i)
{
	struct ilog_array	*array;
	int			 rc = 0;
	uint32_t		 new_len;

	D_ASSERT(i >= 0);

	if (cache->ac_nr == 1) {
		return reset_root(lctx, cache, -1);
	} else if (cache->ac_nr == 2) {
		/** 1 - i will keep the other entry */
		return reset_root(lctx, cache, 1 - i);
	}

	rc = ilog_tx_begin(lctx);
	if (rc != 0)
		return rc;

	/** Just remove the entry at i */
	array = cache->ac_array;
	if (i + 1 != cache->ac_nr) {
		rc = umem_tx_add_ptr(lctx->ic_umm, &array->ia_id[i],
				     sizeof(array->ia_id[0]) * (cache->ac_nr - i));
		if (rc != 0)
			return rc;
		memmove(&array->ia_id[i], &array->ia_id[i + 1],
		       sizeof(array->ia_id[0]) * (cache->ac_nr - i));
	}

	new_len = cache->ac_nr - 1;
	return ilog_ptr_set(lctx, &array->ia_len, &new_len);
}

// id 中保存的是客户端传递来的epoch 和分布式事务的修改序列号
// epr 是上游的max epr
static int
ilog_tree_modify(struct ilog_context *lctx, const struct ilog_id *id_in,
		 const daos_epoch_range_t *epr, int opc)
{
	struct ilog_root	*root;
	// d_in->id_epoch 是客户端传递来的epoch
	daos_epoch_t		 epoch = id_in->id_epoch;
	// id 在id_in 基础上修改
	struct ilog_id		 id = *id_in;
	struct ilog_id		*id_out;
	bool			 is_equal;
	// 初始时认为ilog 是已提交状态
	int			 visibility = ILOG_COMMITTED;
	uint32_t		 new_len;
	size_t			 new_size;
	umem_off_t		 new_array;
	struct ilog_array	*array;
	struct ilog_array_cache	 cache;
	int			 rc = 0;
	int			 i;

	// 获取b+ 树根
	root = lctx->ic_root;

	// 从lctx 对应的root 下的b+ 树中获取entry 信息
	ilog_log2cache(lctx, &cache);

	// 遍历cache 中所有entry 记录，找到比epoch 小的entry
	// todo: cache 中entry 是按照epoch 排好序的吗
	for (i = cache.ac_nr - 1; i >= 0; i--) {
		// 这里是在判断cache 中是否存在比当前epoch 还大的entry
		// !!! 说明当前操作，只关注比当前epoch 小的ilog entry
		if (cache.ac_entries[i].id_epoch <= epoch)
			break;
	}

	// 从后往前比较，如果最后一个entry 的epoch 都比当前的小，那么所有的entry 的epoch 都会比当前的小，即不存在比当前epoch 大的entry

	// 1. 如果 i < 0，说明cache 中不存在比epoch 小的entry。由于只关注比当前epoch 小的entry，那么直接插入到cache 尾巴上就行
	// todo：也就是cache 中的entry 都比epoch 大，那么不是应该当前epoch 更新被撤销吗？即已经存在了比epoch 还新的更新
	if (i < 0) {
		// 如果不是update 场景，
		if (opc != ILOG_OP_UPDATE) {
			D_DEBUG(DB_TRACE, "No entry found, done\n");
			return 0;
		}
		// 如果是第一次添加ilog entry 的话，直接go insert
		goto insert;
	}

	// 2. i >= 0，说明cache 中存在entry 的epoch < 当前要update 的entry epoch
	// 由于关注的是比当前epoch 小的entry，那么用当前entry 替换不关注的entry（插队并替换）
	// todo: 先把上面打破break 的idx 的entry 取出，这个entry 的epoch > 当前要update 的entry 的epoch
	// i 可能是cache 中的最后一个元素，也可能是cache 中间的一个元素
	// 下面修改cache，起始就是修改pmem 中的内存中的数据了
	id_out = &cache.ac_entries[i];

	// 如果直接不走insert，先设置可见性为非提交状态
	visibility = ILOG_UNCOMMITTED;

	// 如果满足break 条件的entry 的epoch 介于max epr 之间
	if (id_out->id_epoch <= epr->epr_hi &&
	    id_out->id_epoch >= epr->epr_lo) {
		// 更新可见性，可见性变为 ILOG_UNCOMMITTED
		visibility = ilog_status_get(lctx, id_out, DAOS_INTENT_UPDATE, true);
		if (visibility < 0 && visibility != -DER_TX_UNCERTAIN)
			return visibility;
	}

	// 到此，可见性为：ILOG_UNCOMMITTED
	rc = update_inplace(lctx, id_out, id_in, opc, &is_equal);
	if (rc != 0)
		return rc;

	if (is_equal) {
		if (opc != ILOG_OP_ABORT)
			return 0;

		return remove_entry(lctx, &cache, i);
	}

	if (opc != ILOG_OP_UPDATE) {
		D_DEBUG(DB_TRACE, "No entry found, done\n");
		return 0;
	}

	// id_in->id_punch_minor_eph == 0
	// visibility == ILOG_UNCOMMITTED
	// 最终还是会进到 insert 中
	// todo: 直接进入到 insert 和最终进入到inset 是什么区别
	if (id_in->id_punch_minor_eph == 0 && visibility != ILOG_UNCOMMITTED &&
	    id_out->id_update_minor_eph > id_out->id_punch_minor_eph)
		return 0;
insert:
	rc = ilog_tx_begin(lctx);
	if (rc != 0)
		return rc;

	// 直接复制 id_in 的参数
	id.id_value = id_in->id_value;
	// 复制客户端传递来的epoch
	id.id_epoch = id_in->id_epoch;
	// 将id 添加到 ilog 中（注册 record）
	rc = ilog_log_add(lctx, &id);
	if (rc != 0)
		return rc;

	D_ASSERT(id.id_punch_minor_eph == id_in->id_punch_minor_eph);
	D_ASSERT(id.id_update_minor_eph == id_in->id_update_minor_eph);

	/* We want to insert after 'i', so just increment it */
	// 将新添加的entry append 到cache 的尾巴，即idx 为 i 的位置
	i++;
	if (cache.ac_nr == cache.ac_array->ia_max_len) {
		new_len = (cache.ac_nr + 1) * 2 - 1;
		new_size = sizeof(*cache.ac_array) + sizeof(cache.ac_entries[0]) * new_len;
		D_ASSERT((new_size & (ILOG_ARRAY_CHUNK_SIZE - 1)) == 0);
		new_array = umem_zalloc(lctx->ic_umm, new_size);
		if (new_array == UMOFF_NULL)
			return lctx->ic_umm->umm_nospc_rc;

		array             = umem_off2ptr(lctx->ic_umm, new_array);
		array->ia_len = cache.ac_nr + 1;
		array->ia_max_len = new_len;
		// 拷贝i 之前的entry
		if (i != 0) {
			/* Copy the entries before i */
			memcpy(&array->ia_id[0], &cache.ac_array->ia_id[0],
			       sizeof(array->ia_id[0]) * i);
		}

		// 拷贝i 之后的entry
		if (i != cache.ac_nr) {
			/* Copy the entries after i */
			memcpy(&array->ia_id[i + 1], &cache.ac_array->ia_id[i],
			       sizeof(array->ia_id[0]) * (cache.ac_nr - i));
		}

		// 填充idx = i 的entry，即当前要插入的entry
		array->ia_id[i].id_value = id.id_value;
		array->ia_id[i].id_epoch = id.id_epoch;

		rc = ilog_ptr_set(lctx, &root->lr_tree.it_root, &new_array);
		if (rc != 0)
			return rc;

		return umem_free(lctx->ic_umm, umem_ptr2off(lctx->ic_umm, cache.ac_array));
	}

	array = cache.ac_array;
	rc    = umem_tx_add_ptr(lctx->ic_umm, &array->ia_id[i],
				sizeof(array->ia_id[0]) * (cache.ac_nr - i + 1));
	if (rc != 0)
		return rc;

	if (i != cache.ac_nr) {
		/* Copy the entries after i */
		memmove(&array->ia_id[i + 1], &array->ia_id[i],
		       sizeof(array->ia_id[0]) * (cache.ac_nr - i));
	}

	array->ia_id[i].id_value = id.id_value;
	array->ia_id[i].id_epoch = id.id_epoch;

	new_len = cache.ac_nr + 1;
	return ilog_ptr_set(lctx, &array->ia_len, &new_len);
}

const char *opc_str[] = {
	"Update",
	"Persist",
	"Abort",
};

// 传入参数：ilog hdl，ilog id，epoch range，ilog op 类型
// id_in 中保存了客户端传递的epoch 和分布式事务的修改序列号
// epr 是上游的max epr
static int
ilog_modify(daos_handle_t loh, const struct ilog_id *id_in,
	    const daos_epoch_range_t *epr, int opc)
{
	// 构建ilog ctx
	struct ilog_context	*lctx;
	// 存储ilog 的root，存在两种结构，如果只存在一条entry，不使用b+tree；如果不止存在一条entry，需要保存到b+ 树中
	struct ilog_root	*root;
	struct ilog_root	 tmp = {0};
	int			 rc = 0;
	int			 visibility = ILOG_UNCOMMITTED;
	uint32_t		 version;

	// 根据hdl 获取lctx
	// todo: 这个cookie，， 是什么常规的操作
	lctx = ilog_hdl2lctx(loh);
	if (lctx == NULL) {
		D_ERROR("Invalid log handle\n");
		return -DER_INVAL;
	}

	D_ASSERT(!lctx->ic_in_txn);
	D_ASSERTF(id_in->id_epoch != 0, "Invalid epoch for ilog opc %d\n", opc);

	// lctx 获取root，这个就是ilog 的df，类似obj，dkey，akey的df
	root = lctx->ic_root;

	version = ilog_mag2ver(root->lr_magic);

	D_DEBUG(DB_TRACE, "%s in incarnation log: log:"DF_X64 " epoch:" DF_X64
		" tree_version: %d\n", opc_str[opc], lctx->ic_root_off,
		id_in->id_epoch, version);

	if (root->lr_tree.it_embedded && root->lr_id.id_epoch <= epr->epr_hi
	    && root->lr_id.id_epoch >= epr->epr_lo) {
		visibility = ilog_status_get(lctx, &root->lr_id, DAOS_INTENT_UPDATE, true);
		if (visibility < 0 && visibility != -DER_TX_UNCERTAIN) {
			rc = visibility;
			goto done;
		}
	}

	// 以下三种场景都是通过 ilog_log_add 来完成最后的ilog entry 添加（entry 注册）
	// 每种场景下的add 过程都是先 ilog_ptr_set （保存tree root信息到pmem），再 ilog_log_add （保存ilog entry 到tree）
	// 即先保存树根信息，再添加entry 到树根对应的树中
	// 如果root 为空，即存储ilog 的tree 为空
	if (ilog_empty(root)) {
		if (opc != ILOG_OP_UPDATE) {
			D_DEBUG(DB_TRACE, "ilog entry "DF_X64" not found\n",
				id_in->id_epoch);
			goto done;
		}

		// insert 到ilog tree 的根
		D_DEBUG(DB_TRACE, "Inserting "DF_X64" at ilog root\n",
			id_in->id_epoch);
		// 构建tmp 为树根
		// 版本增加
		tmp.lr_magic = ilog_ver_inc(lctx);
		tmp.lr_ts_idx = root->lr_ts_idx;
		// 构造好的ilog id 
		tmp.lr_id = *id_in;
		// 11-1先保存 tree root，此时只有一条记录，其实不是b+ tree
		rc = ilog_ptr_set(lctx, root, &tmp);
		// 如果root 构建成功
		if (rc == 0)
			// 1. 如果tree 为空，将新的ilog 添加到tree 作为树根
			// 11-2. 添加entry 到上面已经保存成功的树根中
			rc = ilog_log_add(lctx, &root->lr_id);
	} else if (root->lr_tree.it_embedded) {
		// 如果当前root 下只有一条entry，那么 it_embedded 为 true
		// 从代码看，这个值应该是一直为 false
		bool	is_equal;

		// 2. 如果root 不为空，原地更新（即原地更新当前仅有的一条记录，新记录替换旧记录），is_equal 是lr_id 和id_in 的比较结果
		// 22-1. 先保存树根信息（如果需要的话）
		rc = update_inplace(lctx, &root->lr_id, id_in,
				    opc, &is_equal);
		if (rc != 0)
			goto done;

		// 如果新旧记录相同，即不需要实际的持久化数据到pmem，直接go out
		if (is_equal) {
			if (opc == ILOG_OP_ABORT) {
				D_DEBUG(DB_TRACE, "Removing "DF_X64
					" from ilog root\n", id_in->id_epoch);
				tmp.lr_magic = ilog_ver_inc(lctx);
				rc = ilog_ptr_set(lctx, root, &tmp);
			}
			goto done;
		}

		if (opc != ILOG_OP_UPDATE) {
			D_DEBUG(DB_TRACE, "Entry "DF_X64" not found in ilog\n",
				id_in->id_epoch);
			goto done;
		}

		if (id_in->id_punch_minor_eph == 0 &&
		    root->lr_id.id_punch_minor_eph <
		    root->lr_id.id_update_minor_eph &&
		    id_in->id_epoch > root->lr_id.id_epoch &&
		    visibility == ILOG_COMMITTED) {
			D_DEBUG(DB_TRACE, "No update needed\n");
			goto done;
		}
		/* Either this entry is earlier or prior entry is uncommitted
		 * or either entry is a punch
		 */
		// todo: ilog 只有一条记录时，再次更新时变成两条记录，所以要转换为 b+树，所以执行这个迁移操作吗
		rc = ilog_root_migrate(lctx, id_in);
	} else {
		/** Ok, we have a tree.  Do the operation in the tree */
		// 3. 如果不是1，2场景，即root 不为空，且记录不止一条，即存储ilog 的是b+树结构，那么直接修改ilog tree 中对应的key
		// 输入：构建的lctx，id，epoch range，op 类型
		// epoch range 和op 都是上游传递来的
		// id 保存了客户端传递的epoch 和分布式事务修改序列号
		// epr 是上游传递来的max epr
		// 33-1. 这种情况树根信息不需要更新，直接添加entry 到b+ 树
		rc = ilog_tree_modify(lctx, id_in, epr, opc);
	}
done:
	// 结束ilog 事务
	rc = ilog_tx_end(lctx, rc);
	D_DEBUG(DB_TRACE,
		"%s in incarnation log " DF_X64 " status: rc=" DF_RC " tree_version: %d\n",
		opc_str[opc], id_in->id_epoch, DP_RC(rc), ilog_mag2ver(lctx->ic_root->lr_magic));

	if (rc == 0 && version != ilog_mag2ver(lctx->ic_root->lr_magic) &&
	    (opc == ILOG_OP_PERSIST || opc == ILOG_OP_ABORT)) {
		/** If we persisted or aborted an entry successfully,
		 *  invoke the callback, if applicable but without
		 *  deregistration
		 */
		// todo: 如果op 类型是持久化或者撤销
		ilog_log_del(lctx, id_in, false);
	}

	// 返回update 结果
	return rc;
}

// ilog 更新，传入ilog hdl，最大epoch，epoch 1，epoch 2，false
// minor_eph 最终会传递给ilog_id
// epr 是上游的max epr
// major 是客户端传递来的epoch
// minor 是分布式事务的修改序列号
int
ilog_update(daos_handle_t loh, const daos_epoch_range_t *epr,
	    daos_epoch_t major_eph, uint16_t minor_eph, bool punch)
{
	daos_epoch_range_t	 range = {0, DAOS_EPOCH_MAX};
	// 构建ilog id，主要是 epoch range
	// 这个id 最终要传递给保存ilog 信息的root 中的b+树中，类似一个set 结构
	struct ilog_id		 id = {
		.id_tx_id = 0,
		// 1. 这是客户端传递来的epoch
		.id_epoch = major_eph,
	};

	D_ASSERT(minor_eph != 0);

	// vos_ilog_update_ 里传递时使用的是 punch == false
	if (punch) {
		id.id_punch_minor_eph = minor_eph;
		id.id_update_minor_eph = 0;
	} else {
		// 走这里，最终存储到ilog b+树结构中
		// punch 小epoch 为0
		id.id_punch_minor_eph = 0;
		// update 小epoch 为 minor_eph
		// 2. 这是分布式事务的修改序列号
		id.id_update_minor_eph = minor_eph;
	}

	if (epr)
		range = *epr;

	// 更新ilog
	// 传入 ilog 的hdl，id，range，和op 类型，range 直接使用上游传递的max epr
	// id 保存的是客户端传递来的epoch 和分布式事务的修改序列号
	return ilog_modify(loh, &id, &range, ILOG_OP_UPDATE);

}

/** Makes a specific update to the incarnation log permanent and
 *  removes redundant entries
 */
int
ilog_persist(daos_handle_t loh, const struct ilog_id *id)
{
	daos_epoch_range_t	 range = {id->id_epoch, id->id_epoch};
	int	rc;

	rc = ilog_modify(loh, id, &range, ILOG_OP_PERSIST);

	return rc;
}

/** Removes a specific entry from the incarnation log if it exists */
int
ilog_abort(daos_handle_t loh, const struct ilog_id *id)
{
	daos_epoch_range_t	 range = {0, DAOS_EPOCH_MAX};

	D_DEBUG(DB_IO, "Aborting ilog entry %d "DF_X64"\n", id->id_tx_id,
		id->id_epoch);
	return ilog_modify(loh, id, &range, ILOG_OP_ABORT);
}

#define NUM_EMBEDDED 8

struct ilog_priv {
	/** Embedded context for current log root */
	struct ilog_context	 ip_lctx;
	/** Version of log from prior fetch */
	int32_t			 ip_log_version;
	/** Intent for prior fetch */
	uint32_t		 ip_intent;
	/** Number of status entries allocated */
	uint32_t		 ip_alloc_size;
	/** Cached return code for fetch operation */
	int			 ip_rc;
	/** Embedded status entries */
	struct ilog_info	 ip_embedded[NUM_EMBEDDED];
};
D_CASSERT(sizeof(struct ilog_priv) <= ILOG_PRIV_SIZE);

static inline struct ilog_priv *
ilog_ent2priv(struct ilog_entries *entries)
{
	return (struct ilog_priv *)&entries->ie_priv[0];
}

void
ilog_fetch_init(struct ilog_entries *entries)
{
	struct ilog_priv	*priv = ilog_ent2priv(entries);

	D_ASSERT(entries != NULL);
	memset(entries, 0, sizeof(*entries));
	entries->ie_info = &priv->ip_embedded[0];
}

void
ilog_fetch_move(struct ilog_entries *dest, struct ilog_entries *src)
{
	struct ilog_priv	*priv_dest = ilog_ent2priv(dest);
	struct ilog_priv	*priv_src = ilog_ent2priv(src);

	D_ASSERT(dest != NULL);
	D_ASSERT(src != NULL);

	/** We've already copied everything, just fix up any pointers here */
	if (src->ie_info == &priv_src->ip_embedded[0])
		dest->ie_info = &priv_dest->ip_embedded[0];

	priv_src->ip_alloc_size = 0;
}

static void
ilog_status_refresh(struct ilog_context *lctx, uint32_t intent, bool has_cond,
		    struct ilog_entries *entries)
{
	struct ilog_priv	*priv = ilog_ent2priv(entries);
	struct ilog_entry	 entry;
	int32_t			 status;
	bool			 same_intent = (intent == priv->ip_intent);
	bool			 retry;

	if ((intent == DAOS_INTENT_UPDATE || intent == DAOS_INTENT_PUNCH) && !has_cond)
		retry = false;
	else
		retry = true;

	priv->ip_intent = intent;
	priv->ip_rc = 0;
	ilog_foreach_entry(entries, &entry) {
		if (same_intent &&
		    (entry.ie_status == ILOG_COMMITTED ||
		     entry.ie_status == ILOG_REMOVED))
			continue;
		status = ilog_status_get(lctx, &entry.ie_id, intent, retry);
		if (status < 0 && status != -DER_INPROGRESS) {
			priv->ip_rc = status;
			return;
		}
		entries->ie_info[entry.ie_idx].ii_removed = 0;
		entries->ie_info[entry.ie_idx].ii_status = status;
	}
}

static bool
ilog_fetch_cached(struct umem_instance *umm, struct ilog_root *root,
		  const struct ilog_desc_cbs *cbs, uint32_t intent, bool has_cond,
		  struct ilog_entries *entries)
{
	struct ilog_priv	*priv = ilog_ent2priv(entries);
	struct ilog_context	*lctx = &priv->ip_lctx;

	D_ASSERT(entries->ie_info != NULL);
	D_ASSERT(priv->ip_alloc_size != 0 ||
		 entries->ie_info == &priv->ip_embedded[0]);

	if (priv->ip_lctx.ic_root != root ||
	    priv->ip_log_version != ilog_mag2ver(root->lr_magic)) {
		goto reset;
	}

	if (priv->ip_rc == -DER_NONEXIST)
		return true;

	D_ASSERT(entries->ie_ids != NULL);
	ilog_status_refresh(&priv->ip_lctx, intent, has_cond, entries);

	return true;
reset:
	lctx->ic_root = root;
	lctx->ic_root_off = umem_ptr2off(umm, root);
	lctx->ic_umm      = umm;
	lctx->ic_cbs = *cbs;
	lctx->ic_ref = 0;
	lctx->ic_in_txn = false;
	lctx->ic_ver_inc = false;

	entries->ie_num_entries = 0;
	priv->ip_intent = intent;
	priv->ip_log_version = ilog_mag2ver(lctx->ic_root->lr_magic);
	priv->ip_rc = 0;

	return false;
}

static int
prepare_entries(struct ilog_entries *entries, struct ilog_array_cache *cache)
{
	struct ilog_priv	*priv = ilog_ent2priv(entries);
	struct ilog_info	*info;

	if (cache->ac_nr <= NUM_EMBEDDED)
		goto done;

	if (cache->ac_nr <= priv->ip_alloc_size)
		goto done;

	D_ALLOC_ARRAY(info, cache->ac_nr);
	if (info == NULL)
		return -DER_NOMEM;

	if (entries->ie_info != &priv->ip_embedded[0])
		D_FREE(entries->ie_info);

	entries->ie_info = info;
	priv->ip_alloc_size = cache->ac_nr;

done:
	entries->ie_ids = cache->ac_entries;

	return 0;
}

// todo: 这个函数没看明白，是从哪里取得数据做fetch
int
ilog_fetch(struct umem_instance *umm, struct ilog_df *root_df,
	   const struct ilog_desc_cbs *cbs, uint32_t intent, bool has_cond,
	   struct ilog_entries *entries)
{
	struct ilog_context	*lctx;
	struct ilog_root	*root;
	struct ilog_id		*id;
	// 从entry 里获取priv
	struct ilog_priv	*priv = ilog_ent2priv(entries);
	struct ilog_array_cache	 cache;
	int			 i;
	int			 status;
	int			 rc = 0;
	bool			 retry;

	ILOG_ASSERT_VALID(root_df);

	root = (struct ilog_root *)root_df;

	if (ilog_fetch_cached(umm, root, cbs, intent, has_cond, entries)) {
		if (priv->ip_rc == -DER_NONEXIST)
			return priv->ip_rc;
		if (priv->ip_rc < 0) {
			D_ASSERT(priv->ip_rc != -DER_INPROGRESS);
			/* Don't cache error return codes */
			rc = priv->ip_rc;
			priv->ip_rc = 0;
			priv->ip_log_version = ILOG_MAGIC;
			return rc;
		}

		// 这里是 cache hit 场景，直接返回 0
		return 0;
	}

	// 这里是cache miss 场景，创建并添加到cache
	// 获取lctx
	lctx = &priv->ip_lctx;
	if (ilog_empty(root))
		D_GOTO(out, rc = 0);

	// lctx 转换成cache
	ilog_log2cache(lctx, &cache);

	// 根据cache 准备entry
	rc = prepare_entries(entries, &cache);
	if (rc != 0)
		goto fail;

	if ((intent == DAOS_INTENT_UPDATE || intent == DAOS_INTENT_PUNCH) && !has_cond)
		retry = false;
	else
		retry = true;

	// 遍历cache，填充entry
	for (i = 0; i < cache.ac_nr; i++) {
		id = &cache.ac_entries[i];
		status = ilog_status_get(lctx, id, intent, retry);
		if (status < 0 && status != -DER_INPROGRESS)
			D_GOTO(fail, rc = status);
		entries->ie_info[entries->ie_num_entries].ii_removed = 0;
		entries->ie_info[entries->ie_num_entries++].ii_status = status;
	}

out:
	D_ASSERT(rc != -DER_NONEXIST);
	if (entries->ie_num_entries == 0)
		rc = -DER_NONEXIST;

	priv->ip_rc = rc;

	return rc;
fail:
	/* fetch again next time */
	priv->ip_log_version = ILOG_MAGIC;

	return rc;
}

void
ilog_fetch_finish(struct ilog_entries *entries)
{
	struct ilog_priv	*priv = ilog_ent2priv(entries);

	D_ASSERT(entries != NULL);
	if (priv->ip_alloc_size)
		D_FREE(entries->ie_info);
}

struct agg_arg {
	const daos_epoch_range_t	*aa_epr;
	int32_t				 aa_prev;
	int32_t				 aa_prior_punch;
	daos_epoch_t			 aa_punched;
	bool				 aa_discard;
	bool				 aa_inprogress;
	uint16_t			 aa_punched_minor;
};

enum {
	AGG_RC_DONE,
	AGG_RC_NEXT,
	AGG_RC_REMOVE,
	AGG_RC_REMOVE_PREV,
	AGG_RC_ABORT,
};

static bool
entry_punched(const struct ilog_entry *entry, const struct agg_arg *agg_arg)
{
	uint16_t	minor_epc = MAX(entry->ie_id.id_punch_minor_eph,
					entry->ie_id.id_update_minor_eph);

	if (entry->ie_id.id_epoch > agg_arg->aa_punched)
		return false;

	if (entry->ie_id.id_epoch < agg_arg->aa_punched)
		return true;

	return minor_epc <= agg_arg->aa_punched_minor;

}

static int
check_agg_entry(const struct ilog_entries *entries, const struct ilog_entry *entry,
		struct agg_arg *agg_arg)
{
	int			rc;
	bool			parent_punched = false;
	struct ilog_entry	tmp;
	uint16_t		minor_epc = MAX(entry->ie_id.id_punch_minor_eph,
						entry->ie_id.id_update_minor_eph);

	if (D_LOG_ENABLED(DB_TRACE)) {
		daos_epoch_t		prev_epc = 0;
		daos_epoch_t		prev_punch_epc = 0;

		if (agg_arg->aa_prev != -1) {
			ilog_cache_entry(entries, &tmp, agg_arg->aa_prev);
			prev_epc = tmp.ie_id.id_epoch;
		}
		if (agg_arg->aa_prior_punch != -1) {
			ilog_cache_entry(entries, &tmp, agg_arg->aa_prior_punch);
			prev_punch_epc = tmp.ie_id.id_epoch;
		}
		D_DEBUG(DB_TRACE, "Entry "DF_X64".%d punch=%s prev="DF_X64" prior_punch="DF_X64"\n",
			entry->ie_id.id_epoch, minor_epc, ilog_is_punch(entry) ? "yes" : "no",
			prev_epc, prev_punch_epc);
	}

	if (entry->ie_id.id_epoch > agg_arg->aa_epr->epr_hi)
		D_GOTO(done, rc = AGG_RC_DONE);

	if (agg_arg->aa_inprogress) {
		/** if removing only aborted/in progress entries, skip committed ones */
		if (entry->ie_status == ILOG_COMMITTED)
			D_GOTO(done, rc = AGG_RC_NEXT);
		if (entry->ie_id.id_epoch < agg_arg->aa_epr->epr_lo)
			D_GOTO(done, rc = AGG_RC_NEXT);
		/** If entry is either marked aborted or uncommitted, remove it */
		D_GOTO(done, rc = AGG_RC_REMOVE);
	} else if (agg_arg->aa_discard) {
		/** Normal discard should remove everything */
		if (entry->ie_id.id_epoch < agg_arg->aa_epr->epr_lo)
			D_GOTO(done, rc = AGG_RC_NEXT);
		D_GOTO(done, rc = AGG_RC_REMOVE);
	}

	if (entry->ie_status == ILOG_UNCOMMITTED) {
		/** Abort ilog aggregation on hitting any uncommitted entry */
		D_GOTO(done, rc = AGG_RC_ABORT);
	}

	parent_punched = entry_punched(entry, agg_arg);
	if (entry->ie_id.id_epoch < agg_arg->aa_epr->epr_lo) {
		if (parent_punched) {
			/* Skip entries outside of the range and
			 * punched by the parent
			 */
			D_GOTO(done, rc = AGG_RC_NEXT);
		}
		if (ilog_is_punch(entry)) {
			/* Just save the prior punch entry */
			agg_arg->aa_prior_punch = entry->ie_idx;
		} else {
			/* A create covers the prior punch */
			agg_arg->aa_prior_punch = -1;
		}
		D_GOTO(done, rc = AGG_RC_NEXT);
	}

	/* With purge set, there should not be uncommitted entries */
	D_ASSERT(entry->ie_status != ILOG_UNCOMMITTED);

	if (agg_arg->aa_discard || entry->ie_status == ILOG_REMOVED ||
	    parent_punched) {
		/* Remove stale entry or punched entry */
		D_GOTO(done, rc = AGG_RC_REMOVE);
	}

	if (agg_arg->aa_prev != -1) {
		bool			 punch;

		ilog_cache_entry(entries, &tmp, agg_arg->aa_prev);
		punch = ilog_is_punch(&tmp);

		if (!punch) {
			/* punched by outer level */
			punch = entry_punched(&tmp, agg_arg);
		}
		if (ilog_is_punch(entry) == punch) {
			/* Remove redundant entry */
			D_GOTO(done, rc = AGG_RC_REMOVE);
		}
	}

	if (!ilog_is_punch(entry)) {
		/* Create is needed for now */
		D_GOTO(done, rc = AGG_RC_NEXT);
	}

	if (agg_arg->aa_prev == -1) {
		/* No punched entry to remove */
		D_GOTO(done, rc = AGG_RC_REMOVE);
	}

	if (tmp.ie_id.id_epoch < agg_arg->aa_epr->epr_lo) {
		/** Data punched is not in range */
		agg_arg->aa_prior_punch = entry->ie_idx;
		D_GOTO(done, rc = AGG_RC_NEXT);
	}

	D_ASSERT(!ilog_is_punch(&tmp));

	/* Punch is redundant or covers nothing.  Remove it. */
	rc = AGG_RC_REMOVE_PREV;
done:
	return rc;
}

static int
collapse_tree(struct ilog_context *lctx, struct ilog_array_cache *cache,
	      struct ilog_entries *entries, int removed)
{
	struct ilog_id		*dest;
	struct ilog_array	*array;
	int			 rc;
	uint32_t		 nr = 0;
	int			 i;

	if (removed == 0)
		return 0;

	rc = ilog_tx_begin(lctx);
	if (rc != 0)
		return rc;

	array = cache->ac_array;

	for (i = 0; i < cache->ac_nr; i++) {

		if (!entries->ie_info[i].ii_removed)
			continue;

		dest = &cache->ac_entries[i];

		D_DEBUG(DB_TRACE, "Removing ilog entry at " DF_X64 "\n", dest->id_epoch);

		rc = ilog_log_del(lctx, dest, true);
		if (rc != 0) {
			D_ERROR("Could not remove entry from tree: " DF_RC "\n", DP_RC(rc));
			return rc;
		}
		D_DEBUG(DB_TRACE, "Removed ilog entry at " DF_X64 "\n", dest->id_epoch);
	}
	if (cache->ac_nr == removed)
		return reset_root(lctx, cache, -1);

	if (cache->ac_nr == removed + 1) {
		/** all but one entry removed, move it to root */
		for (i = 0; i < cache->ac_nr; i++) {
			if (!entries->ie_info[i].ii_removed)
				return reset_root(lctx, cache, i);
		}
		D_ASSERT(0);
	}

	rc = umem_tx_add_ptr(lctx->ic_umm, array,
			     sizeof(*array) + sizeof(array->ia_id[0]) * (cache->ac_nr - removed));
	if (rc != 0)
		return rc;

	dest = &array->ia_id[0];

	for (i = 0; i < cache->ac_nr; i++) {
		if (entries->ie_info[i].ii_removed)
			continue;

		dest->id_value = cache->ac_entries[i].id_value;
		dest->id_epoch = cache->ac_entries[i].id_epoch;
		nr++;
		dest++;
	}

	D_ASSERT(nr == cache->ac_nr - removed);
	array->ia_len = nr;

	return 0;
}

int
ilog_aggregate(struct umem_instance *umm, struct ilog_df *ilog,
	       const struct ilog_desc_cbs *cbs, const daos_epoch_range_t *epr,
	       bool discard, bool inprogress, daos_epoch_t punched_major, uint16_t punched_minor,
	       struct ilog_entries *entries)
{
	struct ilog_priv	*priv = ilog_ent2priv(entries);
	struct ilog_context	*lctx;
	struct ilog_entry	 entry;
	struct agg_arg		 agg_arg;
	struct ilog_root	*root;
	struct ilog_array_cache	 cache;
	bool			 empty = false;
	int			 rc = 0;
	int			 removed = 0;

	D_ASSERT(epr != NULL);
	D_ASSERT(punched_major <= epr->epr_hi);
	D_ASSERT(!inprogress || discard);

	D_DEBUG(DB_TRACE, "%s incarnation log: epr: "DF_X64"-"DF_X64" punched="
		DF_X64".%d\n", discard ? "Discard" : "Aggregate", epr->epr_lo,
		epr->epr_hi, punched_major, punched_minor);

	/* This can potentially be optimized but using ilog_fetch gets some code
	 * reuse.
	 */
	rc = ilog_fetch(umm, ilog, cbs, DAOS_INTENT_PURGE, false, entries);
	if (rc == -DER_NONEXIST) {
		D_DEBUG(DB_TRACE, "log is empty\n");
		/* Log is empty */
		return 1;
	}

	lctx = &priv->ip_lctx;

	root = lctx->ic_root;

	ILOG_ASSERT_VALID(root);

	D_ASSERT(!ilog_empty(root)); /* ilog_fetch should have failed */

	ilog_log2cache(lctx, &cache);

	agg_arg.aa_epr = epr;
	agg_arg.aa_prev = -1;
	agg_arg.aa_prior_punch = -1;
	agg_arg.aa_punched = punched_major;
	agg_arg.aa_punched_minor = punched_minor;
	agg_arg.aa_discard = discard;
	agg_arg.aa_inprogress = inprogress;

	ilog_foreach_entry(entries, &entry) {
		D_ASSERT(entry.ie_idx < cache.ac_nr);
		rc = check_agg_entry(entries, &entry, &agg_arg);

		switch (rc) {
		case AGG_RC_DONE:
			goto collapse;
		case AGG_RC_NEXT:
			agg_arg.aa_prev = entry.ie_idx;
			break;
		case AGG_RC_REMOVE_PREV:
			entries->ie_info[agg_arg.aa_prev].ii_removed = 1;
			removed++;
			agg_arg.aa_prev = agg_arg.aa_prior_punch;
			/* Fall through */
		case AGG_RC_REMOVE:
			entries->ie_info[entry.ie_idx].ii_removed = 1;
			removed++;
			break;
		case AGG_RC_ABORT:
			rc = -DER_TX_BUSY;
			goto done;
		default:
			/* Unknown return code */
			D_ASSERT(0);
		}
	}

collapse:
	rc = collapse_tree(lctx, &cache, entries, removed);

	empty = ilog_empty(root);
done:
	rc = ilog_tx_end(lctx, rc);
	D_DEBUG(DB_TRACE, "%s in incarnation log epr:"DF_X64"-"DF_X64
		" status: "DF_RC", removed %d entries\n",
		discard ? "Discard" : "Aggregation", epr->epr_lo,
		epr->epr_hi, DP_RC(rc), removed);
	if (rc)
		return rc;

	return empty;
}

uint32_t *
ilog_ts_idx_get(struct ilog_df *ilog_df)
{
	struct ilog_root	*root;

	/** No validity check as index is just a constant offset */
	root = (struct ilog_root *)ilog_df;

	return &root->lr_ts_idx;
}

uint32_t
ilog_version_get(daos_handle_t loh)
{
	struct ilog_context	*lctx;

	lctx = ilog_hdl2lctx(loh);
	if (lctx == NULL) {
		D_ERROR("Invalid log handle\n");
		return 0;
	}

	return ilog_mag2ver(lctx->ic_root->lr_magic);
}
