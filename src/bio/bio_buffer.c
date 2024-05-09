/**
 * (C) Copyright 2018-2023 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
#define D_LOGFAC	DD_FAC(bio)
#include <spdk/env.h>
#include <spdk/blob.h>
#include <spdk/thread.h>
#include "bio_internal.h"

static void
dma_free_chunk(struct bio_dma_chunk *chunk)
{
	D_ASSERT(chunk->bdc_ptr != NULL);
	D_ASSERT(chunk->bdc_pg_idx == 0);
	D_ASSERT(chunk->bdc_ref == 0);
	D_ASSERT(d_list_empty(&chunk->bdc_link));

	if (bio_spdk_inited)
		spdk_dma_free(chunk->bdc_ptr);
	else
		free(chunk->bdc_ptr);

	D_FREE(chunk);
}

static struct bio_dma_chunk *
dma_alloc_chunk(unsigned int cnt)
{
	struct bio_dma_chunk *chunk;
	ssize_t bytes = (ssize_t)cnt << BIO_DMA_PAGE_SHIFT;
	int rc;

	D_ASSERT(bytes > 0);

	if (DAOS_FAIL_CHECK(DAOS_NVME_ALLOCBUF_ERR)) {
		D_ERROR("Injected DMA buffer allocation error.\n");
		return NULL;
	}

	D_ALLOC_PTR(chunk);
	if (chunk == NULL) {
		return NULL;
	}

	if (bio_spdk_inited) {
		// 利用spdk 接口申请内存，内部调用spdk_malloc
		chunk->bdc_ptr = spdk_dma_malloc_socket(bytes, BIO_DMA_PAGE_SZ, NULL,
							bio_numa_node);
	} else {
		// 使用posix 接口申请内存
		rc = posix_memalign(&chunk->bdc_ptr, BIO_DMA_PAGE_SZ, bytes);
		if (rc)
			chunk->bdc_ptr = NULL;
	}

	if (chunk->bdc_ptr == NULL) {
		D_FREE(chunk);
		return NULL;
	}
	// todo: 申请的内存是如何管理的
	D_INIT_LIST_HEAD(&chunk->bdc_link);

	return chunk;
}

static void
dma_buffer_shrink(struct bio_dma_buffer *buf, unsigned int cnt)
{
	struct bio_dma_chunk *chunk, *tmp;

	d_list_for_each_entry_safe(chunk, tmp, &buf->bdb_idle_list, bdc_link) {
		if (cnt == 0)
			break;

		d_list_del_init(&chunk->bdc_link);
		dma_free_chunk(chunk);

		D_ASSERT(buf->bdb_tot_cnt > 0);
		buf->bdb_tot_cnt--;
		cnt--;
		if (buf->bdb_stats.bds_chks_tot)
			d_tm_set_gauge(buf->bdb_stats.bds_chks_tot, buf->bdb_tot_cnt);
	}
}

int
dma_buffer_grow(struct bio_dma_buffer *buf, unsigned int cnt)
{
	struct bio_dma_chunk *chunk;
	int i, rc = 0;

	D_ASSERT((buf->bdb_tot_cnt + cnt) <= bio_chk_cnt_max);

	for (i = 0; i < cnt; i++) {
		chunk = dma_alloc_chunk(bio_chk_sz);
		if (chunk == NULL) {
			rc = -DER_NOMEM;
			break;
		}

		d_list_add_tail(&chunk->bdc_link, &buf->bdb_idle_list);
		buf->bdb_tot_cnt++;
		if (buf->bdb_stats.bds_chks_tot)
			d_tm_set_gauge(buf->bdb_stats.bds_chks_tot, buf->bdb_tot_cnt);
	}

	return rc;
}

void
dma_buffer_destroy(struct bio_dma_buffer *buf)
{
	D_ASSERT(d_list_empty(&buf->bdb_used_list));
	D_ASSERT(buf->bdb_active_iods == 0);
	D_ASSERT(buf->bdb_queued_iods == 0);

	bulk_cache_destroy(buf);
	dma_buffer_shrink(buf, buf->bdb_tot_cnt);

	D_ASSERT(buf->bdb_tot_cnt == 0);
	ABT_mutex_free(&buf->bdb_mutex);
	ABT_cond_free(&buf->bdb_wait_iod);
	ABT_cond_free(&buf->bdb_fifo);

	D_FREE(buf);
}

static inline char *
chk_type2str(int chk_type)
{
	switch (chk_type) {
	case BIO_CHK_TYPE_IO:
		return "io";
	case BIO_CHK_TYPE_LOCAL:
		return "local";
	case BIO_CHK_TYPE_REBUILD:
		return "rebuild";
	default:
		return "unknown";
	}
}

static void
dma_metrics_init(struct bio_dma_buffer *bdb, int tgt_id)
{
	struct bio_dma_stats	*stats = &bdb->bdb_stats;
	char			 desc[40];
	int			 i, rc;

	rc = d_tm_add_metric(&stats->bds_chks_tot, D_TM_GAUGE, "Total chunks", "chunk",
			     "dmabuff/total_chunks/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create total_chunks telemetry: "DF_RC"\n", DP_RC(rc));

	for (i = BIO_CHK_TYPE_IO; i < BIO_CHK_TYPE_MAX; i++) {
		snprintf(desc, sizeof(desc), "Used chunks (%s)", chk_type2str(i));
		rc = d_tm_add_metric(&stats->bds_chks_used[i], D_TM_GAUGE, desc, "chunk",
				     "dmabuff/used_chunks_%s/tgt_%d", chk_type2str(i), tgt_id);
		if (rc)
			D_WARN("Failed to create used_chunks_%s telemetry: "DF_RC"\n",
			       chk_type2str(i), DP_RC(rc));
	}

	rc = d_tm_add_metric(&stats->bds_bulk_grps, D_TM_GAUGE, "Total bulk grps", "grp",
			     "dmabuff/bulk_grps/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create total_bulk_grps telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_active_iods, D_TM_GAUGE, "Active requests", "req",
			     "dmabuff/active_reqs/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create active_requests telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_queued_iods, D_TM_GAUGE, "Queued requests", "req",
			     "dmabuff/queued_reqs/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create queued_requests telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_grab_errs, D_TM_COUNTER, "Grab buffer errors", "err",
			     "dmabuff/grab_errs/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create grab_errs telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_grab_retries, D_TM_STATS_GAUGE, "Grab buffer retry count",
			     "retry", "dmabuff/grab_retries/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create grab_retries telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_wal_sz, D_TM_STATS_GAUGE, "WAL tx size",
			     "bytes", "dmabuff/wal_sz/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create WAL size telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_wal_qd, D_TM_STATS_GAUGE, "WAL tx QD",
			     "commits", "dmabuff/wal_qd/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create WAL QD telemetry: "DF_RC"\n", DP_RC(rc));

	rc = d_tm_add_metric(&stats->bds_wal_waiters, D_TM_STATS_GAUGE, "WAL waiters",
			     "transactions", "dmabuff/wal_waiters/tgt_%d", tgt_id);
	if (rc)
		D_WARN("Failed to create WAL waiters telemetry: "DF_RC"\n", DP_RC(rc));
}

struct bio_dma_buffer *
dma_buffer_create(unsigned int init_cnt, int tgt_id)
{
	struct bio_dma_buffer *buf;
	int rc;

	D_ALLOC_PTR(buf);
	if (buf == NULL)
		return NULL;

	D_INIT_LIST_HEAD(&buf->bdb_idle_list);
	D_INIT_LIST_HEAD(&buf->bdb_used_list);
	buf->bdb_tot_cnt = 0;
	buf->bdb_active_iods = 0;

	rc = ABT_mutex_create(&buf->bdb_mutex);
	if (rc != ABT_SUCCESS) {
		D_FREE(buf);
		return NULL;
	}

	rc = ABT_cond_create(&buf->bdb_wait_iod);
	if (rc != ABT_SUCCESS) {
		ABT_mutex_free(&buf->bdb_mutex);
		D_FREE(buf);
		return NULL;
	}

	rc = ABT_cond_create(&buf->bdb_fifo);
	if (rc != ABT_SUCCESS) {
		ABT_mutex_free(&buf->bdb_mutex);
		ABT_cond_free(&buf->bdb_wait_iod);
		D_FREE(buf);
		return NULL;
	}

	rc = bulk_cache_create(buf);
	if (rc != 0) {
		ABT_mutex_free(&buf->bdb_mutex);
		ABT_cond_free(&buf->bdb_wait_iod);
		ABT_cond_free(&buf->bdb_fifo);
		D_FREE(buf);
		return NULL;
	}

	dma_metrics_init(buf, tgt_id);

	rc = dma_buffer_grow(buf, init_cnt);
	if (rc != 0) {
		dma_buffer_destroy(buf);
		return NULL;
	}

	return buf;
}

struct bio_sglist *
bio_iod_sgl(struct bio_desc *biod, unsigned int idx)
{
	struct bio_sglist	*bsgl = NULL;

	D_ASSERTF(idx < biod->bd_sgl_cnt, "Invalid sgl index %d/%d\n",
		  idx, biod->bd_sgl_cnt);

	bsgl = &biod->bd_sgls[idx];
	D_ASSERT(bsgl != NULL);

	return bsgl;
}

struct bio_desc *
bio_iod_alloc(struct bio_io_context *ctxt, struct umem_instance *umem,
	      unsigned int sgl_cnt, unsigned int type)
{
	struct bio_desc	*biod;

	D_ASSERT(ctxt != NULL);
	D_ASSERT(sgl_cnt != 0);

	D_ALLOC(biod, offsetof(struct bio_desc, bd_sgls[sgl_cnt]));
	if (biod == NULL)
		return NULL;

	D_ASSERT(type < BIO_IOD_TYPE_MAX);
	biod->bd_umem = umem;
	// 设置io ctx，里面有blob id
	biod->bd_ctxt = ctxt;
	biod->bd_type = type;
	biod->bd_sgl_cnt = sgl_cnt;

	biod->bd_dma_done = ABT_EVENTUAL_NULL;
	return biod;
}

static inline void
iod_dma_completion(struct bio_desc *biod, int err)
{
	if (biod->bd_completion != NULL) {
		D_ASSERT(biod->bd_comp_arg != NULL);
		biod->bd_completion(biod->bd_comp_arg, err);
	} else if (biod->bd_dma_done != ABT_EVENTUAL_NULL) {
		ABT_eventual_set(biod->bd_dma_done, NULL, 0);
	}
}

void
iod_dma_wait(struct bio_desc *biod)
{
	struct bio_xs_context	*xs_ctxt = biod->bd_ctxt->bic_xs_ctxt;
	int			 rc;

	D_ASSERT(xs_ctxt != NULL);
	if (xs_ctxt->bxc_self_polling) {
		D_DEBUG(DB_IO, "Self poll completion\n");
		rc = xs_poll_completion(xs_ctxt, &biod->bd_inflights, 0);
		if (rc)
			D_ERROR("Self poll completion failed. "DF_RC"\n", DP_RC(rc));
	} else if (biod->bd_inflights != 0) {
		rc = ABT_eventual_wait(biod->bd_dma_done, NULL);
		if (rc != ABT_SUCCESS)
			D_ERROR("ABT eventual wait failed. %d\n", rc);
	}
}

void
bio_iod_free(struct bio_desc *biod)
{
	int i;

	if (biod->bd_async_post && biod->bd_dma_done != ABT_EVENTUAL_NULL)
		iod_dma_wait(biod);

	D_ASSERT(!biod->bd_buffer_prep);

	if (biod->bd_dma_done != ABT_EVENTUAL_NULL)
		ABT_eventual_free(&biod->bd_dma_done);

	for (i = 0; i < biod->bd_sgl_cnt; i++)
		bio_sgl_fini(&biod->bd_sgls[i]);

	D_FREE(biod->bd_bulk_hdls);

	D_FREE(biod);
}

static inline bool
dma_chunk_is_huge(struct bio_dma_chunk *chunk)
{
	return d_list_empty(&chunk->bdc_link);
}

/*
 * Release all the DMA chunks held by @biod, once the use count of any
 * chunk drops to zero, put it back to free list.
 */
static void
iod_release_buffer(struct bio_desc *biod)
{
	struct bio_dma_buffer *bdb;
	struct bio_rsrvd_dma *rsrvd_dma = &biod->bd_rsrvd;
	int i;

	/* Release bulk handles */
	bulk_iod_release(biod);

	/* No reserved DMA regions */
	if (rsrvd_dma->brd_rg_cnt == 0) {
		D_ASSERT(rsrvd_dma->brd_rg_max == 0);
		D_ASSERT(rsrvd_dma->brd_chk_max == 0);
		biod->bd_buffer_prep = 0;
		return;
	}

	D_ASSERT(rsrvd_dma->brd_regions != NULL);
	D_FREE(rsrvd_dma->brd_regions);
	rsrvd_dma->brd_regions = NULL;
	rsrvd_dma->brd_rg_max = rsrvd_dma->brd_rg_cnt = 0;
	biod->bd_nvme_bytes = 0;

	/* All DMA chunks are used through cached bulk handle */
	if (rsrvd_dma->brd_chk_cnt == 0) {
		D_ASSERT(rsrvd_dma->brd_dma_chks == NULL);
		D_ASSERT(rsrvd_dma->brd_chk_max == 0);
		biod->bd_buffer_prep = 0;
		return;
	}

	/* Release the DMA chunks not from cached bulk handle */
	D_ASSERT(rsrvd_dma->brd_dma_chks != NULL);
	bdb = iod_dma_buf(biod);
	for (i = 0; i < rsrvd_dma->brd_chk_cnt; i++) {
		struct bio_dma_chunk *chunk = rsrvd_dma->brd_dma_chks[i];

		D_ASSERT(chunk != NULL);
		D_ASSERT(chunk->bdc_ref > 0);
		D_ASSERT(chunk->bdc_type == biod->bd_chk_type);
		D_ASSERT(chunk->bdc_bulk_grp == NULL);
		chunk->bdc_ref--;

		D_DEBUG(DB_IO, "Release chunk:%p[%p] idx:%u ref:%u huge:%d "
			"type:%u\n", chunk, chunk->bdc_ptr, chunk->bdc_pg_idx,
			chunk->bdc_ref, dma_chunk_is_huge(chunk),
			chunk->bdc_type);

		if (dma_chunk_is_huge(chunk)) {
			dma_free_chunk(chunk);
		} else if (chunk->bdc_ref == 0) {
			chunk->bdc_pg_idx = 0;
			D_ASSERT(bdb->bdb_used_cnt[chunk->bdc_type] > 0);
			bdb->bdb_used_cnt[chunk->bdc_type] -= 1;
			if (bdb->bdb_stats.bds_chks_used[chunk->bdc_type])
				d_tm_set_gauge(bdb->bdb_stats.bds_chks_used[chunk->bdc_type],
					       bdb->bdb_used_cnt[chunk->bdc_type]);

			if (chunk == bdb->bdb_cur_chk[chunk->bdc_type])
				bdb->bdb_cur_chk[chunk->bdc_type] = NULL;
			d_list_move_tail(&chunk->bdc_link, &bdb->bdb_idle_list);
		}
		rsrvd_dma->brd_dma_chks[i] = NULL;
	}

	D_FREE(rsrvd_dma->brd_dma_chks);
	rsrvd_dma->brd_dma_chks = NULL;
	rsrvd_dma->brd_chk_max = rsrvd_dma->brd_chk_cnt = 0;

	biod->bd_buffer_prep = 0;
}

struct bio_copy_args {
	/* DRAM sg lists to be copied to/from */
	d_sg_list_t	*ca_sgls;
	int		 ca_sgl_cnt;
	/* Current sgl index */
	int		 ca_sgl_idx;
	/* Current IOV index inside of current sgl */
	int		 ca_iov_idx;
	/* Current offset inside of current IOV */
	ssize_t		 ca_iov_off;
	/* Total size to be copied */
	unsigned int	 ca_size_tot;
	/* Copied size */
	unsigned int	 ca_size_copied;

};

// 将d_iov 中的数据拷贝到biov
static int
copy_one(struct bio_desc *biod, struct bio_iov *biov, void *data)
{
	// rdma 存储的bulk 数据或者是inline 模式下的sgls 数据
	struct bio_copy_args	*arg = data;
	d_sg_list_t		*sgl;
	void			*addr = bio_iov2req_buf(biov);
	ssize_t			 size = bio_iov2req_len(biov);
	uint16_t		 media = bio_iov2media(biov);

	if (bio_iov2req_len(biov) == 0)
		return 0;

	D_ASSERT(biod->bd_type < BIO_IOD_TYPE_GETBUF);
	D_ASSERT(arg->ca_sgl_idx < arg->ca_sgl_cnt);
	sgl = &arg->ca_sgls[arg->ca_sgl_idx];

	while (arg->ca_iov_idx < sgl->sg_nr) {
		// sgls 中的d_iov
		d_iov_t *iov;
		ssize_t nob, buf_len;

		iov = &sgl->sg_iovs[arg->ca_iov_idx];
		buf_len = (biod->bd_type == BIO_IOD_TYPE_UPDATE) ?
					iov->iov_len : iov->iov_buf_len;

		if (buf_len <= arg->ca_iov_off) {
			D_ERROR("Invalid iov[%d] "DF_U64"/"DF_U64" %d\n",
				arg->ca_iov_idx, arg->ca_iov_off,
				buf_len, biod->bd_type);
			return -DER_INVAL;
		}

		if (iov->iov_buf == NULL) {
			D_ERROR("Invalid iov[%d], iov_buf is NULL\n",
				arg->ca_iov_idx);
			return -DER_INVAL;
		}

		nob = min(size, buf_len - arg->ca_iov_off);
		if (arg->ca_size_tot) {
			if ((nob + arg->ca_size_copied) > arg->ca_size_tot) {
				D_ERROR("Copy size %u is not aligned with IOVs %u/"DF_U64"\n",
					arg->ca_size_tot, arg->ca_size_copied, nob);
				return -DER_INVAL;
			}
			arg->ca_size_copied += nob;
		}

		if (addr != NULL) {
			D_DEBUG(DB_TRACE, "bio copy %p size %zd\n",
				addr, nob);
			// 在addr 和 iov->iov_buf + arg->ca_iov_off 两个地址之间拷贝数据
			// bio_iov 和 d_iov_t 之间进行数据拷贝
			// 前者地址来自于传参与拷贝的 biov
			// 后者的地址来自于函数第三个 data 参数（sgls）里面的 d_iov_t
			bio_memcpy(biod, media, addr, iov->iov_buf +
					arg->ca_iov_off, nob);
			addr += nob;
		} else {
			/* fetch on hole */
			D_ASSERT(biod->bd_type == BIO_IOD_TYPE_FETCH);
		}

		arg->ca_iov_off += nob;
		if (biod->bd_type == BIO_IOD_TYPE_FETCH) {
			/* the first population for fetch */
			if (arg->ca_iov_off == nob)
				sgl->sg_nr_out++;

			iov->iov_len = arg->ca_iov_off;
			/* consumed an iov, move to the next */
			if (iov->iov_len == iov->iov_buf_len) {
				arg->ca_iov_off = 0;
				arg->ca_iov_idx++;
			}
		} else {
			/* consumed an iov, move to the next */
			if (arg->ca_iov_off == iov->iov_len) {
				arg->ca_iov_off = 0;
				arg->ca_iov_idx++;
			}
		}

		/* Specified copy size finished, abort */
		if (arg->ca_size_tot && (arg->ca_size_copied == arg->ca_size_tot))
			return 1;

		size -= nob;
		if (size == 0)
			return 0;
	}

	D_DEBUG(DB_TRACE, "Consumed all iovs, "DF_U64" bytes left\n", size);
	return -DER_REC2BIG;
}

static int
iterate_biov(struct bio_desc *biod,
	     int (*cb_fn)(struct bio_desc *, struct bio_iov *, void *data),
	     void *data)
{
	// 遍历所有的sgls，再遍历sgls 下的所有biov，然后对每个biov 执行对应的cb 函数（bulk_map_one 或者dma_map_one）
	// data 是表示当前biod 里面是否有bulk 数据
	int i, j, rc = 0;

	// 遍历所有的sgl list的数组，每个元素都是一个sgl list
	for (i = 0; i < biod->bd_sgl_cnt; i++) {
		// 遍历里面所有的bio sgls 下面的biov
		// 在这之前所有的数据都是存储在d_sgls 的d_iov 里面的
		struct bio_sglist *bsgl = &biod->bd_sgls[i];

		if (data != NULL) {
			// bulk 数据或者是sgls 数据拷贝
			if (cb_fn == copy_one) {
				struct bio_copy_args *arg = data;

				D_ASSERT(i < arg->ca_sgl_cnt);
				arg->ca_sgl_idx = i;
				arg->ca_iov_idx = 0;
				arg->ca_iov_off = 0;
				if (biod->bd_type == BIO_IOD_TYPE_FETCH)
					arg->ca_sgls[i].sg_nr_out = 0;
			} else if (cb_fn == bulk_map_one) {
				// bulk 数据用的这个cb 函数
				struct bio_bulk_args *arg = data;

				// 设置当前sgl list 的idx
				arg->ba_sgl_idx = i;
			}
		}

		// 没有io 的slg list 直接跳过
		if (bsgl->bs_nr_out == 0)
			continue;

		// 对当前sgl list，对里面所有的io 执行cb 函数
		for (j = 0; j < bsgl->bs_nr_out; j++) {
			struct bio_iov *biov = &bsgl->bs_iovs[j];
			// 如果是bulk 数据，那么 cb_fn == bulk_map_one，否则cb_fn == dma_map_one，或者copy_one
			// 实际上就是在处理所有的biov，iov 是存储在sgl list 中的，而这里biod 的bd_sgls 是sgl list 的一个数组
			// 本质是rdma vs inline 传输方式
			rc = cb_fn(biod, biov, data);
			if (rc)
				break;
		}
		if (rc)
			break;
	}

	return rc;
}

static void *
chunk_reserve(struct bio_dma_chunk *chk, unsigned int chk_pg_idx,
	      unsigned int pg_cnt, unsigned int pg_off)
{
	D_ASSERT(chk != NULL);

	/* Huge chunk is dedicated for single huge IOV */
	if (dma_chunk_is_huge(chk))
		return NULL;

	D_ASSERTF(chk->bdc_pg_idx <= bio_chk_sz, "%u > %u\n",
		  chk->bdc_pg_idx, bio_chk_sz);

	D_ASSERTF(chk_pg_idx == chk->bdc_pg_idx ||
		  (chk_pg_idx + 1) == chk->bdc_pg_idx, "%u, %u\n",
		  chk_pg_idx, chk->bdc_pg_idx);

	/* The chunk doesn't have enough unused pages */
	if (chk_pg_idx + pg_cnt > bio_chk_sz)
		return NULL;

	D_DEBUG(DB_TRACE, "Reserved on chunk:%p[%p], idx:%u, cnt:%u, off:%u\n",
		chk, chk->bdc_ptr, chk_pg_idx, pg_cnt, pg_off);

	chk->bdc_pg_idx = chk_pg_idx + pg_cnt;
	return chk->bdc_ptr + (chk_pg_idx << BIO_DMA_PAGE_SHIFT) + pg_off;
}

static inline struct bio_rsrvd_region *
iod_last_region(struct bio_desc *biod)
{
	unsigned int cnt = biod->bd_rsrvd.brd_rg_cnt;

	D_ASSERT(!cnt || cnt <= biod->bd_rsrvd.brd_rg_max);
	return (cnt != 0) ? &biod->bd_rsrvd.brd_regions[cnt - 1] : NULL;
}

static int
chunk_get_idle(struct bio_dma_buffer *bdb, struct bio_dma_chunk **chk_ptr)
{
	struct bio_dma_chunk *chk;
	int rc;

	if (d_list_empty(&bdb->bdb_idle_list)) {
		/* Try grow buffer first */
		if (bdb->bdb_tot_cnt < bio_chk_cnt_max) {
			rc = dma_buffer_grow(bdb, 1);
			if (rc == 0)
				goto done;
		}

		/* Try to reclaim an unused chunk from bulk groups */
		rc = bulk_reclaim_chunk(bdb, NULL);
		if (rc)
			return rc;
	}
done:
	D_ASSERT(!d_list_empty(&bdb->bdb_idle_list));
	chk = d_list_entry(bdb->bdb_idle_list.next, struct bio_dma_chunk,
			   bdc_link);
	d_list_move_tail(&chk->bdc_link, &bdb->bdb_used_list);
	*chk_ptr = chk;

	return 0;
}

static int
iod_add_chunk(struct bio_desc *biod, struct bio_dma_chunk *chk)
{
	struct bio_rsrvd_dma *rsrvd_dma = &biod->bd_rsrvd;
	unsigned int max, cnt;

	max = rsrvd_dma->brd_chk_max;
	cnt = rsrvd_dma->brd_chk_cnt;

	if (cnt == max) {
		struct bio_dma_chunk **chunks;
		int size = sizeof(struct bio_dma_chunk *);
		unsigned new_cnt = cnt + 10;

		D_ALLOC_ARRAY(chunks, new_cnt);
		if (chunks == NULL)
			return -DER_NOMEM;

		if (max != 0) {
			memcpy(chunks, rsrvd_dma->brd_dma_chks, max * size);
			D_FREE(rsrvd_dma->brd_dma_chks);
		}

		rsrvd_dma->brd_dma_chks = chunks;
		rsrvd_dma->brd_chk_max = new_cnt;
	}

	chk->bdc_ref++;
	// 新申请的chunk 添加到biod 里面rsrvd_dma 上（预留的dma buffer，里面存储的都是chunk）
	rsrvd_dma->brd_dma_chks[cnt] = chk;
	rsrvd_dma->brd_chk_cnt++;
	return 0;
}

int
iod_add_region(struct bio_desc *biod, struct bio_dma_chunk *chk,
	       unsigned int chk_pg_idx, unsigned int chk_off, uint64_t off,
	       uint64_t end, uint8_t media)
{
	struct bio_rsrvd_dma *rsrvd_dma = &biod->bd_rsrvd;
	unsigned int max, cnt;

	max = rsrvd_dma->brd_rg_max;
	cnt = rsrvd_dma->brd_rg_cnt;

	// 预留dma buffer 数量满了
	if (cnt == max) {
		// 新创建一个region
		struct bio_rsrvd_region *rgs;
		int size = sizeof(struct bio_rsrvd_region);
		// 满了，扩20个region的空间
		unsigned new_cnt = cnt + 20;

		D_ALLOC_ARRAY(rgs, new_cnt);
		if (rgs == NULL)
			return -DER_NOMEM;

		if (max != 0) {
			// 把原来的拷贝出来，再释放掉原来的空间
			memcpy(rgs, rsrvd_dma->brd_regions, max * size);
			D_FREE(rsrvd_dma->brd_regions);
		}

		// 指向新申请出来的空间，并重新设置大小
		rsrvd_dma->brd_regions = rgs;
		rsrvd_dma->brd_rg_max = new_cnt;
	}

	// 直接在尾巴填充新创建的region
	// 这些信息在最终读写nvme 的时候要用来决定读写地址
	rsrvd_dma->brd_regions[cnt].brr_chk = chk;
	// spdk_blob_io_read/write 会使用到 brr_pg_idx 来确定要读写的数据的buffer 地址，同时要用到off 来决定数据要写到blob 的哪里
	// 实际存储数据的buffer 地址，后面到dma_rw 里会用这个来找payload 完成读写操作
	rsrvd_dma->brd_regions[cnt].brr_pg_idx = chk_pg_idx;
	rsrvd_dma->brd_regions[cnt].brr_chk_off = chk_off;
	// 是根据biov 计算出来的 dma_biov2pg
	// todo: 这个预留出来的空间有什么说法，为啥这个object 要存在这里，而那个object 要存在那里？
	// 当前数据需要存储到的blob 的offset
	// off 在函数 nvme_rw 中会用到
	rsrvd_dma->brd_regions[cnt].brr_off = off;
	rsrvd_dma->brd_regions[cnt].brr_end = end;
	rsrvd_dma->brd_regions[cnt].brr_media = media;
	rsrvd_dma->brd_rg_cnt++;

	if (media == DAOS_MEDIA_NVME)
		// 追加新的region 存储的数据长度
		biod->bd_nvme_bytes += (end - off);

	return 0;
}

static inline bool
direct_scm_access(struct bio_desc *biod, struct bio_iov *biov)
{
	/* Get buffer operation */
	// todo: 这个是fetch/update 之外的什么场景
	if (biod->bd_type == BIO_IOD_TYPE_GETBUF)
		return false;

	// 如果当前的读写media 不是scm，返回false
	if (bio_iov2media(biov) != DAOS_MEDIA_SCM)
		return false;
	/*
	 * Direct access SCM when:
	 *
	 * - It's inline I/O, or;
	 * - Direct SCM RDMA enabled, or;
	 * - It's deduped SCM extent;
	 */
	// 如果当前的media 是scm：
	// 1. 当前是inline io（非bulk io），有bulk 数据的就是rdma
	if (!biod->bd_rdma || bio_scm_rdma)
		return true;

	// 2. deduped scm extent，这个是什么场景
	if (BIO_ADDR_IS_DEDUP(&biov->bi_addr)) {
		D_ASSERT(biod->bd_type == BIO_IOD_TYPE_UPDATE);
		return true;
	}

	return false;
}

static bool
iod_expand_region(struct bio_iov *biov, struct bio_rsrvd_region *last_rg,
		  uint64_t off, uint64_t end, unsigned int pg_cnt, unsigned int pg_off)
{
	uint64_t		cur_pg, prev_pg_start, prev_pg_end;
	unsigned int		chk_pg_idx;
	struct bio_dma_chunk	*chk = last_rg->brr_chk;

	chk_pg_idx = last_rg->brr_pg_idx;
	D_ASSERT(chk_pg_idx < bio_chk_sz);

	prev_pg_start = last_rg->brr_off >> BIO_DMA_PAGE_SHIFT;
	prev_pg_end = last_rg->brr_end >> BIO_DMA_PAGE_SHIFT;
	cur_pg = off >> BIO_DMA_PAGE_SHIFT;
	D_ASSERT(prev_pg_start <= prev_pg_end);

	/* Only merge NVMe regions */
	if (bio_iov2media(biov) == DAOS_MEDIA_SCM ||
	    bio_iov2media(biov) != last_rg->brr_media)
		return false;

	/* Not consecutive with prev rg */
	if (cur_pg != prev_pg_end)
		return false;

	D_DEBUG(DB_TRACE, "merging IOVs: ["DF_U64", "DF_U64"), ["DF_U64", "DF_U64")\n",
		last_rg->brr_off, last_rg->brr_end, off, end);

	if (last_rg->brr_off < off)
		chk_pg_idx += (prev_pg_end - prev_pg_start);
	else
		/* The prev region must be covered by one page */
		D_ASSERTF(prev_pg_end == prev_pg_start,
			  ""DF_U64" != "DF_U64"\n", prev_pg_end, prev_pg_start);

	bio_iov_set_raw_buf(biov, chunk_reserve(chk, chk_pg_idx, pg_cnt, pg_off));
	if (bio_iov2raw_buf(biov) == NULL)
		return false;

	if (off < last_rg->brr_off)
		last_rg->brr_off = off;
	if (end > last_rg->brr_end)
		last_rg->brr_end = end;

	D_DEBUG(DB_TRACE, "Consecutive reserve %p.\n", bio_iov2raw_buf(biov));
	return true;
}

static bool
iod_pad_region(struct bio_iov *biov, struct bio_rsrvd_region *last_rg, unsigned int *chk_off)
{
	struct bio_dma_chunk	*chk = last_rg->brr_chk;
	unsigned int		 chk_pg_idx = last_rg->brr_pg_idx;
	unsigned int		 off, pg_off;
	void			*payload;

	if (bio_iov2media(biov) != DAOS_MEDIA_SCM ||
	    last_rg->brr_media != DAOS_MEDIA_SCM)
		return false;

	D_ASSERT(last_rg->brr_end > last_rg->brr_off);
	off = last_rg->brr_chk_off + (last_rg->brr_end - last_rg->brr_off);
	pg_off = off & (BIO_DMA_PAGE_SZ - 1);

	/* The last page is used up */
	if (pg_off == 0)
		return false;

	/* The last page doesn't have enough free space */
	if (pg_off + bio_iov2raw_len(biov) > BIO_DMA_PAGE_SZ)
		return false;

	payload = chk->bdc_ptr + (chk_pg_idx << BIO_DMA_PAGE_SHIFT) + off;
	bio_iov_set_raw_buf(biov, payload);
	*chk_off = off;	/* Set for current region */

	D_DEBUG(DB_TRACE, "Padding reserve %p.\n", bio_iov2raw_buf(biov));
	return true;
}

/* Convert offset of @biov into memory pointer */
// 将offset 转化为内存指针
// todo: 这个函数以及bulk_map_one 的含义作用
int
dma_map_one(struct bio_desc *biod, struct bio_iov *biov, void *arg)
{
	struct bio_rsrvd_region *last_rg;
	struct bio_dma_buffer *bdb;
	struct bio_dma_chunk *chk = NULL, *cur_chk;
	// 后面确定数据存放地址的主要是通过off 和chk_pg_idx 来确定的
	uint64_t off, end;
	unsigned int pg_cnt, pg_off, chk_pg_idx, chk_off = 0;
	int rc;

	// 非bulk 场景，arg 为NULL
	D_ASSERT(arg == NULL);
	D_ASSERT(biov);
	D_ASSERT(biod && biod->bd_chk_type < BIO_CHK_TYPE_MAX);

	// 如果为空或者为hole，直接返回
	if ((bio_iov2raw_len(biov) == 0) || bio_addr_is_hole(&biov->bi_addr)) {
		// todo: 这个函数就是为当前的biov 关联存储的地址的
		bio_iov_set_raw_buf(biov, NULL);
		return 0;
	}

	// todo: 这个是什么场景
	if (direct_scm_access(biod, biov)) {
		struct umem_instance *umem = biod->bd_umem;

		D_ASSERT(umem != NULL);
		// todo: 将这个biov 存储到pmem 的这个地址上
		bio_iov_set_raw_buf(biov, umem_off2ptr(umem, bio_iov2raw_off(biov)));
		return 0;
	}
	D_ASSERT(!BIO_ADDR_IS_DEDUP(&biov->bi_addr));

	// 先获取xs ctx 的 dma buffer
	bdb = iod_dma_buf(biod);
	// biov 转化成page
	// 现在要根据biov 数据的大小，申请相应的资源
	// spdk_blob_io_write 时用到的off，是和当前off 有关联的
	// off 在此根据biov 被初始化
	dma_biov2pg(biov, &off, &end, &pg_cnt, &pg_off);

	/*
	 * For huge IOV, we'll bypass our per-xstream DMA buffer cache and
	 * allocate chunk from the SPDK reserved huge pages directly, this
	 * kind of huge chunk will be freed immediately on I/O completion.
	 *
	 * We assume the contiguous huge IOV is quite rare, so there won't
	 * be high contention over the SPDK huge page cache.
	 */
	// todo: 这里就是决定为什么这个object 要存放在这个硬盘，而那个object 要存放在那个硬盘？
	// 对于巨大的iov，将绕过xs dma buffer 缓存（这个就是之前reserve 的资源），直接从spdk 申请的大页上申请chunk，这些chunk将在io 完成后立即释放
	// 我们假设连续的大iov是很罕见的，所以不会有spdk 大页缓存上的激烈竞争
	// 这里的page 就是biov 转化后的数据
	if (pg_cnt > bio_chk_sz) {
		// 申请一个新的chunk（可以理解为大块资源）。从spdk 或者posix 接口申请
		chk = dma_alloc_chunk(pg_cnt);
		if (chk == NULL)
			return -DER_NOMEM;

		chk->bdc_type = biod->bd_chk_type;
		// 将申请好的大块资源chunk 添加到biod 的rsrvd_dma 中（里面存了chunk 和region 两个数组） 
		rc = iod_add_chunk(biod, chk);
		if (rc) {
			// 如果添加失败了，就把这个chunk 释放
			dma_free_chunk(chk);
			return rc;
		}

		// 更新当前biov dma buffer 地址（对于spdk 来说是dma buffer，对于scm 来说是实际内存地址）
		// todo: 为啥是chunk 的base 地址 + pg_off
		// todo: 将biov存储到这个硬盘的这个地址上
		bio_iov_set_raw_buf(biov, chk->bdc_ptr + pg_off);
		chk_pg_idx = 0;

		D_DEBUG(DB_IO, "Huge chunk:%p[%p], cnt:%u, off:%u\n",
			chk, chk->bdc_ptr, pg_cnt, pg_off);

		// chunk 创建完 & 添加到biod 上后直接add region 到biod
		goto add_region;
	}

	// iov 不够大，直接使用已经预留的空间，这里先获取最后一个region
	last_rg = iod_last_region(biod);

	/* First, try consecutive reserve from the last reserved region */
	// 从最后一个region 获取连续的预留空间
	if (last_rg) {
		D_DEBUG(DB_TRACE, "Last region %p:%d ["DF_U64","DF_U64")\n",
			last_rg->brr_chk, last_rg->brr_pg_idx,
			last_rg->brr_off, last_rg->brr_end);

		// 根据region 获取所在的chunk
		chk = last_rg->brr_chk;
		D_ASSERT(biod->bd_chk_type == chk->bdc_type);

		/* Expand the last NVMe region when it's contiguous with current NVMe region. */
		// 扩展最后一个region，扩展完直接返回
		if (iod_expand_region(biov, last_rg, off, end, pg_cnt, pg_off))
			return 0;

		/*
		 * If prev region is SCM having unused bytes in last chunk page, try to reserve
		 * from the unused bytes for current SCM region.
		 */
		// todo: 什么情况下会扩展失败？
		if (iod_pad_region(biov, last_rg, &chk_off)) {
			chk_pg_idx = last_rg->brr_pg_idx;
			goto add_region;
		}
	}

	/* Try to reserve from the last DMA chunk in io descriptor */
	// 尝试从最后一个dma chunk 预留资源
	if (chk != NULL) {
		D_ASSERT(biod->bd_chk_type == chk->bdc_type);
		chk_pg_idx = chk->bdc_pg_idx;
		bio_iov_set_raw_buf(biov, chunk_reserve(chk, chk_pg_idx,
							pg_cnt, pg_off));
		if (bio_iov2raw_buf(biov) != NULL) {
			D_DEBUG(DB_IO, "Last chunk reserve %p.\n",
				bio_iov2raw_buf(biov));
			goto add_region;
		}
	}

	/*
	 * Try to reserve the DMA buffer from the 'current chunk' of the
	 * per-xstream DMA buffer. It could be different with the last chunk
	 * in io descriptor, because dma_map_one() may yield in the future.
	 */
	cur_chk = bdb->bdb_cur_chk[biod->bd_chk_type];
	if (cur_chk != NULL && cur_chk != chk) {
		chk = cur_chk;
		chk_pg_idx = chk->bdc_pg_idx;
		bio_iov_set_raw_buf(biov, chunk_reserve(chk, chk_pg_idx,
							pg_cnt, pg_off));
		if (bio_iov2raw_buf(biov) != NULL) {
			D_DEBUG(DB_IO, "Current chunk reserve %p.\n",
				bio_iov2raw_buf(biov));
			goto add_chunk;
		}
	}

	/*
	 * Switch to another idle chunk, if there isn't any idle chunk
	 * available, grow buffer.
	 */
	// 切换到其他的可用chunk
	rc = chunk_get_idle(bdb, &chk);
	if (rc) {
		if (rc == -DER_AGAIN)
			biod->bd_retry = 1;
		else
			D_ERROR("Failed to get idle chunk. "DF_RC"\n", DP_RC(rc));

		return rc;
	}

	D_ASSERT(chk != NULL);
	chk->bdc_type = biod->bd_chk_type;
	bdb->bdb_cur_chk[chk->bdc_type] = chk;
	bdb->bdb_used_cnt[chk->bdc_type] += 1;
	if (bdb->bdb_stats.bds_chks_used[chk->bdc_type])
		d_tm_set_gauge(bdb->bdb_stats.bds_chks_used[chk->bdc_type],
			       bdb->bdb_used_cnt[chk->bdc_type]);
	chk_pg_idx = chk->bdc_pg_idx;

	D_ASSERT(chk_pg_idx == 0);
	bio_iov_set_raw_buf(biov,
			    chunk_reserve(chk, chk_pg_idx, pg_cnt, pg_off));
	if (bio_iov2raw_buf(biov) != NULL) {
		D_DEBUG(DB_IO, "New chunk reserve %p.\n",
			bio_iov2raw_buf(biov));
		goto add_chunk;
	}

	return -DER_OVERFLOW;

add_chunk:
	// todo: 还有一个add chunk
	// todo: 整体的布局是什么样子的？什么下面分的chunk，chunk下分的region，extent和blob，blob上面还有blobstore
	// 还有page等，还有bulk，，，，，，
	rc = iod_add_chunk(biod, chk);
	if (rc) {
		/* Revert the reservation in chunk */
		D_ASSERT(chk->bdc_pg_idx >= pg_cnt);
		chk->bdc_pg_idx -= pg_cnt;
		return rc;
	}
add_region:
	// 依赖新创建的chunk 添加新的region
	// dma map 里也可能会add region
	// chk_pg_idx 是描述chunk 下的page 起始页的
	return iod_add_region(biod, chk, chk_pg_idx, chk_off, off, end,
			      bio_iov2media(biov));
}

static inline bool
injected_nvme_error(struct bio_desc *biod)
{
	if (biod->bd_type == BIO_IOD_TYPE_UPDATE)
		return DAOS_FAIL_CHECK(DAOS_NVME_WRITE_ERR) != 0;
	else
		return DAOS_FAIL_CHECK(DAOS_NVME_READ_ERR) != 0;
}

static void
dma_drop_iod(struct bio_dma_buffer *bdb)
{
	D_ASSERT(bdb->bdb_active_iods > 0);
	bdb->bdb_active_iods--;
	if (bdb->bdb_stats.bds_active_iods)
		d_tm_set_gauge(bdb->bdb_stats.bds_active_iods, bdb->bdb_active_iods);

	ABT_mutex_lock(bdb->bdb_mutex);
	ABT_cond_broadcast(bdb->bdb_wait_iod);
	ABT_mutex_unlock(bdb->bdb_mutex);
}

static void
rw_completion(void *cb_arg, int err)
{
	struct bio_xs_context	*xs_ctxt;
	struct bio_xs_blobstore	*bxb;
	struct bio_io_context	*io_ctxt;
	struct bio_desc		*biod = cb_arg;
	struct media_error_msg	*mem;

	D_ASSERT(biod->bd_type < BIO_IOD_TYPE_GETBUF);
	D_ASSERT(biod->bd_inflights > 0);
	biod->bd_inflights--;

	bxb = biod->bd_ctxt->bic_xs_blobstore;
	D_ASSERT(bxb != NULL);
	D_ASSERT(bxb->bxb_blob_rw > 0);
	bxb->bxb_blob_rw--;

	io_ctxt = biod->bd_ctxt;
	D_ASSERT(io_ctxt != NULL);
	D_ASSERT(io_ctxt->bic_inflight_dmas > 0);
	io_ctxt->bic_inflight_dmas--;

	if (err != 0 || injected_nvme_error(biod)) {
		/* Report only one NVMe I/O error per IOD */
		if (biod->bd_result != 0)
			goto done;

		if (biod->bd_type == BIO_IOD_TYPE_FETCH || glb_criteria.fc_enabled)
			biod->bd_result = -DER_NVME_IO;
		else
			biod->bd_result = -DER_IO;

		D_ALLOC_PTR(mem);
		if (mem == NULL) {
			D_ERROR("NVMe I/O error report is skipped\n");
			goto done;
		}
		mem->mem_err_type = (biod->bd_type == BIO_IOD_TYPE_UPDATE) ? MET_WRITE : MET_READ;
		mem->mem_bs = bxb->bxb_blobstore;
		D_ASSERT(biod->bd_ctxt->bic_xs_ctxt);
		xs_ctxt = biod->bd_ctxt->bic_xs_ctxt;
		mem->mem_tgt_id = xs_ctxt->bxc_tgt_id;
		spdk_thread_send_msg(owner_thread(mem->mem_bs), bio_media_error, mem);
	}

done:
	if (biod->bd_inflights == 0) {
		iod_dma_completion(biod, err);
		if (biod->bd_async_post && biod->bd_buffer_prep) {
			iod_release_buffer(biod);
			dma_drop_iod(iod_dma_buf(biod));
		}
		D_DEBUG(DB_IO, "DMA complete, type:%d\n", biod->bd_type);
	}
}

void
bio_memcpy(struct bio_desc *biod, uint16_t media, void *media_addr,
	   void *addr, ssize_t n)
{
	D_ASSERT(biod->bd_type < BIO_IOD_TYPE_GETBUF);
	// 如果是写scm
	if (biod->bd_type == BIO_IOD_TYPE_UPDATE && media == DAOS_MEDIA_SCM) {
		struct umem_instance *umem = biod->bd_umem;

		D_ASSERT(umem != NULL);
		/*
		 * We could do no_drain copy and rely on the tx commit to
		 * drain controller, however, test shows calling a persistent
		 * copy and drain controller here is faster.
		 */
		if (DAOS_ON_VALGRIND && umem_tx_inprogress(umem)) {
			/** Ignore the update to what is reserved block.
			 *  Ordinarily, this wouldn't be inside a transaction
			 *  but in MVCC tests, it can happen.
			 */
			umem_tx_xadd_ptr(umem, media_addr, n,
					 UMEM_XADD_NO_SNAPSHOT);
		}
		// todo: 这里和scm 读使用不同的copy 函数？
		umem_atomic_copy(umem, media_addr, addr, n, UMEM_RESERVED_MEM);
	} else {
		// 如果是写nvme
		if (biod->bd_type == BIO_IOD_TYPE_UPDATE)
			memcpy(media_addr, addr, n);
		else
			// 如果是读操作（读scm 或者nvme）。
			// todo: 读scm 为啥不能使用和写scm 同样的copy 函数？ 
			memcpy(addr, media_addr, n);
	}
}

static void
scm_rw(struct bio_desc *biod, struct bio_rsrvd_region *rg)
{
	struct umem_instance	*umem = biod->bd_umem;
	void			*payload;

	D_ASSERT(biod->bd_rdma);
	D_ASSERT(!bio_scm_rdma);
	D_ASSERT(umem != NULL);

	// 和nvme 一样，都是通过 rg->brr_pg_idx 来查找payload
	payload = rg->brr_chk->bdc_ptr + (rg->brr_pg_idx << BIO_DMA_PAGE_SHIFT);
	payload += rg->brr_chk_off;

	D_DEBUG(DB_IO, "SCM RDMA, type:%d payload:%p len:"DF_U64"\n",
		biod->bd_type, payload, rg->brr_end - rg->brr_off);

	// 写/读数据到payload，数据来源是 umem_off2ptr(umem, rg->brr_off)
	bio_memcpy(biod, DAOS_MEDIA_SCM, umem_off2ptr(umem, rg->brr_off),
		   payload, rg->brr_end - rg->brr_off);
}

static void
nvme_rw(struct bio_desc *biod, struct bio_rsrvd_region *rg)
{
	struct spdk_io_channel	*channel;
	struct spdk_blob	*blob;
	struct bio_xs_context	*xs_ctxt;
	uint64_t		 pg_idx, pg_cnt, rw_cnt;
	void			*payload;
	struct bio_xs_blobstore	*bxb = biod->bd_ctxt->bic_xs_blobstore;

	D_ASSERT(bxb != NULL);
	D_ASSERT(biod->bd_ctxt->bic_xs_ctxt);
	xs_ctxt = biod->bd_ctxt->bic_xs_ctxt;
	// todo: 这个blob 在ctx 里是怎么决定是哪个的，并且是怎么管理的
	// 使用biod 指定的blob
	// biod 里面有预留的存储数据的地址，还有操作对应的blob
	blob = biod->bd_ctxt->bic_blob;
	channel = bxb->bxb_io_channel;

	/* Bypass NVMe I/O, used by daos_perf for performance evaluation */
	if (daos_io_bypass & IOBP_NVME)
		return;

	/* No locking for BS state query here is tolerable */
	if (bxb->bxb_blobstore->bb_state == BIO_BS_STATE_FAULTY) {
		D_ERROR("Blobstore is marked as FAULTY.\n");
		if (biod->bd_type == BIO_IOD_TYPE_FETCH || glb_criteria.fc_enabled)
			biod->bd_result = -DER_NVME_IO;
		else
			biod->bd_result = -DER_IO;
		return;
	}

	if (!is_blob_valid(biod->bd_ctxt)) {
		D_ERROR("Blobstore is invalid. blob:%p, closing:%d\n",
			blob, biod->bd_ctxt->bic_closing);
		biod->bd_result = -DER_NO_HDL;
		return;
	}

	D_ASSERT(channel != NULL);
	D_ASSERT(rg->brr_chk_off == 0);
	// todo: 这里可以标记当前要写入的数据吗？
	// todo: buffer 是从哪里设置的
	// 和nvme 一样，都是通过 rg->brr_pg_idx 来查找payload
	payload = rg->brr_chk->bdc_ptr + (rg->brr_pg_idx << BIO_DMA_PAGE_SHIFT);
	// 根据rg 来准备pg_idx 和rw_cnt 用于具体的bio 读写
	// pg 相关信息是在iod prepare 阶段根据boid 的iov 转化过来的，对应函数：dma_biov2pg
	// todo: 研究下rg 的构造过程以及内部的brr_off 的赋值
	// off 是上游reserve 的offset 地址
	// 上游reserve 函数：vos_reserve_single / recx
	// 这里设置的off，函数：bio_buffer.c 中 iod_add_region
	// 追到底off 是在这里计算出来的：函数 dma_biov2pg
	pg_idx = rg->brr_off >> BIO_DMA_PAGE_SHIFT;
	pg_cnt = (rg->brr_end + BIO_DMA_PAGE_SZ - 1) >> BIO_DMA_PAGE_SHIFT;
	D_ASSERT(pg_cnt > pg_idx);
	pg_cnt -= pg_idx;

	// 每次写这么多页，根据dma 的页计算出来的
	while (pg_cnt > 0) {

		drain_inflight_ios(xs_ctxt, bxb);

		biod->bd_dma_issued = 1;
		biod->bd_inflights++;
		bxb->bxb_blob_rw++;
		biod->bd_ctxt->bic_inflight_dmas++;

		// 每次写入的最大sz 是bio_chk_sz，所以如果pg 比较大，就分多次读写，每次bio_chk_sz 这么大
		rw_cnt = (pg_cnt > bio_chk_sz) ? bio_chk_sz : pg_cnt;

		D_DEBUG(DB_IO, "%s blob:%p payload:%p, pg_idx:"DF_U64", pg_cnt:"DF_U64"/"DF_U64"\n",
			biod->bd_type == BIO_IOD_TYPE_UPDATE ? "Write" : "Read",
			blob, payload, pg_idx, pg_cnt, rw_cnt);

		D_ASSERT(biod->bd_type < BIO_IOD_TYPE_GETBUF);
		// nvme设备 都是通过spdk blob io 接口来完成读写的，ceph 里面的nvmedevice 是直接走的块接口
		// payload 是要参与读写的实际数据
		// 将由biov 转化过来的 pg 再次转化为读写单元，填入spdk bio api
		// spdk bio 接口
		// 依赖pg idx 和bio ctx 的 bic_io_unit，通过函数 spdk_bs_get_io_unit_size 来获取
		// todo: payload 是包含要写入数据的buffer
		// 这里相当于走的是封装好的blob 的接口，而不是底层的通用块设备的接口 spdk_nvme_ns_cmd_readv_ext(spdk_nvme_ns_cmd_writev)
		// blob 的write 接口，只需要指定blob 的起始io unit 的位置，和写入的数据length
		if (biod->bd_type == BIO_IOD_TYPE_UPDATE)
			spdk_blob_io_write(blob, channel, payload,
						// 根据三个参数决定：io unit, pg idx, dma_page_size
					   page2io_unit(biod->bd_ctxt, pg_idx, BIO_DMA_PAGE_SZ),
					   page2io_unit(biod->bd_ctxt, rw_cnt, BIO_DMA_PAGE_SZ),
					   rw_completion, biod);
		else {
			// todo: io unit 是怎么管理的，为什么能mapping 到对应的磁盘的位置
			// todo: 每个线程只创建了一个bs，同时对应一个blob 么
			spdk_blob_io_read(blob, channel, payload,
					  page2io_unit(biod->bd_ctxt, pg_idx, BIO_DMA_PAGE_SZ),
					  page2io_unit(biod->bd_ctxt, rw_cnt, BIO_DMA_PAGE_SZ),
					  rw_completion, biod);
			if (DAOS_ON_VALGRIND)
				VALGRIND_MAKE_MEM_DEFINED(payload, rw_cnt * BIO_DMA_PAGE_SZ);
		}

		pg_cnt -= rw_cnt;
		pg_idx += rw_cnt;
		// 一次写这么多页
		payload += (rw_cnt * BIO_DMA_PAGE_SZ);
	}
}

static void
dma_rw(struct bio_desc *biod)
{
	// rg 存储在biod 中，连续的dma buffer region
	// 先获取io 描述符下的bio dma buffer们。是dma buffer 的数组，其中每个元素都是一个dma buffer
	struct bio_rsrvd_dma	*rsrvd_dma = &biod->bd_rsrvd;
	// biod 中有dma buffer，dma buffer 是分region 存放的
	// biod --> dma buffer --> dma buffer region
	// 这些信息都是从biod 的sgls list 中获取到的
	struct bio_rsrvd_region	*rg;
	int			 i;

	biod->bd_inflights = 1;

	D_ASSERT(biod->bd_type < BIO_IOD_TYPE_GETBUF);
	D_DEBUG(DB_IO, "DMA start, type:%d\n", biod->bd_type);

	// 每个rg 是rsrvd_dma 的一个元素，是一个dma buffer region
	// 看下这些region 是在哪构建的
	for (i = 0; i < rsrvd_dma->brd_rg_cnt; i++) {
		// 从dma buffer io描述符获取rg 信息
		// todo: 在map 之后，要写入的数据已经存储到rg 中了吗？
		rg = &rsrvd_dma->brd_regions[i];

		D_ASSERT(rg->brr_chk != NULL);
		D_ASSERT(rg->brr_end > rg->brr_off);

		// 以rg 为单元完成读写
		if (rg->brr_media == DAOS_MEDIA_SCM)
			scm_rw(biod, rg);
		else
			// 向blob 中的rg 这里写入
			nvme_rw(biod, rg);
	}

	D_ASSERT(biod->bd_inflights > 0);
	biod->bd_inflights -= 1;

	if (!biod->bd_async_post) {
		iod_dma_wait(biod);
		D_DEBUG(DB_IO, "Wait DMA done, type:%d\n", biod->bd_type);
	}
}

static inline bool
iod_should_retry(struct bio_desc *biod, struct bio_dma_buffer *bdb)
{
	/*
	 * When there isn't any in-flight IODs, it means the whole DMA buffer
	 * isn't large enough to satisfy current huge IOD, don't retry.
	 *
	 * When current IOD is for copy target, take the source IOD into account.
	 */
	if (biod->bd_copy_dst) {
		D_ASSERT(bdb->bdb_active_iods >= 1);
		return bdb->bdb_active_iods > 1;
	}
	return bdb->bdb_active_iods != 0;
}

static inline void
iod_fifo_wait(struct bio_desc *biod, struct bio_dma_buffer *bdb)
{
	if (!biod->bd_in_fifo) {
		biod->bd_in_fifo = 1;
		D_ASSERT(bdb->bdb_queued_iods == 0);
		bdb->bdb_queued_iods = 1;
		if (bdb->bdb_stats.bds_queued_iods)
			d_tm_set_gauge(bdb->bdb_stats.bds_queued_iods, bdb->bdb_queued_iods);
	}

	/* First waiter in the FIFO queue waits on 'bdb_wait_iod' */
	ABT_mutex_lock(bdb->bdb_mutex);
	ABT_cond_wait(bdb->bdb_wait_iod, bdb->bdb_mutex);
	ABT_mutex_unlock(bdb->bdb_mutex);
}

static void
iod_fifo_in(struct bio_desc *biod, struct bio_dma_buffer *bdb)
{
	// 优先级别较高的不会进入到这个队列，比如check pointing
	/* No prior waiters */
	// 如果没有更高优先级的任务需要等待
	if (!bdb || bdb->bdb_queued_iods == 0)
		return;
	/*
	 * Non-blocking prep request is usually from high priority job like checkpointing,
	 * so we allow it jump the queue.
	 */
	// 如果当前的no blocking 标记为true，那么说明优先级别较高，不进入队列
	if (biod->bd_non_blocking)
		return;

	// 否则的话说明当前请求的优先级一般，要进入到队列等待被唤醒
	biod->bd_in_fifo = 1;
	bdb->bdb_queued_iods++;
	if (bdb->bdb_stats.bds_queued_iods)
		d_tm_set_gauge(bdb->bdb_stats.bds_queued_iods, bdb->bdb_queued_iods);

	/* Except the first waiter, all other waiters in FIFO queue wait on 'bdb_fifo' */
	// 等待
	ABT_mutex_lock(bdb->bdb_mutex);
	// 在 iod_fifo_out 这个里面唤醒 mutex
	ABT_cond_wait(bdb->bdb_fifo, bdb->bdb_mutex);
	ABT_mutex_unlock(bdb->bdb_mutex);
}

static void
iod_fifo_out(struct bio_desc *biod, struct bio_dma_buffer *bdb)
{
	if (!biod->bd_in_fifo)
		return;

	biod->bd_in_fifo = 0;
	D_ASSERT(bdb != NULL);
	D_ASSERT(bdb->bdb_queued_iods > 0);
	bdb->bdb_queued_iods--;
	if (bdb->bdb_stats.bds_queued_iods)
		d_tm_set_gauge(bdb->bdb_stats.bds_queued_iods, bdb->bdb_queued_iods);

	/* Wakeup next one in the FIFO queue */
	if (bdb->bdb_queued_iods) {
		ABT_mutex_lock(bdb->bdb_mutex);
		ABT_cond_signal(bdb->bdb_fifo);
		ABT_mutex_unlock(bdb->bdb_mutex);
	}
}

#define	DMA_INFO_DUMP_INTVL	60	/* seconds */
static void
dump_dma_info(struct bio_dma_buffer *bdb)
{
	struct bio_bulk_cache	*bbc = &bdb->bdb_bulk_cache;
	struct bio_bulk_group	*bbg;
	uint64_t		 cur;
	int			 i, bulk_grps = 0, bulk_chunks = 0;

	cur = daos_gettime_coarse();
	if ((bdb->bdb_dump_ts + DMA_INFO_DUMP_INTVL) > cur)
		return;

	bdb->bdb_dump_ts = cur;
	D_EMIT("DMA buffer isn't sufficient to sustain current workload, "
	       "enlarge the nr_hugepages in server YAML if possible.\n");

	D_EMIT("chk_size:%u, tot_chk:%u/%u, active_iods:%u, queued_iods:%u, used:%u,%u,%u\n",
	       bio_chk_sz, bdb->bdb_tot_cnt, bio_chk_cnt_max, bdb->bdb_active_iods,
	       bdb->bdb_queued_iods, bdb->bdb_used_cnt[BIO_CHK_TYPE_IO],
	       bdb->bdb_used_cnt[BIO_CHK_TYPE_LOCAL], bdb->bdb_used_cnt[BIO_CHK_TYPE_REBUILD]);

	/* cached bulk info */
	for (i = 0; i < bbc->bbc_grp_cnt; i++) {
		bbg = &bbc->bbc_grps[i];

		if (bbg->bbg_chk_cnt == 0)
			continue;

		bulk_grps++;
		bulk_chunks += bbg->bbg_chk_cnt;

		D_EMIT("bulk_grp %d: bulk_size:%u, chunks:%u\n",
		       i, bbg->bbg_bulk_pgs, bbg->bbg_chk_cnt);
	}
	D_EMIT("bulk_grps:%d, bulk_chunks:%d\n", bulk_grps, bulk_chunks);
}

// todo: map 是指做什么映射 ？
static int
iod_map_iovs(struct bio_desc *biod, void *arg)
{
	// arg 是继承自bulk args 的参数，表示是否有bulk 大块数据
	// 新建一个biod dma buffer
	struct bio_dma_buffer	*bdb;
	int			 rc, retry_cnt = 0;

	/* NVMe context isn't allocated */
	// 赋值dma buffer
	if (biod->bd_ctxt->bic_xs_ctxt == NULL)
		bdb = NULL;
	else
		bdb = iod_dma_buf(biod);

	// todo: 加入什么队列，在mutex 上阻塞
	// todo: 在这里入队列，在下面出队列，整个队列里一直最多只有一个item 吗？
	iod_fifo_in(biod, bdb);
retry:
	// 构建dma buffer region。走 bulk_map_one，里面可能会调用 dma_map_one
	// 这里根据arg 构建biod
	// 向biod 中添加region 的逻辑只在bulk_map_one 和dma_map_one 这两个函数里面出现
	// biod dma buffer region 构建
	// arg 表示是否有bulk 数据，如果有的话就用 bulk_map_one，否则的话用dma_map_one 来做回调函数
	// 遍历处理biov 里面的所有sgls
	// 回调函数调用结构：cb_fn(biod, biov, data)，作用都是传入biod 和biov 做处理
	// 这里映射的含义是，将biov 中存储的数据，映射到scm 的内存或者spdk 的硬盘空间

	// NA_Mem_register 用于内存region 注册。调用函数：hg_bulk_register_segments 和 hg_bulk_register
	// 当前支持的所有na class:
	// ./na/na_ucx.c:887:    na_ucx_mem_register,                  /* mem_register */
	// ./na/na_mpi.c:428:    NULL,                                 /* mem_register */
	// ./na/na_psm.c:2612: *  - mem_register,mem_deregister: mem register not needed for psm I/O
	// ./na/na_psm.c:2656:    NULL,                                  /* mem_register */
	// ./na/na_bmi.c:484:    NULL,                                 /* mem_register */
	// ./na/na_sm.c:1123:    NULL,                                /* mem_register */
	// ./na/na_ofi.c:1752:    na_ofi_mem_register,                   /* mem_register */
	// ./na/na_cci.c:402:    na_cci_mem_register,                  /* mem_register */
	/*
	在 na/na.c 中实现
	NA_Mem_register(na_class_t *na_class, na_mem_handle_t *mem_handle,
		enum na_mem_type mem_type, uint64_t device)
	// 根据ops 对应的mem_register 函数
    na_class->ops->mem_register(na_class, mem_handle, mem_type, device);

	hg_bulk_register(na_class_t *na_class, void *base, size_t len,
    unsigned long flags, enum na_mem_type mem_type, uint64_t device,
    na_mem_handle_t **mem_handle_p, size_t *serialize_size_p)
	(内部会连续调用 NA_Mem_handle_create，NA_Mem_register，NA_Mem_handle_get_serialize_size。即创建hdl，注册和缓存序列化后的hdl)

	hg_bulk_register_segments(na_class_t *na_class, struct na_segment *segments,
    size_t count, unsigned long flags, enum na_mem_type mem_type,
    uint64_t device, na_mem_handle_t **mem_handle_p, size_t *serialize_size_p)

	hg_bulk_create 中会调用 hg_bulk_register 和hg_bulk_register_segment
	hg_bulk_create(hg_core_class_t *core_class, hg_uint32_t count, void **bufs,
    const hg_size_t *lens, hg_uint8_t flags, const struct hg_bulk_attr *attrs,
    struct hg_bulk **hg_bulk_p)

	HG_Bulk_create 和 HG_Bulk_create_attr 中会调用 hg_bulk_create
	HG_Bulk_create(hg_class_t *hg_class, hg_uint32_t count, void **buf_ptrs,
    const hg_size_t *buf_sizes, hg_uint8_t flags, hg_bulk_t *handle)

	HG_Bulk_create_attr(hg_class_t *hg_class, hg_uint32_t count, void **buf_ptrs,
    const hg_size_t *buf_sizes, hg_uint8_t flags,
    const struct hg_bulk_attr *attrs, hg_bulk_t *handle)

	hg_set_struct(struct hg_private_handle *hg_handle,
    const struct hg_proc_info *hg_proc_info, hg_op_t op, void *struct_ptr,
    hg_size_t *payload_size, hg_bool_t *more_data)

	HG_Forward(hg_handle_t handle, hg_cb_t callback, void *arg, void *in_struct);

	总结：memory region 整个注册过程从上到下调用过程：
	---条条大路通罗马---HG_Bulk_create --> hg_bulk_create
	---条条大路通罗马---HG_Forward --> hg_set_struct --> HG_Bulk_create --> hg_bulk_create --> hg_bulk_register --> NA_Mem_register --> na_class->ops->mem_register  -->na_ofi_mem_register

	na_ofi_mem_register 里面：
	1. register region：fi_mr_regattr
	2. attach mr to endpoint when provvider request it: fi_mr_bind & fi_mr_enable
	3. Retrieve key: fi_mr_key

	HG_Forward 函数的回调函数是通过 HG_Register() 来设置的，cb是通过执行HG_Trigger 函数来执行的。HG_Forward函数是非阻塞的。
	*/
	rc = iterate_biov(biod, arg ? bulk_map_one : dma_map_one, arg);
	if (rc) {
		/*
		 * To avoid deadlock, held buffers need be released
		 * before waiting for other active IODs.
		 */
		iod_release_buffer(biod);

		if (!biod->bd_retry)
			goto out;

		D_ASSERT(bdb != NULL);
		if (bdb->bdb_stats.bds_grab_errs)
			d_tm_inc_counter(bdb->bdb_stats.bds_grab_errs, 1);
		dump_dma_info(bdb);

		biod->bd_retry = 0;
		if (!iod_should_retry(biod, bdb)) {
			D_ERROR("Per-xstream DMA buffer isn't large enough "
				"to satisfy large IOD %p\n", biod);
			goto out;
		}

		if (biod->bd_non_blocking) {
			rc = -DER_AGAIN;
			goto out;
		}

		retry_cnt++;
		D_DEBUG(DB_IO, "IOD %p waits for active IODs. %d\n", biod, retry_cnt);

		iod_fifo_wait(biod, bdb);

		D_DEBUG(DB_IO, "IOD %p finished waiting. %d\n", biod, retry_cnt);

		goto retry;
	}

	// 打上buffer 准备好的标记
	biod->bd_buffer_prep = 1;
	if (retry_cnt && bdb->bdb_stats.bds_grab_retries)
		d_tm_set_gauge(bdb->bdb_stats.bds_grab_retries, retry_cnt);
out:
	// todo: 从队列中移除
	iod_fifo_out(biod, bdb);
	return rc;
}

int
iod_prep_internal(struct bio_desc *biod, unsigned int type, void *bulk_ctxt,
		  unsigned int bulk_perm)
{
	// 用于大块传输的参数
	struct bio_bulk_args	 bulk_arg;
	struct bio_dma_buffer	*bdb;
	void			*arg = NULL;
	int			 rc;

	if (biod->bd_buffer_prep)
		return -DER_INVAL;

	biod->bd_chk_type = type;
	/* For rebuild pull, the DMA buffer will be used as RDMA client */
	// 当前biod是否需要rdma传输（有bulk 数据就需要rdma 传输，否则直接inline transport）
	biod->bd_rdma = (bulk_ctxt != NULL) || (type == BIO_CHK_TYPE_REBUILD);

	// 如果是大块数据传输，那么构造对应的task 的参数
	if (bulk_ctxt != NULL && !(daos_io_bypass & IOBP_SRV_BULK_CACHE)) {
		// rpc 的crt ctx
		bulk_arg.ba_bulk_ctxt = bulk_ctxt;
		// 读写类型
		bulk_arg.ba_bulk_perm = bulk_perm;
		bulk_arg.ba_sgl_idx = 0;
		arg = &bulk_arg;
	}

	// 根据biod 里面的biov，构建dma buffer 和region等信息
	// 构建dma buffer region
	// 里面会执行biod add region 操作，在biod 下添加新的region（dma buffer） 
	// map 映射说的是将iovs 中的数据映射到boid 里面rsrvd_dma 中的bulk，chunk 或者region中，对应scm 的内存地址或者spdk 的硬盘地址
	// todo: 为啥不在mapping 的时候直接传输数据呢？
	rc = iod_map_iovs(biod, arg);
	if (rc)
		return rc;

	/* All direct SCM access, no DMA buffer prepared */
	// 这个biod 描述的所有的io 都是scm 访问
	// dma 访问指的是外设和存储器之间的数据传输
	if (biod->bd_rsrvd.brd_rg_cnt == 0)
		return 0;

	// 返回dma buff
	bdb = iod_dma_buf(biod);
	bdb->bdb_active_iods++;
	if (bdb->bdb_stats.bds_active_iods)
		d_tm_set_gauge(bdb->bdb_stats.bds_active_iods, bdb->bdb_active_iods);

	if (biod->bd_type < BIO_IOD_TYPE_GETBUF) {
		rc = ABT_eventual_create(0, &biod->bd_dma_done);
		if (rc != ABT_SUCCESS) {
			rc = -DER_NOMEM;
			goto failed;
		}
	}

	biod->bd_dma_issued = 0;
	biod->bd_inflights = 0;
	biod->bd_result = 0;

	/* Load data from media to buffer on read */
	// 如果当前请求是 fetch 请求，那么从media 加载数据，直接调用dma_rw 就结束了
	// 如果是update 请求，需要再通过 bio_iod_post_async 最后再进入到 dma_rw 里完成写操作
	// 上面已经完成了biov 到biod 的rsrvd_dma 数据映射，这里直接操作rsrvd_dma 就可以了
	if (biod->bd_type == BIO_IOD_TYPE_FETCH)
		dma_rw(biod);

	if (biod->bd_result) {
		rc = biod->bd_result;
		goto failed;
	}

	return 0;
failed:
	iod_release_buffer(biod);
	dma_drop_iod(bdb);
	return rc;
}

int
bio_iod_prep(struct bio_desc *biod, unsigned int type, void *bulk_ctxt,
	     unsigned int bulk_perm)
{
	// 如果传输的有大块数据，那么bulk_ctx 不为空，否则bulk_ctx 为NULL
	return iod_prep_internal(biod, type, bulk_ctxt, bulk_perm);
}

int
bio_iod_try_prep(struct bio_desc *biod, unsigned int type, void *bulk_ctxt,
		 unsigned int bulk_perm)
{
	if (biod->bd_type == BIO_IOD_TYPE_FETCH)
		return -DER_NOTSUPPORTED;

	biod->bd_non_blocking = 1;
	return iod_prep_internal(biod, type, bulk_ctxt, bulk_perm);
}

int
bio_iod_post(struct bio_desc *biod, int err)
{
	biod->bd_dma_issued = 0;
	biod->bd_inflights = 0;
	biod->bd_result = err;

	if (!biod->bd_buffer_prep) {
		biod->bd_result = -DER_INVAL;
		goto out;
	}

	/* No more actions for direct accessed SCM IOVs */
	if (biod->bd_rsrvd.brd_rg_cnt == 0) {
		iod_release_buffer(biod);
		goto out;
	}

	/* Land data from buffer to media on write */
	// 将buffer 中的数据落地到设备
	// todo: fetch 走哪里？
	if (err == 0 && biod->bd_type == BIO_IOD_TYPE_UPDATE)
		dma_rw(biod);

	if (biod->bd_inflights == 0) {
		if (biod->bd_buffer_prep) {
			iod_release_buffer(biod);
			dma_drop_iod(iod_dma_buf(biod));
		}
	}
out:
	if (!biod->bd_dma_issued && biod->bd_type == BIO_IOD_TYPE_UPDATE)
		iod_dma_completion(biod, biod->bd_result);
	return biod->bd_result;
}

int
bio_iod_post_async(struct bio_desc *biod, int err)
{
	/* Async post is for UPDATE only */
	if (biod->bd_type != BIO_IOD_TYPE_UPDATE)
		goto out;

	/* Async post is only for MD on SSD */
	if (!bio_nvme_configured(SMD_DEV_TYPE_META))
		goto out;
	/*
	 * When the value on data blob is too large, don't do async post to
	 * avoid calculating checksum for large values.
	 */
	if (biod->bd_nvme_bytes > bio_max_async_sz)
		goto out;

	biod->bd_async_post = 1;
out:
	return bio_iod_post(biod, err);
}

int
bio_iod_copy(struct bio_desc *biod, d_sg_list_t *sgls, unsigned int nr_sgl)
{
	struct bio_copy_args arg = { 0 };

	if (!biod->bd_buffer_prep)
		return -DER_INVAL;

	if (biod->bd_sgl_cnt != nr_sgl)
		return -DER_INVAL;

	// 这里是d_sgls 和d_iov
	arg.ca_sgls = sgls;
	arg.ca_sgl_cnt = nr_sgl;

	// 小块的数据处理流程。小块数都存储在sgls 结构里
	// 所以要遍历slg，依次处理每个sgl 下面的biov，对biov 执行cb 函数
	// copy_one(biod, biov, data);  其中 data == NULL
	return iterate_biov(biod, copy_one, &arg);
}

static int
flush_one(struct bio_desc *biod, struct bio_iov *biov, void *arg)
{
	struct umem_instance *umem = biod->bd_umem;

	D_ASSERT(arg == NULL);
	D_ASSERT(biov);
	D_ASSERT(umem != NULL);

	if (bio_iov2req_len(biov) == 0)
		return 0;

	if (bio_addr_is_hole(&biov->bi_addr))
		return 0;

	if (!direct_scm_access(biod, biov))
		return 0;

	D_ASSERT(bio_iov2raw_buf(biov) != NULL);
	umem_atomic_flush(umem, bio_iov2req_buf(biov),
		      bio_iov2req_len(biov));
	return 0;
}

void
bio_iod_flush(struct bio_desc *biod)
{
	D_ASSERT(biod->bd_buffer_prep);
	if (biod->bd_type == BIO_IOD_TYPE_UPDATE)
		iterate_biov(biod, flush_one, NULL);
}

/* To keep the passed in @bsgl_in intact, copy it to the bsgl attached in bio_desc */
static struct bio_sglist *
iod_dup_sgl(struct bio_desc *biod, struct bio_sglist *bsgl_in)
{
	struct bio_sglist	*bsgl;
	int			 i, rc;

	bsgl = bio_iod_sgl(biod, 0);

	rc = bio_sgl_init(bsgl, bsgl_in->bs_nr);
	if (rc)
		return NULL;

	for (i = 0; i < bsgl->bs_nr; i++) {
		D_ASSERT(bio_iov2req_buf(&bsgl_in->bs_iovs[i]) == NULL);
		D_ASSERT(bio_iov2req_len(&bsgl_in->bs_iovs[i]) != 0);
		bsgl->bs_iovs[i] = bsgl_in->bs_iovs[i];
	}
	bsgl->bs_nr_out = bsgl->bs_nr;

	return bsgl;
}

static int
bio_rwv(struct bio_io_context *ioctxt, struct bio_sglist *bsgl_in,
	d_sg_list_t *sgl, bool update)
{
	struct bio_sglist	*bsgl;
	struct bio_desc		*biod;
	int			 i, rc;

	for (i = 0; i < bsgl_in->bs_nr; i++) {
		if (bio_addr_is_hole(&bsgl_in->bs_iovs[i].bi_addr)) {
			D_ERROR("Read/write a hole isn't allowed\n");
			return -DER_INVAL;
		}
	}

	/* allocate blob I/O descriptor */
	biod = bio_iod_alloc(ioctxt, NULL, 1 /* single bsgl */,
			     update ? BIO_IOD_TYPE_UPDATE : BIO_IOD_TYPE_FETCH);
	if (biod == NULL)
		return -DER_NOMEM;

	bsgl = iod_dup_sgl(biod, bsgl_in);
	if (bsgl == NULL) {
		rc = -DER_NOMEM;
		goto out;
	}

	/* map the biov to DMA safe buffer, fill DMA buffer if read operation */
	rc = bio_iod_prep(biod, BIO_CHK_TYPE_LOCAL, NULL, 0);
	if (rc)
		goto out;

	for (i = 0; i < bsgl->bs_nr; i++)
		D_ASSERT(bio_iov2raw_buf(&bsgl->bs_iovs[i]) != NULL);

	rc = bio_iod_copy(biod, sgl, 1 /* single sgl */);
	if (rc)
		D_ERROR("Copy biod failed, "DF_RC"\n", DP_RC(rc));

	/* release DMA buffer, write data back to NVMe device for write */
	rc = bio_iod_post(biod, rc);

out:
	bio_iod_free(biod); /* also calls bio_sgl_fini */

	return rc;
}

int
bio_readv(struct bio_io_context *ioctxt, struct bio_sglist *bsgl,
	  d_sg_list_t *sgl)
{
	int	rc;

	rc = bio_rwv(ioctxt, bsgl, sgl, false);
	if (rc)
		D_ERROR("Readv to blob:%p failed for xs:%p, rc:%d\n",
			ioctxt->bic_blob, ioctxt->bic_xs_ctxt, rc);
	else
		D_DEBUG(DB_IO, "Readv to blob %p for xs:%p successfully\n",
			ioctxt->bic_blob, ioctxt->bic_xs_ctxt);

	return rc;
}

int
bio_writev(struct bio_io_context *ioctxt, struct bio_sglist *bsgl,
	   d_sg_list_t *sgl)
{
	int	rc;

	rc = bio_rwv(ioctxt, bsgl, sgl, true);
	if (rc)
		D_ERROR("Writev to blob:%p failed for xs:%p, rc:%d\n",
			ioctxt->bic_blob, ioctxt->bic_xs_ctxt, rc);
	else
		D_DEBUG(DB_IO, "Writev to blob %p for xs:%p successfully\n",
			ioctxt->bic_blob, ioctxt->bic_xs_ctxt);

	return rc;
}

static int
bio_rw(struct bio_io_context *ioctxt, bio_addr_t addr, d_iov_t *iov,
	bool update)
{
	struct bio_sglist	bsgl;
	struct bio_iov		biov;
	d_sg_list_t		sgl;
	int			rc;

	bio_iov_set(&biov, addr, iov->iov_len);
	bsgl.bs_iovs = &biov;
	bsgl.bs_nr = bsgl.bs_nr_out = 1;

	sgl.sg_iovs = iov;
	sgl.sg_nr = 1;
	sgl.sg_nr_out = 0;

	rc = bio_rwv(ioctxt, &bsgl, &sgl, update);
	if (rc)
		D_ERROR("%s to blob:%p failed for xs:%p, rc:%d\n",
			update ? "Write" : "Read", ioctxt->bic_blob,
			ioctxt->bic_xs_ctxt, rc);
	else
		D_DEBUG(DB_IO, "%s to blob %p for xs:%p successfully\n",
			update ? "Write" : "Read", ioctxt->bic_blob,
			ioctxt->bic_xs_ctxt);

	return rc;
}

int
bio_read(struct bio_io_context *ioctxt, bio_addr_t addr, d_iov_t *iov)
{
	return bio_rw(ioctxt, addr, iov, false);
}

int
bio_write(struct bio_io_context *ioctxt, bio_addr_t addr, d_iov_t *iov)
{
	return bio_rw(ioctxt, addr, iov, true);
}

struct bio_desc *
bio_buf_alloc(struct bio_io_context *ioctxt, unsigned int len, void *bulk_ctxt,
	      unsigned int bulk_perm)
{
	struct bio_sglist	*bsgl;
	struct bio_desc		*biod;
	unsigned int		 chk_type;
	int			 rc;

	biod = bio_iod_alloc(ioctxt, NULL, 1, BIO_IOD_TYPE_GETBUF);
	if (biod == NULL)
		return NULL;

	bsgl = bio_iod_sgl(biod, 0);
	rc = bio_sgl_init(bsgl, 1);
	if (rc)
		goto error;

	D_ASSERT(len > 0);
	bio_iov_set_len(&bsgl->bs_iovs[0], len);
	bsgl->bs_nr_out = bsgl->bs_nr;

	chk_type = (bulk_ctxt != NULL) ? BIO_CHK_TYPE_IO : BIO_CHK_TYPE_LOCAL;
	rc = bio_iod_prep(biod, chk_type, bulk_ctxt, bulk_perm);
	if (rc)
		goto error;

	return biod;
error:
	bio_iod_free(biod);
	return NULL;
}

void
bio_buf_free(struct bio_desc *biod)
{
	D_ASSERT(biod != NULL);
	D_ASSERT(biod->bd_type == BIO_IOD_TYPE_GETBUF);
	bio_iod_post(biod, 0);
	bio_iod_free(biod);
}

void *
bio_buf_bulk(struct bio_desc *biod, unsigned int *bulk_off)
{
	D_ASSERT(biod != NULL);
	D_ASSERT(biod->bd_type == BIO_IOD_TYPE_GETBUF);
	D_ASSERT(biod->bd_buffer_prep);

	return bio_iod_bulk(biod, 0, 0, bulk_off);
}

void *
bio_buf_addr(struct bio_desc *biod)
{
	struct bio_sglist	*bsgl;

	D_ASSERT(biod != NULL);
	D_ASSERT(biod->bd_type == BIO_IOD_TYPE_GETBUF);
	D_ASSERT(biod->bd_buffer_prep);

	bsgl = bio_iod_sgl(biod, 0);
	return bio_iov2buf(&bsgl->bs_iovs[0]);
}

struct bio_copy_desc {
	struct bio_desc		*bcd_iod_src;
	struct bio_desc		*bcd_iod_dst;
};

static void
free_copy_desc(struct bio_copy_desc *copy_desc)
{
	if (copy_desc->bcd_iod_src)
		bio_iod_free(copy_desc->bcd_iod_src);
	if (copy_desc->bcd_iod_dst)
		bio_iod_free(copy_desc->bcd_iod_dst);
	D_FREE(copy_desc);
}

static struct bio_copy_desc *
alloc_copy_desc(struct bio_io_context *ioctxt, struct umem_instance *umem,
		struct bio_sglist *bsgl_src, struct bio_sglist *bsgl_dst)
{
	struct bio_copy_desc	*copy_desc;
	struct bio_sglist	*bsgl_read, *bsgl_write;

	D_ALLOC_PTR(copy_desc);
	if (copy_desc == NULL)
		return NULL;

	copy_desc->bcd_iod_src = bio_iod_alloc(ioctxt, umem, 1, BIO_IOD_TYPE_FETCH);
	if (copy_desc->bcd_iod_src == NULL)
		goto free;

	copy_desc->bcd_iod_dst = bio_iod_alloc(ioctxt, umem, 1, BIO_IOD_TYPE_UPDATE);
	if (copy_desc->bcd_iod_dst == NULL)
		goto free;

	bsgl_read = iod_dup_sgl(copy_desc->bcd_iod_src, bsgl_src);
	if (bsgl_read == NULL)
		goto free;

	bsgl_write = iod_dup_sgl(copy_desc->bcd_iod_dst, bsgl_dst);
	if (bsgl_write == NULL)
		goto free;

	return copy_desc;
free:
	free_copy_desc(copy_desc);
	return NULL;
}

int
bio_copy_prep(struct bio_io_context *ioctxt, struct umem_instance *umem,
	      struct bio_sglist *bsgl_src, struct bio_sglist *bsgl_dst,
	      struct bio_copy_desc **desc)
{
	struct bio_copy_desc	*copy_desc;
	int			 rc, ret;

	copy_desc = alloc_copy_desc(ioctxt, umem, bsgl_src, bsgl_dst);
	if (copy_desc == NULL) {
		*desc = NULL;
		return -DER_NOMEM;
	}

	rc = bio_iod_prep(copy_desc->bcd_iod_src, BIO_CHK_TYPE_LOCAL, NULL, 0);
	if (rc)
		goto free;

	copy_desc->bcd_iod_dst->bd_copy_dst = 1;
	rc = bio_iod_prep(copy_desc->bcd_iod_dst, BIO_CHK_TYPE_LOCAL, NULL, 0);
	if (rc) {
		ret = bio_iod_post(copy_desc->bcd_iod_src, 0);
		D_ASSERT(ret == 0);
		goto free;
	}

	*desc = copy_desc;
	return 0;
free:
	free_copy_desc(copy_desc);
	*desc = NULL;
	return rc;
}

int
bio_copy_run(struct bio_copy_desc *copy_desc, unsigned int copy_size,
	     struct bio_csum_desc *csum_desc)
{
	struct bio_sglist	*bsgl_src;
	d_sg_list_t		 sgl_src;
	struct bio_copy_args	 arg = { 0 };
	int			 rc;

	/* TODO: Leverage DML or SPDK accel APIs to support cusm generation */
	if (csum_desc != NULL)
		return -DER_NOSYS;

	bsgl_src = bio_iod_sgl(copy_desc->bcd_iod_src, 0);
	rc = bio_sgl_convert(bsgl_src, &sgl_src);
	if (rc)
		return rc;

	arg.ca_sgls = &sgl_src;
	arg.ca_sgl_cnt = 1;
	arg.ca_size_tot = copy_size;
	rc = iterate_biov(copy_desc->bcd_iod_dst, copy_one, &arg);
	if (rc > 0)	/* Abort on reaching specified copy size */
		rc = 0;

	d_sgl_fini(&sgl_src, false);
	return rc;
}

int
bio_copy_post(struct bio_copy_desc *copy_desc, int err)
{
	int	rc;

	rc = bio_iod_post(copy_desc->bcd_iod_src, 0);
	D_ASSERT(rc == 0);
	rc = bio_iod_post(copy_desc->bcd_iod_dst, err);

	free_copy_desc(copy_desc);

	return rc;
}

struct bio_sglist *
bio_copy_get_sgl(struct bio_copy_desc *copy_desc, bool src)
{
	struct bio_desc	*biod;

	biod = src ? copy_desc->bcd_iod_src : copy_desc->bcd_iod_dst;
	D_ASSERT(biod != NULL);

	return bio_iod_sgl(biod, 0);
}

int
bio_copy(struct bio_io_context *ioctxt, struct umem_instance *umem,
	 struct bio_sglist *bsgl_src, struct bio_sglist *bsgl_dst,
	 unsigned int copy_size, struct bio_csum_desc *csum_desc)
{
	struct bio_copy_desc	*copy_desc;
	int			 rc;

	rc = bio_copy_prep(ioctxt, umem, bsgl_src, bsgl_dst, &copy_desc);
	if (rc)
		return rc;

	rc = bio_copy_run(copy_desc, copy_size, csum_desc);
	rc = bio_copy_post(copy_desc, rc);

	return rc;
}
