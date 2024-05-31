/**
 * (C) Copyright 2016-2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
/**
 * Server-side management API offering the following functionalities:
 * - manage storage allocation (PMEM files, disk partitions, ...)
 * - initialize pool and target service
 * - provide fault domains
 */

#ifndef __MGMT_SRV_H__
#define __MGMT_SRV_H__

/**
 * Common file names used by each layer to store persistent data
 */
// 每个engine 的每个pool 都会在pmem 上创建对应的rdb-pool 文件，以及和target 个数相等的vos-targtid 文件
#define	VOS_FILE	"vos-" /* suffixed by thread id */
#define	DSM_META_FILE	"meta"
#define RDB_FILE	"rdb-"

int
ds_mgmt_tgt_file(const uuid_t pool_uuid, const char *fname, int *idx,
		 char **fpath);
int
ds_mgmt_tgt_pool_iterate(int (*cb)(uuid_t uuid, void *arg), void *arg);

#endif /* __MGMT_SRV_H__ */
