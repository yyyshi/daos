/**
 * (C) Copyright 2020-2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

/*
 * This provides a simple example for how to access different DAOS objects.
 *
 * For more information on the DAOS object model, please visit this page:
 * https://docs.daos.io/latest/overview/storage/#daos-object
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mpi.h>
#include <daos.h>

/** local task information */
static char		node[128] = "unknown";
static daos_handle_t	poh;
static daos_handle_t	coh;
static int		rank, rankn;
#define FAIL(fmt, ...)						\
do {								\
	fprintf(stderr, "Process (%s): " fmt " aborting\n",	\
		node, ## __VA_ARGS__);				\
	exit(1);						\
} while (0)

#define	ASSERT(cond, ...)					\
do {								\
	if (!(cond))						\
		FAIL(__VA_ARGS__);				\
} while (0)

enum handleType {
	HANDLE_POOL,
	HANDLE_CO,
};

#define ENUM_DESC_BUF	512
#define ENUM_DESC_NR	5

enum {
	OBJ_DKEY,
	OBJ_AKEY
};

static void
dts_buf_render(char *buf, unsigned int buf_len)
{
	int	nr = 'z' - 'a' + 1;
	int	i;

	for (i = 0; i < buf_len - 1; i++) {
		int randv = rand() % (2 * nr);

		if (randv < nr)
			buf[i] = 'a' + randv;
		else
			buf[i] = 'A' + (randv - nr);
	}
	buf[i] = '\0';
}

static inline void
handle_share(daos_handle_t *hdl, int type)
{
	d_iov_t	ghdl = { NULL, 0, 0 };
	int	rc;

	if (rank == 0) {
		/** fetch size of global handle */
		if (type == HANDLE_POOL)
			rc = daos_pool_local2global(*hdl, &ghdl);
		else
			rc = daos_cont_local2global(*hdl, &ghdl);
		ASSERT(rc == 0, "local2global failed with %d", rc);
	}

	/** broadcast size of global handle to all peers */
	MPI_Bcast(&ghdl.iov_buf_len, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);

	/** allocate buffer for global pool handle */
	ghdl.iov_buf = malloc(ghdl.iov_buf_len);
	ghdl.iov_len = ghdl.iov_buf_len;

	if (rank == 0) {
		/** generate actual global handle to share with peer tasks */
		if (type == HANDLE_POOL)
			rc = daos_pool_local2global(*hdl, &ghdl);
		else
			rc = daos_cont_local2global(*hdl, &ghdl);
		ASSERT(rc == 0, "local2global failed with %d", rc);
	}

	/** broadcast global handle to all peers */
	MPI_Bcast(ghdl.iov_buf, ghdl.iov_len, MPI_BYTE, 0, MPI_COMM_WORLD);

	if (rank != 0) {
		/** unpack global handle */
		if (type == HANDLE_POOL) {
			/* NB: Only pool_global2local are different */
			rc = daos_pool_global2local(ghdl, hdl);
		} else {
			rc = daos_cont_global2local(poh, ghdl, hdl);
		}
		ASSERT(rc == 0, "global2local failed with %d", rc);
	}

	free(ghdl.iov_buf);

	MPI_Barrier(MPI_COMM_WORLD);
}

static void
enumerate_key(daos_handle_t oh, int *total_nr, daos_key_t *dkey, int key_type)
{
	char		*buf;
	daos_key_desc_t  kds[ENUM_DESC_NR];
	daos_anchor_t	 anchor = {0};
	d_sg_list_t	 sgl;
	d_iov_t		 sg_iov;
	int		 key_nr = 0;
	int		 rc;

	buf = malloc(ENUM_DESC_BUF);
	d_iov_set(&sg_iov, buf, ENUM_DESC_BUF);
	sgl.sg_nr		= 1;
	sgl.sg_nr_out		= 0;
	sgl.sg_iovs		= &sg_iov;

	while (!daos_anchor_is_eof(&anchor)) {
		uint32_t nr = ENUM_DESC_NR;

		memset(buf, 0, ENUM_DESC_BUF);
		if (key_type == OBJ_DKEY)
			rc = daos_obj_list_dkey(oh, DAOS_TX_NONE, &nr, kds,
						&sgl, &anchor, NULL);
		else
			rc = daos_obj_list_akey(oh, DAOS_TX_NONE, dkey, &nr,
						kds, &sgl, &anchor, NULL);
		ASSERT(rc == 0, "object list failed with %d", rc);
		if (nr == 0)
			continue;
		key_nr += nr;
	}

	*total_nr = key_nr;
}

#define KEYS 10
#define BUFLEN 1024

void
example_daos_key_array()
{
	daos_handle_t	oh;
	char		buf[BUFLEN], rbuf[BUFLEN];
	daos_obj_id_t	oid;
	d_iov_t		dkey;
	int		total_nr = 0;
	char		dkey_str[32] = {0};
	int		i, rc;

	if (rank == 0)
		printf("Example of DAOS Key array:\n");

	/*
	 * Set an object ID. This is chosen by the user.
	 *
	 * DAOS provides a unique 64 bit integer oid allocator that can be used
	 * for the oid.lo to allocate 1 or more unique oids in the
	 * container. Please see: daos_cont_alloc_oids();
	 */
	// 设置object id
	oid.hi = 0;
	oid.lo = 1;

	/*
	 * generate objid to encode feature flags and object class to the
	 * OID. The object class controls the sharding and redundancy of the
	 * object (replication, Erasure coding, no protection). In this case, we
	 * choose max striping with no data prorection - OC_SX.
	 */
	// oc 用于数据保护和sharding。传入container hdl，返回oid
	// 会把特性和obj class 编码到oid 里。其中class 决定分片和冗余策略
	daos_obj_generate_oid(coh, &oid, 0, OC_SX, 0, 0);

	/** open DAOS object */
	// simple test
	// 输入container hdl 和oid，打开一个obj，返回object hdl == oh。这里会查询元数据信息
	// todo: 如果layout 是根据oid 设置的，那么如果发生了数据移动，layout 是怎么变化的？
	rc = daos_obj_open(coh, oid, DAOS_OO_RW, &oh, NULL);
	// open 之后就可以读写了
	ASSERT(rc == 0, "object open failed with %d", rc);

	/*
	 * In this example, we will create an object with 10 dkeys, where each
	 * dkey has 1 akey, and and array with a 1k extent. A user can create as
	 * many dkeys as they like under a single object. All akeys and values
	 * under the same dkey are guaranteed to be colocated on the same
	 * storage target. There is no limitation on how many akeys that can be
	 * created under a single dkey or how many records can be stored under a
	 * single akey, other than the space available on a single target.
	 */

	// 这个例子里，我们创建一个含有10个dkey 的object，每个dkey 有1个akey。
	// 用户可以按照喜好创建他们喜欢的个数的dkey在一个object 中。
	// 同一个dkey 下的所有akey 和value 会保证被存储到同一个target上。
	// 在一个single dkey 上可以无限制的创建akey，一个akey 上可以无限制的创建records（除非存储空间不足）
	/*
	 * init buffer (for this example, we reuse the same buffer for all the
	 * updates just for simplicity.
	 */
	// 构建模拟写入的buffer数据
	// todo 这个buff 最大可以多少
	dts_buf_render(buf, BUFLEN);

	// 创建10 个dkey
	// todo: 一个object 下的10 个dkey 是什么布局的
	for (i = 0; i < KEYS; i++) {
		d_sg_list_t	sgl;
		// 这里是d_iov 后面会转化为biov 再持久化到设备
		d_iov_t		sg_iov;
		// todo: iod 到底能描述什么：根据iod 的akey 可以唯一获取一组extent
		daos_iod_t	iod;
		// 存储records，是extent 的数组
		daos_recx_t	recx;

		/** init dkey */
		sprintf(dkey_str, "dkey_%d", i);
		d_iov_set(&dkey, dkey_str, strlen(dkey_str));

		/*
		 * init scatter/gather. this describes data in your memory. in
		 * this case it's a single contiguous buffer, but this gives the
		 * ability to provide an iovec for segmented buffer in memory.
		 */
		// 构造sgl，存储的要写入的buffer 数据
		d_iov_set(&sg_iov, buf, BUFLEN);
		sgl.sg_nr		= 1;
		sgl.sg_nr_out		= 0;
		sgl.sg_iovs		= &sg_iov;

		/** init I/O descriptor */
		// 构造iod
		// todo: dkey 都不同，但是akey 一样，表示数据是怎么存储的？
		d_iov_set(&iod.iod_name, "akey", strlen("akey")); /** akey */

		/*
		 * number of extents in recx array, 1 means we are accessing a
		 * single contiguous extent. we can have segmented/partial
		 * access similar to an iovec for file offsets. Each process
		 * writes 1k extent contiguously: 0: 0, 1:1024, 2:2048, etc.
		 */
		// todo: 用户端是如何自定义存储相关的设置的
		// 1 表示一个extent，即recx 里面只有一个extent
		iod.iod_nr	= 1;
		// todo: record 的容量大小
		iod.iod_size	= 1; /** record size (1 byte array here) */
		// todo: extent
		// 每个extent 容量都是1k 大小
		recx.rx_nr	= BUFLEN; /** extent size */
		// todo: extent 的偏移量，每次偏移量都是 0 吗？
		recx.rx_idx	= rank * BUFLEN; /** extent offset */
		iod.iod_recxs	= &recx;
		iod.iod_type	= DAOS_IOD_ARRAY; /** value type of the akey */

		/*
		 * Update a dkey. In this case we have 1 akey under this dkey,
		 * hence 1 iod and 1 sgl. for multiple akey access, this
		 * function is used with an array of iods and sgls and the
		 * number of akeys passed as the nr (5th argument to this
		 * function.
		 */
		// 写入一个dkey，当前场景一个dkey 下有一个akey，因此对应1 个iod 和 1个sgl。
		// 对于多个akey 的场景，这个函数传递iods 和sgls 数组以及个数（参数5）作为函数参数
		// 在open 的时候根据hdl 创建了dc_object 并添加link 信息到了hash table。之后fetch / update 请求再通过hdl 查找对应的dc_object 来获取相关信息
		// todo: 创建layout 时候是根据dkey 的hash来通过jump 算法选择targets 的
		// todo: 也就是说同一个object下不同的dkey 会生成不同的layout吗（不是）
		// 是每个object 有一个自己的layout，layout 里面是当前object 分布数据到shards 的整体信息。再根据dkey 散列到shards 环的不同桶中
		// todo: 只能传 DAOS_TX_NONE 这个吗
		rc = daos_obj_update(oh, DAOS_TX_NONE, 0, &dkey, 1, &iod, &sgl,
				     NULL);
		ASSERT(rc == 0, "object update failed with %d", rc);
	}

	// 上面是写入，这里是将写入的dkey 读出来
	for (i = 0; i < KEYS; i++) {
		d_sg_list_t	sgl;
		d_iov_t		sg_iov;
		daos_iod_t	iod;
		daos_recx_t	recx;

		/** init dkey */
		// todo dkey 是需要用户指定的
		sprintf(dkey_str, "dkey_%d", i);
		d_iov_set(&dkey, dkey_str, strlen(dkey_str));

		/** init scatter/gather */
		// todo: 读取的时候的iod 是不是要和写入时候的保持一致才能读取成功？
		d_iov_set(&sg_iov, rbuf, BUFLEN);
		sgl.sg_nr		= 1;
		sgl.sg_nr_out		= 0;
		sgl.sg_iovs		= &sg_iov;

		/** init I/O descriptor */
		d_iov_set(&iod.iod_name, "akey", strlen("akey")); /** akey */
		// todo: 这俩描述的什么信息
		// todo: 一个extent 在服务端具体表示什么
		iod.iod_nr	= 1; /** number of extents in recx array */
		// todo: record size 是什么玩意
		iod.iod_size	= 1; /** record size (1 byte array here) */
		// 一个extent 的大小
		recx.rx_nr	= BUFLEN; /** extent size */
		// extent 的idx
		recx.rx_idx	= rank * BUFLEN; /** extent offset */
		iod.iod_recxs	= &recx;
		iod.iod_type	= DAOS_IOD_ARRAY; /** value type of the akey */

		/** fetch a dkey */
		// tx hdl 还是传递的 DAOS_TX_NONE
		// todo: 只能传这个吗
		rc = daos_obj_fetch(oh, DAOS_TX_NONE, 0, &dkey, 1, &iod, &sgl,
				    NULL, NULL);
		ASSERT(rc == 0, "object update failed with %d", rc);

		if (memcmp(buf, rbuf, BUFLEN) != 0)
			ASSERT(0, "Data verification");
		memset(rbuf, 0, BUFLEN);
	}
	MPI_Barrier(MPI_COMM_WORLD);

	/** list all dkeys */
	enumerate_key(oh, &total_nr, NULL, OBJ_DKEY);
	ASSERT(total_nr == KEYS, "key enumeration failed");

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0) {
		/** punch/remove 1 akey */
		sprintf(dkey_str, "dkey_%d", 2);
		d_iov_set(&dkey, dkey_str, strlen(dkey_str));
		// punch hole通常用于稀疏文件场景，使用punch hole 清理不再使用的区域，释放物理磁盘空间
		// 逻辑视图：[数据][空洞][数据][空洞]
		// 物理视图：[数据]      [数据]
		// 核心原理就是跳过零值区域，未分配的部分不实际存储
		rc = daos_obj_punch_dkeys(oh, DAOS_TX_NONE, 0, 1, &dkey, NULL);
		ASSERT(rc == 0, "object punch failed with %d", rc);
	}
	MPI_Barrier(MPI_COMM_WORLD);

	/** list all dkeys again (should have 1 less) */
	enumerate_key(oh, &total_nr, NULL, OBJ_DKEY);
	ASSERT(total_nr == KEYS - 1, "key enumeration failed");

	daos_obj_close(oh, NULL);

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0)
		printf("SUCCESS\n");
}

void
example_daos_key_sv()
{
	daos_handle_t	oh;
	char		buf[BUFLEN], rbuf[BUFLEN];
	daos_obj_id_t	oid;
	d_iov_t		dkey;
	int		total_nr = 0;
	char		dkey_str[32] = {0};
	char		akey_str[32] = {0};
	int		i, rc;

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0)
		printf("Example of DAOS Key Single Value type:\n");

	/*
	 * Most of this example is the same as the key_array one, except the
	 * type of the value under the akey will be a single value of size
	 * 1024. This is a single value that is atomically updated / read, and
	 * no partial access is allowed.
	 */

	oid.hi = 0;
	oid.lo = 2;
	daos_obj_generate_oid(coh, &oid, 0, OC_SX, 0, 0);

	rc = daos_obj_open(coh, oid, DAOS_OO_RW, &oh, NULL);
	ASSERT(rc == 0, "object open failed with %d", rc);

	/*
	 * In this example, we will create an object with 10 dkeys, where each
	 * dkey has 1 akey, and a Single Value of size 1k. A user can create as
	 * many dkeys as they like under a single object. All akeys and values
	 * under the same dkey are guaranteed to be colocated on the same
	 * storage target. A user can update the akey after it was first
	 * inserted with a new single value of a different size, but the old
	 * value is atomically removed and updated to the new value.
	 */

	dts_buf_render(buf, BUFLEN);

	for (i = 0; i < KEYS; i++) {
		d_sg_list_t	sgl;
		d_iov_t		sg_iov;
		daos_iod_t	iod;

		sprintf(dkey_str, "dkey_%d", i);
		d_iov_set(&dkey, dkey_str, strlen(dkey_str));

		d_iov_set(&sg_iov, buf, BUFLEN);
		sgl.sg_nr		= 1;
		sgl.sg_nr_out		= 0;
		sgl.sg_iovs		= &sg_iov;

		/*
		 * Unlike the dkey_array case, where all ranks can update
		 * different extents of the value in the same akey, with a
		 * single value, the last update to the akey wins. in this case,
		 * each rank will create a separate akey under the same dkey
		 * with it's rank attached to akey name.
		 */
		sprintf(akey_str, "akey_%d", rank);
		d_iov_set(&iod.iod_name, akey_str, strlen(akey_str));

		iod.iod_nr	= 1; /** has to be 1 for single value */
		iod.iod_size	= BUFLEN; /** size of the single value */
		iod.iod_recxs	= NULL; /** recx is ignored for single value */
		iod.iod_type	= DAOS_IOD_SINGLE; /** value type of the akey */

		rc = daos_obj_update(oh, DAOS_TX_NONE, 0, &dkey, 1, &iod, &sgl,
				     NULL);
		ASSERT(rc == 0, "object update failed with %d", rc);
	}

	for (i = 0; i < KEYS; i++) {
		d_sg_list_t	sgl;
		d_iov_t		sg_iov;
		daos_iod_t	iod;

		/** init dkey */
		sprintf(dkey_str, "dkey_%d", i);
		d_iov_set(&dkey, dkey_str, strlen(dkey_str));

		/** init scatter/gather */
		d_iov_set(&sg_iov, rbuf, BUFLEN);
		sgl.sg_nr		= 1;
		sgl.sg_nr_out		= 0;
		sgl.sg_iovs		= &sg_iov;

		/** init I/O descriptor */
		sprintf(akey_str, "akey_%d", rank);
		d_iov_set(&iod.iod_name, akey_str, strlen(akey_str));
		iod.iod_nr	= 1;
		/*
		 * Size of the single value. if user doesn't know the length,
		 * they can set this qto DAOS_REC_ANY (0) and pass a NULL
		 * sgl. after the fetch, DAOS reports the actual size of the
		 * value.
		 */
		iod.iod_size	= BUFLEN;
		iod.iod_recxs	= NULL;
		iod.iod_type	= DAOS_IOD_SINGLE;

		/** fetch a dkey */
		rc = daos_obj_fetch(oh, DAOS_TX_NONE, 0, &dkey, 1, &iod, &sgl,
				    NULL, NULL);
		ASSERT(rc == 0, "object update failed with %d", rc);

		if (memcmp(buf, rbuf, BUFLEN) != 0)
			ASSERT(0, "Data verification");
		memset(rbuf, 0, BUFLEN);
	}
	MPI_Barrier(MPI_COMM_WORLD);

	/** list all dkeys */
	enumerate_key(oh, &total_nr, NULL, OBJ_DKEY);
	ASSERT(total_nr == KEYS, "key enumeration failed");

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0) {
		/** punch/remove 1 akey */
		sprintf(dkey_str, "dkey_%d", 2);
		d_iov_set(&dkey, dkey_str, strlen(dkey_str));
		rc = daos_obj_punch_dkeys(oh, DAOS_TX_NONE, 0, 1, &dkey, NULL);
		ASSERT(rc == 0, "object punch failed with %d", rc);
	}
	MPI_Barrier(MPI_COMM_WORLD);

	/** list all dkeys again (should have 1 less) */
	enumerate_key(oh, &total_nr, NULL, OBJ_DKEY);
	ASSERT(total_nr == KEYS - 1, "key enumeration failed");

	daos_obj_close(oh, NULL);

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0)
		printf("SUCCESS\n");
}

// daos array test
void
example_daos_array()
{
	daos_handle_t	oh;
	char		buf[BUFLEN], rbuf[BUFLEN];
	daos_obj_id_t	oid;
	int		rc;

	if (rank == 0)
		printf("Example of DAOS Array:\n");

	/*
	 * Set an object ID. This is chosen by the user.
	 *
	 * DAOS provides a unique 64 bit integer oid allocator that can be used
	 * for the oid.lo to allocate 1 or more unique oids in the
	 * container. Please see: daos_cont_alloc_oids();
	 */
	// todo: 用户自己指定oid 吗
	oid.hi = 0;
	oid.lo = 3;

	/**
	 * Convenience function to generate a DAOS Array object ID by encoding
	 * the private DAOS bits of the object address space.
	 */
	// 因为是array object，需要单独生成一个array object id
	daos_array_generate_oid(coh, &oid, true, 0, 0, 0);

	/*
	 * Create the array object with cell size 1 (byte array) and 1m chunk
	 * size (similar to stripe size in Lustre). Both are configurable by the
	 * user of course.
	 */
	// 传入cont 和oid，创建一个 array，返回 oh
	if (rank == 0) {
		rc = daos_array_create(coh, oid, DAOS_TX_NONE, 1, 1048576, &oh,
				       NULL);
		ASSERT(rc == 0, "array create failed with %d", rc);
	}

	MPI_Barrier(MPI_COMM_WORLD);

	if (rank != 0) {
		size_t cell_size, csize;

		// 打开创建的array
		rc = daos_array_open(coh, oid, DAOS_TX_NONE, DAOS_OO_RW,
				     &cell_size, &csize, &oh, NULL);
		ASSERT(rc == 0, "array open failed with %d", rc);
		ASSERT(cell_size == 1, "array open failed");
		ASSERT(csize == 1048576, "array open failed");
	}

	// 构造sgl list
	daos_array_iod_t iod;
	d_sg_list_t	sgl;
	daos_range_t	rg;
	d_iov_t		iov;
	daos_size_t	array_size;

	/** set array location */
	iod.arr_nr = 1; /** number of ranges / array iovec */
	rg.rg_len = BUFLEN; /** length */
	rg.rg_idx = rank * BUFLEN; /** offset */
	iod.arr_rgs = &rg;

	/** set memory location, each rank writing BUFLEN */
	sgl.sg_nr = 1;
	d_iov_set(&iov, buf, BUFLEN);
	sgl.sg_iovs = &iov;

	/** Write */
	// array write 接口
	rc = daos_array_write(oh, DAOS_TX_NONE, &iod, &sgl, NULL);
	ASSERT(rc == 0, "array write failed with %d", rc);

	MPI_Barrier(MPI_COMM_WORLD);

	/** check size */
	rc = daos_array_get_size(oh, DAOS_TX_NONE, &array_size, NULL);
	ASSERT(rc == 0, "array get_size failed with %d", rc);
	ASSERT(array_size == BUFLEN * rankn, "key enumeration failed");

	d_iov_set(&iov, rbuf, BUFLEN);
	sgl.sg_iovs = &iov;

	/** read & verify */
	// array read 接口
	rc = daos_array_read(oh, DAOS_TX_NONE, &iod, &sgl, NULL);
	ASSERT(rc == 0, "array read failed with %d", rc);

	if (memcmp(buf, rbuf, BUFLEN) != 0)
		ASSERT(0, "Data verification");

	daos_array_close(oh, NULL);
	MPI_Barrier(MPI_COMM_WORLD);

	if (rank == 0)
		printf("SUCCESS\n");
}

static void
list_keys(daos_handle_t oh, int *num_keys)
{
	char		*buf;
	daos_key_desc_t kds[ENUM_DESC_NR];
	daos_anchor_t	anchor = {0};
	int		key_nr = 0;
	d_sg_list_t	sgl;
	d_iov_t		sg_iov;

	buf = malloc(ENUM_DESC_BUF);
	d_iov_set(&sg_iov, buf, ENUM_DESC_BUF);
	sgl.sg_nr		= 1;
	sgl.sg_nr_out		= 0;
	sgl.sg_iovs		= &sg_iov;

	while (!daos_anchor_is_eof(&anchor)) {
		uint32_t	nr = ENUM_DESC_NR;
		int		rc;

		memset(buf, 0, ENUM_DESC_BUF);
		rc = daos_kv_list(oh, DAOS_TX_NONE, &nr, kds, &sgl, &anchor,
				  NULL);
		ASSERT(rc == 0, "KV list failed with %d", rc);

		if (nr == 0)
			continue;
		key_nr += nr;
	}
	*num_keys = key_nr;
}

void
example_daos_kv()
{
	daos_handle_t	oh;
	char		buf[BUFLEN], rbuf[BUFLEN];
	daos_obj_id_t	oid;
	char		key[32] = {0};
	int		i, rc;

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0)
		printf("Example of DAOS High level KV type:\n");

	/*
	 * This is an example if the high level KV API which abstracts out the
	 * 2-level keys and exposes a single Key and atomic single value to
	 * represent a more traditional KV API. In this example we insert 10
	 * keys each with value BUFLEN (note that the value under each key need
	 * not to be of the same size.
	 */

	oid.hi = 0;
	oid.lo = 4;
	daos_obj_generate_oid(coh, &oid, DAOS_OT_KV_HASHED, OC_SX, 0, 0);

	rc = daos_kv_open(coh, oid, DAOS_OO_RW, &oh, NULL);
	ASSERT(rc == 0, "KV open failed with %d", rc);

	dts_buf_render(buf, BUFLEN);

	/** each rank puts 10 keys */
	for (i = 0; i < KEYS; i++) {
		sprintf(key, "key_%d_%d", i, rank);
		rc = daos_kv_put(oh, DAOS_TX_NONE, 0, key, BUFLEN, buf, NULL);
		ASSERT(rc == 0, "KV put failed with %d", rc);
	}

	/** each rank gets 10 keys */
	for (i = 0; i < KEYS; i++) {
		daos_size_t size;

		sprintf(key, "key_%d_%d", i, rank);

		/** first query the size */
		rc = daos_kv_get(oh, DAOS_TX_NONE, 0, key, &size, NULL, NULL);
		ASSERT(rc == 0, "KV get failed with %d", rc);
		ASSERT(size == BUFLEN, "Invalid read size");

		/** get the data */
		rc = daos_kv_get(oh, DAOS_TX_NONE, 0, key, &size, rbuf, NULL);
		ASSERT(rc == 0, "KV get failed with %d", rc);
		ASSERT(size == BUFLEN, "Invalid read size");

		if (memcmp(buf, rbuf, BUFLEN) != 0)
			ASSERT(0, "Data verification");
		memset(rbuf, 0, BUFLEN);
	}
	MPI_Barrier(MPI_COMM_WORLD);

	int num_keys = 0;

	/** enumerate all keys */
	list_keys(oh, &num_keys);
	ASSERT(num_keys == KEYS * rankn, "KV enumerate failed");

	MPI_Barrier(MPI_COMM_WORLD);
	/** each rank removes a key */
	sprintf(key, "key_%d_%d", 1, rank);
	rc = daos_kv_remove(oh, DAOS_TX_NONE, 0, key, NULL);
	ASSERT(rc == 0, "KV remove failed with %d", rc);
	MPI_Barrier(MPI_COMM_WORLD);

	/** enumerate all keys */
	list_keys(oh, &num_keys);
	ASSERT(num_keys == (KEYS - 1) * rankn,
	       "KV enumerate after remove failed");

	rc = daos_kv_close(oh, NULL);
	ASSERT(rc == 0, "KV close failed with %d", rc);

	MPI_Barrier(MPI_COMM_WORLD);
	if (rank == 0)
		printf("SUCCESS\n");
}

int
main(int argc, char **argv)
{
	int		rc;

	rc = MPI_Init(&argc, &argv);
	ASSERT(rc == MPI_SUCCESS, "MPI_Init failed with %d", rc);

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &rankn);

	rc = gethostname(node, sizeof(node));
	ASSERT(rc == 0, "buffer for hostname too small");

	if (argc != 2) {
		fprintf(stderr, "args: pool\n");
		exit(1);
	}

	/** initialize the local DAOS stack */
	// 这里会初始化所有的oc，后面在open object 时候会去做二分查找，根据oid 查找对应的oclass，比如OC_SX等
	rc = daos_init();
	ASSERT(rc == 0, "daos_init failed with %d", rc);

	/** Call connect on rank 0 only and broadcast handle to others */
	if (rank == 0) {
		rc = daos_pool_connect(argv[1], NULL, DAOS_PC_RW, &poh,
				       NULL, NULL);
		ASSERT(rc == 0, "pool connect failed with %d", rc);
	}
	/** share pool handle with peer tasks */
	handle_share(&poh, HANDLE_POOL);

	/*
	 * Create and open container on rank 0 and share the handle.
	 *
	 * Alternatively, one could create the container outside of this program
	 * using the daos utility: daos cont create --pool=puuid
	 * and pass the uuid to the app.
	 */
	if (rank == 0) {
		/** create container */
		rc = daos_cont_create_with_label(poh, "simple_obj", NULL, NULL,
						 NULL);
		ASSERT(rc == 0, "container create failed with %d", rc);

		/** open container */
		rc = daos_cont_open(poh, "simple_obj", DAOS_COO_RW, &coh, NULL,
				    NULL);
		ASSERT(rc == 0, "container open failed with %d", rc);
	}
	/** share container handle with peer tasks */
	handle_share(&coh, HANDLE_CO);

	/** Example of DAOS key_Array object */
	example_daos_key_array();

	/** Example of DAOS key_SV object */
	example_daos_key_sv();

	/** Example of DAOS Array object */
	example_daos_array();

	/** Example of DAOS KV object */
	// 客户端kv 存储例子
	example_daos_kv();

	MPI_Barrier(MPI_COMM_WORLD);

	rc = daos_cont_close(coh, NULL);
	ASSERT(rc == 0, "cont close failed");

	rc = daos_pool_disconnect(poh, NULL);
	ASSERT(rc == 0, "disconnect failed");

	rc = daos_fini();
	ASSERT(rc == 0, "daos_fini failed with %d", rc);

	MPI_Finalize();
	return rc;
}
