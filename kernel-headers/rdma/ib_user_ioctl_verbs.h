/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (c) 2017-2018, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef IB_USER_IOCTL_VERBS_H
#define IB_USER_IOCTL_VERBS_H

#include <linux/types.h>
#include <rdma/ib_user_verbs.h>

#ifndef RDMA_UAPI_PTR
#define RDMA_UAPI_PTR(_type, _name)	__aligned_u64 _name
#endif

#define IB_UVERBS_ACCESS_OPTIONAL_FIRST (1 << 20)
#define IB_UVERBS_ACCESS_OPTIONAL_LAST (1 << 29)

enum ib_uverbs_core_support {
	IB_UVERBS_CORE_SUPPORT_OPTIONAL_MR_ACCESS = 1 << 0,
};

enum ib_uverbs_access_flags {
	IB_UVERBS_ACCESS_LOCAL_WRITE = 1 << 0,
	IB_UVERBS_ACCESS_REMOTE_WRITE = 1 << 1,
	IB_UVERBS_ACCESS_REMOTE_READ = 1 << 2,
	IB_UVERBS_ACCESS_REMOTE_ATOMIC = 1 << 3,
	IB_UVERBS_ACCESS_MW_BIND = 1 << 4,
	IB_UVERBS_ACCESS_ZERO_BASED = 1 << 5,
	IB_UVERBS_ACCESS_ON_DEMAND = 1 << 6,
	IB_UVERBS_ACCESS_HUGETLB = 1 << 7,

	IB_UVERBS_ACCESS_RELAXED_ORDERING = IB_UVERBS_ACCESS_OPTIONAL_FIRST,
	IB_UVERBS_ACCESS_OPTIONAL_RANGE =
		((IB_UVERBS_ACCESS_OPTIONAL_LAST << 1) - 1) &
		~(IB_UVERBS_ACCESS_OPTIONAL_FIRST - 1)
};

enum ib_uverbs_query_port_cap_flags {
	IB_UVERBS_PCF_SM = 1 << 1,
	IB_UVERBS_PCF_NOTICE_SUP = 1 << 2,
	IB_UVERBS_PCF_TRAP_SUP = 1 << 3,
	IB_UVERBS_PCF_OPT_IPD_SUP = 1 << 4,
	IB_UVERBS_PCF_AUTO_MIGR_SUP = 1 << 5,
	IB_UVERBS_PCF_SL_MAP_SUP = 1 << 6,
	IB_UVERBS_PCF_MKEY_NVRAM = 1 << 7,
	IB_UVERBS_PCF_PKEY_NVRAM = 1 << 8,
	IB_UVERBS_PCF_LED_INFO_SUP = 1 << 9,
	IB_UVERBS_PCF_SM_DISABLED = 1 << 10,
	IB_UVERBS_PCF_SYS_IMAGE_GUID_SUP = 1 << 11,
	IB_UVERBS_PCF_PKEY_SW_EXT_PORT_TRAP_SUP = 1 << 12,
	IB_UVERBS_PCF_EXTENDED_SPEEDS_SUP = 1 << 14,
	IB_UVERBS_PCF_CM_SUP = 1 << 16,
	IB_UVERBS_PCF_SNMP_TUNNEL_SUP = 1 << 17,
	IB_UVERBS_PCF_REINIT_SUP = 1 << 18,
	IB_UVERBS_PCF_DEVICE_MGMT_SUP = 1 << 19,
	IB_UVERBS_PCF_VENDOR_CLASS_SUP = 1 << 20,
	IB_UVERBS_PCF_DR_NOTICE_SUP = 1 << 21,
	IB_UVERBS_PCF_CAP_MASK_NOTICE_SUP = 1 << 22,
	IB_UVERBS_PCF_BOOT_MGMT_SUP = 1 << 23,
	IB_UVERBS_PCF_LINK_LATENCY_SUP = 1 << 24,
	IB_UVERBS_PCF_CLIENT_REG_SUP = 1 << 25,
	/*
	 * IsOtherLocalChangesNoticeSupported is aliased by IP_BASED_GIDS and
	 * is inaccessible
	 */
	IB_UVERBS_PCF_LINK_SPEED_WIDTH_TABLE_SUP = 1 << 27,
	IB_UVERBS_PCF_VENDOR_SPECIFIC_MADS_TABLE_SUP = 1 << 28,
	IB_UVERBS_PCF_MCAST_PKEY_TRAP_SUPPRESSION_SUP = 1 << 29,
	IB_UVERBS_PCF_MCAST_FDB_TOP_SUP = 1 << 30,
	IB_UVERBS_PCF_HIERARCHY_INFO_SUP = 1ULL << 31,

	/* NOTE this is an internal flag, not an IBA flag */
	IB_UVERBS_PCF_IP_BASED_GIDS = 1 << 26,
};

enum ib_uverbs_query_port_flags {
	IB_UVERBS_QPF_GRH_REQUIRED = 1 << 0,
};

enum ib_uverbs_flow_action_esp_keymat {
	IB_UVERBS_FLOW_ACTION_ESP_KEYMAT_AES_GCM,
};

enum ib_uverbs_flow_action_esp_keymat_aes_gcm_iv_algo {
	IB_UVERBS_FLOW_ACTION_IV_ALGO_SEQ,
};

struct ib_uverbs_flow_action_esp_keymat_aes_gcm {
	__aligned_u64	iv;
	__u32		iv_algo; /* Use enum ib_uverbs_flow_action_esp_keymat_aes_gcm_iv_algo */

	__u32		salt;
	__u32		icv_len;

	__u32		key_len;
	__u32		aes_key[256 / 32];
};

enum ib_uverbs_flow_action_esp_replay {
	IB_UVERBS_FLOW_ACTION_ESP_REPLAY_NONE,
	IB_UVERBS_FLOW_ACTION_ESP_REPLAY_BMP,
};

struct ib_uverbs_flow_action_esp_replay_bmp {
	__u32	size;
};

enum ib_uverbs_flow_action_esp_flags {
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_INLINE_CRYPTO	= 0UL << 0,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_FULL_OFFLOAD	= 1UL << 0,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TUNNEL		= 0UL << 1,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_TRANSPORT	= 1UL << 1,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_DECRYPT		= 0UL << 2,	/* Default */
	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ENCRYPT		= 1UL << 2,

	IB_UVERBS_FLOW_ACTION_ESP_FLAGS_ESN_NEW_WINDOW	= 1UL << 3,
};

struct ib_uverbs_flow_action_esp_encap {
	/* This struct represents a list of pointers to flow_xxxx_filter that
	 * encapsulates the payload in ESP tunnel mode.
	 */
	RDMA_UAPI_PTR(void *, val_ptr); /* pointer to a flow_xxxx_filter */
	RDMA_UAPI_PTR(struct ib_uverbs_flow_action_esp_encap *, next_ptr);
	__u16	len;		/* Len of the filter struct val_ptr points to */
	__u16	type;		/* Use flow_spec_type enum */
};

struct ib_uverbs_flow_action_esp {
	__u32		spi;
	__u32		seq;
	__u32		tfc_pad;
	__u32		flags;
	__aligned_u64	hard_limit_pkts;
};

enum ib_uverbs_read_counters_flags {
	/* prefer read values from driver cache */
	IB_UVERBS_READ_COUNTERS_PREFER_CACHED = 1 << 0,
};

enum ib_uverbs_advise_mr_advice {
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH,
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE,
};

enum ib_uverbs_advise_mr_flag {
	IB_UVERBS_ADVISE_MR_FLAG_FLUSH = 1 << 0,
};

struct ib_uverbs_query_port_resp_ex {
	struct ib_uverbs_query_port_resp legacy_resp;
	__u16 port_cap_flags2;
	__u8  reserved[6];
};

enum rdma_driver_id {
	RDMA_DRIVER_UNKNOWN,
	RDMA_DRIVER_MLX5,
	RDMA_DRIVER_MLX4,
	RDMA_DRIVER_CXGB3,
	RDMA_DRIVER_CXGB4,
	RDMA_DRIVER_MTHCA,
	RDMA_DRIVER_BNXT_RE,
	RDMA_DRIVER_OCRDMA,
	RDMA_DRIVER_NES,
	RDMA_DRIVER_I40IW,
	RDMA_DRIVER_VMW_PVRDMA,
	RDMA_DRIVER_QEDR,
	RDMA_DRIVER_HNS,
	RDMA_DRIVER_USNIC,
	RDMA_DRIVER_RXE,
	RDMA_DRIVER_HFI1,
	RDMA_DRIVER_QIB,
	RDMA_DRIVER_EFA,
	RDMA_DRIVER_SIW,
};

enum ib_uverbs_objects_types {
	IB_UVERBS_OBJECT_DEVICE, /* No instances of DEVICE are allowed */
	IB_UVERBS_OBJECT_PD,
	IB_UVERBS_OBJECT_COMP_CHANNEL,
	IB_UVERBS_OBJECT_CQ,
	IB_UVERBS_OBJECT_QP,
	IB_UVERBS_OBJECT_SRQ,
	IB_UVERBS_OBJECT_AH,
	IB_UVERBS_OBJECT_MR,
	IB_UVERBS_OBJECT_MW,
	IB_UVERBS_OBJECT_FLOW,
	IB_UVERBS_OBJECT_XRCD,
	IB_UVERBS_OBJECT_RWQ_IND_TBL,
	IB_UVERBS_OBJECT_WQ,
	IB_UVERBS_OBJECT_FLOW_ACTION,
	IB_UVERBS_OBJECT_DM,
	IB_UVERBS_OBJECT_COUNTERS,
	IB_UVERBS_OBJECT_TOTAL,
};

struct rxe_dump_queue {
	__u64 start;
	__u64 size;
	__u32	log2_elem_size;
	__u32	index_mask;
	__u32	producer_index;
	__u32	consumer_index;
} __attribute__((packed));

struct rxe_dump_qp {
	struct rxe_dump_queue	sq;
	struct rxe_dump_queue	rq;
	__u32			wqe_index;
	__u32			req_opcode;
	__u32			comp_psn;
	__u32			comp_opcode;
	__u32			msn;
	__u32			resp_opcode;
} __attribute__((packed));

struct ib_uverbs_dump_object {
	/* Set by generic code */
	__u32 type;
	__u32 size;
	__u32 handle;
} __attribute__((packed));

struct ib_uverbs_dump_object_pd {
	struct ib_uverbs_dump_object obj;
} __attribute__((packed));

struct rxe_dump_mr {
	__u32 lkey;
	__u32 rkey;
	__u32 mrn;
};

struct ib_uverbs_dump_object_mr {
	struct ib_uverbs_dump_object obj;

	/* Set by driver specific code  */
	__u64 address;
	__u64 length;
	__u32 access;

	/* Set by generic code */
	__u32 pd_handle;
	__u32 lkey;
	__u32 rkey;

	struct rxe_dump_mr rxe;
} __attribute__((packed));

struct ib_uverbs_dump_object_cq {
	struct ib_uverbs_dump_object obj;

	/* Set by driver specific code */
	__u32 comp_vector;

	/* Set by generic code */
	__u32 cqe;
	__u32 comp_channel;

	struct rxe_dump_queue rxe;
} __attribute__((packed));

enum ib_qp_state {
	IB_QPS_RESET,
	IB_QPS_INIT,
	IB_QPS_RTR,
	IB_QPS_RTS,
	IB_QPS_SQD,
	IB_QPS_SQE,
	IB_QPS_ERR
};

enum ib_mtu {
	IB_MTU_256  = 1,
	IB_MTU_512  = 2,
	IB_MTU_1024 = 3,
	IB_MTU_2048 = 4,
	IB_MTU_4096 = 5
};

enum ib_mig_state {
	IB_MIG_MIGRATED,
	IB_MIG_REARM,
	IB_MIG_ARMED
};

struct ib_qp_cap {
	__u32	max_send_wr;
	__u32	max_recv_wr;
	__u32	max_send_sge;
	__u32	max_recv_sge;
	__u32	max_inline_data;

	/*
	 * Maximum number of rdma_rw_ctx structures in flight at a time.
	 * ib_create_qp() will calculate the right amount of neededed WRs
	 * and MRs based on this.
	 */
	__u32	max_rdma_ctxs;
} __attribute__((packed));

enum ib_qp_type {
	/*
	 * IB_QPT_SMI and IB_QPT_GSI have to be the first two entries
	 * here (and in that order) since the MAD layer uses them as
	 * indices into a 2-entry table.
	 */
	IB_QPT_SMI,
	IB_QPT_GSI,

	IB_QPT_RC,
	IB_QPT_UC,
	IB_QPT_UD,
	IB_QPT_RAW_IPV6,
	IB_QPT_RAW_ETHERTYPE,
	IB_QPT_RAW_PACKET = 8,
	IB_QPT_XRC_INI = 9,
	IB_QPT_XRC_TGT,
	IB_QPT_MAX,
	IB_QPT_DRIVER = 0xFF,
	/* Reserve a range for qp types internal to the low level driver.
	 * These qp types will not be visible at the IB core layer, so the
	 * IB_QPT_MAX usages should not be affected in the core layer
	 */
	IB_QPT_RESERVED1 = 0x1000,
	IB_QPT_RESERVED2,
	IB_QPT_RESERVED3,
	IB_QPT_RESERVED4,
	IB_QPT_RESERVED5,
	IB_QPT_RESERVED6,
	IB_QPT_RESERVED7,
	IB_QPT_RESERVED8,
	IB_QPT_RESERVED9,
	IB_QPT_RESERVED10,
};

struct ib_qp_dump_attr {
	enum ib_qp_state		qp_state;
	enum ib_mtu			path_mtu;
	enum ib_mig_state		path_mig_state;
	__u32				qkey;
	__u32				rq_psn;
	__u32				sq_psn;
	__u32				dest_qp_num;
	__u32				qp_access_flags;
	struct ib_qp_cap		cap;
	struct ib_uverbs_ah_attr	ah_attr;
	struct ib_uverbs_ah_attr	alt_ah_attr;
	__u16				pkey_index;
	__u16				alt_pkey_index;
	__u8				en_sqd_async_notify;
	__u8				sq_draining;
	__u8				max_rd_atomic;
	__u8				max_dest_rd_atomic;
	__u8				min_rnr_timer;
	__u8				port_num;
	__u8				timeout;
	__u8				retry_cnt;
	__u8				rnr_retry;
	__u8				alt_port_num;
	__u8				alt_timeout;
	__u32				rate_limit;
} __attribute__((packed));

struct ib_uverbs_dump_object_qp {
	struct ib_uverbs_dump_object obj;

	/* Set by generic code */
	__u32 pd_handle;
	__u32 scq_handle;
	__u32 rcq_handle;
	__u32 srq_handle;

	__u32 qp_type;
	__u32 sq_sig_all;
	__u32 qp_num;

	struct ib_qp_dump_attr attr;

	struct rxe_dump_qp rxe;
} __attribute__((packed));

struct ib_uverbs_dump_object_ah {
	struct ib_uverbs_dump_object obj;

	__u32 pd_handle;
	struct ib_uverbs_ah_attr attr;
} __attribute__((packed));

struct ib_uverbs_dump_object_srq {
	struct ib_uverbs_dump_object obj;

	__u32 pd_handle;
	__u32 cq_handle;
	__u32	max_wr;
	__u32	max_sge;
	__u32	srq_limit;

	__u32 srq_type;
	struct rxe_dump_queue	queue;
} __attribute__((packed));

struct ib_uverbs_dump_object_comp_channel {
	struct ib_uverbs_dump_object obj;
} __attribute__((packed));
#endif
