#pragma once

#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct fred_cs {
	u64 cs: 16;
	u64 sl: 2;
	u64 wfe: 1;
};

struct fred_ss {
	u64 ss: 16;
	u64 sti: 1;
	u64 swevent: 1;
	u64 nmi: 1;
	int: 13;
	u64 vector: 8;
	short: 8;
	u64 type: 4;
	char: 4;
	u64 enclave: 1;
	u64 lm: 1;
	u64 nested: 1;
	char: 1;
	u64 insnlen: 4;
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	union {
		u16 cs;
		u64 csx;
		struct fred_cs fred_cs;
	};
	long unsigned int flags;
	long unsigned int sp;
	union {
		u16 ss;
		u64 ssx;
		struct fred_ss fred_ss;
	};
};

struct user_pt_regs {
	__u64		regs[31];
	__u64		sp;
	__u64		pc;
	__u64		pstate;
};

struct in_addr {
	__be32 s_addr;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

union nf_inet_addr {
	__u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

union nf_conntrack_man_proto {
	__be16 all;
	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 id;
	} icmp;
	struct {
		__be16 port;
	} dccp;
	struct {
		__be16 port;
	} sctp;
	struct {
		__be16 key;
	} gre;
};

struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	u_int16_t l3num;
};

struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	struct {
		union nf_inet_addr u3;
		union {
			__be16 all;
			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				u_int8_t type;
				u_int8_t code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;
		u_int8_t protonum;
		u_int8_t dir;
	} dst;
};

struct nf_conntrack_tuple_hash {
	struct nf_conntrack_tuple tuple;
};

typedef struct {
	struct net *net;
} possible_net_t;

struct nf_conn {
	u32 timeout;
	struct nf_conntrack_tuple_hash tuplehash[2];
	long unsigned int status;
	possible_net_t ct_net;
	u_int32_t mark;
	struct nf_ct_ext *ext;
};

typedef struct {
	s64 counter;
} atomic64_t;

struct nf_conn_counter {
	atomic64_t packets;
	atomic64_t bytes;
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL = 0,
	IP_CT_DIR_REPLY = 1,
	IP_CT_DIR_MAX = 2,
};

struct nf_conn_acct {
	struct nf_conn_counter counter[IP_CT_DIR_MAX];
};

struct nf_ct_ext {
	u8 offset[10];
	u8 len;
	unsigned int gen_id;
	char data[0];
};

enum nf_ct_ext_id {
	NF_CT_EXT_HELPER = 0,
	NF_CT_EXT_NAT = 1,
	NF_CT_EXT_SEQADJ = 2,
	NF_CT_EXT_ACCT = 3,
	NF_CT_EXT_ECACHE = 4,
	NF_CT_EXT_TSTAMP = 5,
	NF_CT_EXT_TIMEOUT = 6,
	NF_CT_EXT_LABELS = 7,
	NF_CT_EXT_SYNPROXY = 8,
	NF_CT_EXT_ACT_CT = 9,
	NF_CT_EXT_NUM = 10,
};

struct nf_conn_tstamp {
	u_int64_t start;
	u_int64_t stop;
};

struct ns_common {
	unsigned int inum;
};

struct net {
	struct ns_common ns;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif
