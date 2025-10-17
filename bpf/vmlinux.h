#pragma once

#define __VMLINUX_H__

enum {
        false = 0,
        true = 1,
};

typedef _Bool bool;

typedef unsigned char __u8;
typedef __u8 u8;
typedef u8 u_int8_t;

typedef short unsigned int __u16;
typedef __u16 __be16;
typedef __u16 u16;
typedef u16 u_int16_t;

typedef unsigned int __u32;
typedef __u32 __be32;
typedef __u32 u32;
typedef u32 u_int32_t;

typedef long long unsigned int __u64;
typedef __u64 __be64;
typedef __u64 u64;
typedef u64 u_int64_t;

typedef long long int __s64;
typedef __s64 s64;

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
};

enum {
        BPF_ANY = 0,
        BPF_NOEXIST = 1,
};

enum {
	BPF_F_INDEX_MASK		= 0xffffffffULL,
	BPF_F_CURRENT_CPU		= BPF_F_INDEX_MASK,
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

enum ip_conntrack_status {
	IPS_CONFIRMED = 8,
	IPS_DYING = 512,
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

struct sk_buff {
	long unsigned int _nfct;
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
