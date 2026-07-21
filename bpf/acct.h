#pragma once

#include "bpf_endian.h"

#include "cooldown.h"

enum event_type {
    CT_NEW = 1 << 0,
    CT_UPDATE = 1 << 1,
    CT_DESTROY = 1 << 2,
};

struct event {
  enum event_type type;
  u64 start;
  u64 ts;
  union nf_inet_addr srcaddr;
  union nf_inet_addr dstaddr;
  u64 packets_orig;
  u64 bytes_orig;
  u64 packets_ret;
  u64 bytes_ret;
  u32 connmark;
  u32 netns;
  u16 srcport;
  u16 dstport;
  u8 proto;
};

// Lightweight packet counters for making rate limiting decisions.
struct packets {
  u64 orig;
  u64 ret;
  u64 total;
};

// ct_valid returns true if the nf_conn carries the IPS_CONFIRMED bit.
// This is necessary particularly for new flows, since they may race against
// identical flows that are being created by packets going through other
// interfaces. nf_conns with the IPS_CONFIRMED bit set have been inserted
// into the global hash table and have won the race.
static __always_inline bool ct_valid(struct nf_conn *ct) {
  return ct->status & IPS_CONFIRMED;
}

// ct_get_ext gets a reference to the nf_conn's extension with the given id.
//
// Returns NULL if the extension's repective sysctl is disabled.
static __always_inline void *ct_get_ext(struct nf_conn *ct, enum nf_ct_ext_id id) {
  u8 off = ct->ext->offset[id];
  if (!off)
    return NULL;

  return (void *)ct->ext + off;
}

static __always_inline struct nf_conn_acct *ct_get_acct(struct nf_conn *ct) {
  return ct_get_ext(ct, NF_CT_EXT_ACCT);
}

static __always_inline struct nf_conn_tstamp *ct_get_tstamp(struct nf_conn *ct) {
  return ct_get_ext(ct, NF_CT_EXT_TSTAMP);
}

static __always_inline bool packets_read_acct(struct packets *packets, struct nf_conn_acct *acct) {
  if (acct == NULL)
    return false;

  packets->orig = BPF_CORE_READ(acct, counter[IP_CT_DIR_ORIGINAL].packets.counter);
  packets->ret = BPF_CORE_READ(acct, counter[IP_CT_DIR_REPLY].packets.counter);

  packets->total = packets->orig + packets->ret;

  return true;
}

static __always_inline bool data_read_acct(struct event *data, struct nf_conn_acct *acct) {
  if (acct == NULL)
    return false;

  data->packets_orig = BPF_CORE_READ(acct, counter[IP_CT_DIR_ORIGINAL].packets.counter);
  data->bytes_orig = BPF_CORE_READ(acct, counter[IP_CT_DIR_ORIGINAL].bytes.counter);

  data->packets_ret = BPF_CORE_READ(acct, counter[IP_CT_DIR_REPLY].packets.counter);
  data->bytes_ret = BPF_CORE_READ(acct, counter[IP_CT_DIR_REPLY].bytes.counter);

  return true;
}

static __always_inline bool data_read_tstamp(struct event *data, struct nf_conn_tstamp *ts) {
  if (ts == NULL)
    return false;

  data->start = BPF_CORE_READ(ts, start);

  return true;
}

// extract_tuple extracts tuple information (proto, src/dest ip and port) of ct
// into data.
static __always_inline void extract_tuple(struct event *data, struct nf_conn *ct) {
  struct nf_conntrack_tuple *tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

  data->proto = tuple->dst.protonum;

  data->srcaddr = tuple->src.u3;
  data->dstaddr = tuple->dst.u3;

  data->srcport = bpf_htons(tuple->src.u.all);
  data->dstport = bpf_htons(tuple->dst.u.all);
}

static __always_inline struct nf_conn *skb_get_ct(struct sk_buff *skb) {
  #define NFCT_PTRMASK	~(7UL)
  return bpf_core_cast((void *)(skb->_nfct & NFCT_PTRMASK), struct nf_conn);
}

// flow_initialize_origin sets the first-seen timestamp of the nf_conn
// to ts. If pkts_total is larger than one, the flow is considered as old as
// the second age threshold (curve1age), to protect against event storms
// when the program is restarted.
// This call is write-once due to BPF_NOEXIST.
static __always_inline u64 flow_initialize_origin(struct nf_conn *ct, u64 ts, u64 pkts_total) {
  u64 origin = ts;

  // pkts_total is evaluated to account for flows that existed before
  if (pkts_total < 2)
    goto update;

  // Make sure current timestamp is larger than the curve point to prevent rollover.
  if (origin > curve1.age) {
    origin -= curve1.age;
  } else {
    // Clamp the origin to zero (boottime of the machine).
    origin = 0;
  }

update:
  bpf_map_update_elem(&flow_origin, &ct, &origin, BPF_NOEXIST);

  return origin;
}

// flow_cleanup removes all possible map entries related to the connection.
static __always_inline void flow_cleanup(struct nf_conn *ct) {
  bpf_map_delete_elem(&flow_cooldown, &ct);
  bpf_map_delete_elem(&flow_origin, &ct);
}
