#include <linux/kconfig.h>
#include "bpf_helpers.h"

#define KBUILD_MODNAME "empty" // Required for including printk.h
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_timestamp.h>

struct acct_event_t {
  u64 start;
  u64 ts;
  u32 cid;
  u32 connmark;
  union nf_inet_addr srcaddr;
  union nf_inet_addr dstaddr;
  u64 packets_orig;
  u64 bytes_orig;
  u64 packets_ret;
  u64 bytes_ret;
  u16 srcport;
  u16 dstport;
  u32 netns;
  u8 proto;
};

// get_acct_ext gets a reference to the nf_conn's accounting extension.
// Returns non-zero on error.
__attribute__((always_inline))
static int get_acct_ext(struct nf_conn_acct **acct_ext, struct nf_conn *ct) {

  // Check if accounting extension is enabled and initialized
  // for this connection. Important because the acct codepath
  // is called for unix socket usage as well. Also, the acct
  // extension memory is uninitialized if the acct sysctl is disabled.
  struct nf_ct_ext *ct_ext;
  bpf_probe_read(&ct_ext, sizeof(ct_ext), &ct->ext);
  if (!ct_ext)
    return -1;

  u8 ct_acct_offset;
  bpf_probe_read(&ct_acct_offset, sizeof(ct_acct_offset), &ct_ext->offset[NF_CT_EXT_ACCT]);
  if (!ct_acct_offset)
    return -1;

  // Obtain reference to accounting conntrack extension.
  *acct_ext = ((void *)ct_ext + ct_acct_offset);
  if (!*acct_ext)
    return -1;

  return 0;
}

// get_ts_ext gets a reference to the nf_conn's timestamp extension.
// Returns non-zero on error.
__attribute__((always_inline))
static int get_ts_ext(struct nf_conn_tstamp **ts_ext, struct nf_conn *ct) {

  struct nf_ct_ext *ct_ext;
  bpf_probe_read(&ct_ext, sizeof(ct_ext), &ct->ext);
  if (!ct_ext)
    return -1;

  u8 ct_ts_offset;
  bpf_probe_read(&ct_ts_offset, sizeof(ct_ts_offset), &ct_ext->offset[NF_CT_EXT_TSTAMP]);
  if (!ct_ts_offset)
    return -1;

  *ts_ext = ((void *)ct_ext + ct_ts_offset);
  if (!*ts_ext)
    return -1;

  return 0;
}

// extract_counters extracts accounting info from an nf_conn_acct into acct_event_t.
__attribute__((always_inline))
static void extract_counters(struct acct_event_t *data, struct nf_conn_acct *acct_ext) {

  struct nf_conn_counter ctr[IP_CT_DIR_MAX];
  bpf_probe_read(&ctr, sizeof(ctr), &acct_ext->counter);

  data->packets_orig = ctr[IP_CT_DIR_ORIGINAL].packets.counter;
  data->bytes_orig = ctr[IP_CT_DIR_ORIGINAL].bytes.counter;

  data->packets_ret = ctr[IP_CT_DIR_REPLY].packets.counter;
  data->bytes_ret = ctr[IP_CT_DIR_REPLY].bytes.counter;

}

// extract_tstamp extracts the start timestamp of nf_conn_tstamp into acct_event_t.
__attribute__((always_inline))
static void extract_tstamp(struct acct_event_t *data, struct nf_conn_tstamp *ts_ext) {
  bpf_probe_read(&data->start, sizeof(data->start), &ts_ext->start);
}

// extract_tuple extracts tuple information (proto, src/dest ip and port) of an nf_conn
// into an acct_event_t.
__attribute__((always_inline))
static void extract_tuple(struct acct_event_t *data, struct nf_conn *ct) {

  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

  data->proto = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;

  data->srcaddr = tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
  data->dstaddr = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;

  data->srcport = tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
  data->dstport = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;

}

// extract_netns extracts the nf_conn's network namespace inode number into an acct_event_t.
__attribute__((always_inline))
static void extract_netns(struct acct_event_t *data, struct nf_conn *ct) {

  // Obtain reference to network namespace.
  // Warning: ct_net is a possible_net_t with a single member,
  // so we read `struct net` instead at the same location. Reading
  // the `*net` in `possible_net_t` will yield a (non-zero) garbage value.
  struct net *net;
  bpf_probe_read(&net, sizeof(net), &ct->ct_net);

  if (net) {
    // netns field will remain zero if probe read fails.
    bpf_probe_read(&data->netns, sizeof(data->netns), &net->ns.inum);
  }
}

struct bpf_map_def SEC("maps/perf_acct_update") perf_acct_update = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/perf_acct_end") perf_acct_end = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/nextupd") nextupd = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/currct") currct = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/config") config = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(void *),
	.max_entries = 1,
	.pinning = 0,
	.namespace = "",
};


SEC("kprobe/__nf_ct_refresh_acct")
int kprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  u32 pid = bpf_get_current_pid_tgid();

	// stash the conntrack pointer for lookup on return
	bpf_map_update_elem(&currct, &pid, &ct, BPF_ANY);

	return 0;
}

SEC("kretprobe/__nf_ct_refresh_acct")
int kretprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  u32 pid = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  // Look up the conntrack structure stashed by the kprobe.
  struct nf_conn **ctp;
  ctp = bpf_map_lookup_elem(&currct, &pid);
	if (ctp == 0)
		return 0;

  // Dereference and delete from the stash table.
  struct nf_conn *ct = *ctp;
  bpf_map_delete_elem(&currct, &pid);

  // Obtain reference to accounting conntrack extension.
  struct nf_conn_acct *acct_ext = 0;
  if (get_acct_ext(&acct_ext, ct))
    return 0;

  // Initialize cooldown value in the config map to 2 seconds.
  u64 config_cd = 0;
  u64 def_cd = 2000000000;
  bpf_map_update_elem(&config, &config_cd, &def_cd, BPF_NOEXIST);

  // Allocate event struct after all checks have succeeded.
  struct acct_event_t data = {
    .start = 0,
    .ts = ts,
    .cid = (u32)ct,
  };

  // Pull counters onto the BPF stack first, so that we can make event rate
  // limiting decisions based on packet counters without doing unnecessary work.
  extract_counters(&data, acct_ext);

  // Sample accounting events from the kernel using a hybrid rate limiting model.
  // On every event that is sent, a future deadline is set for that specific flow
  // equal to the cooldown time. Every packet that is handled when the dealine has
  // not yet come, has to either be the 1st, 2nd, 8th or 32nd total packet in the flow
  // to be sent as an event. This ensures that flows generate an event at least and
  // at most once per deadline.
  // Packets 1, 2, 8 and 32 are always sent and also increase the deadline. The first
  // packet is always sent because the current timestamp is always past the default (0).

  // Look up the cooldown value in the config map.
  u64 *cdp = bpf_map_lookup_elem(&config, &config_cd);
  u64 cd = def_cd; // Initialize to the default to make sure there is a value.
  if (cdp) {
    cd = *cdp;
  }

  u64 pkts_total = (data.packets_orig + data.packets_ret);

  // Look up when the next event is scheduled to be sent to userspace.
  u64 *nextp = bpf_map_lookup_elem(&nextupd, &ct);
  u64 next = 0;
  if (nextp)
    next = *nextp;

  // The deadline has not yet expired, but we allow certain exceptions.
  if (ts < next) {
    if (pkts_total > 32) {
      // Flow is no longer in burst mode and will only be sampled after deadline.
      return 0;
    } else {
      // Flow is in burst mode (flow start), check if the current packet
      // matches any of the pre-defined checkpoints for sending an event.
      if ( ! (pkts_total == 2 ||
              pkts_total == 8 ||
              pkts_total == 32))
        return 0;
    }
  }

  // Extract proto, src/dst address and ports.
  extract_tuple(&data, ct);
  // Extract network namespace identifier (inode).
  extract_netns(&data, ct);
  // Extract conntrack connection mark.
  bpf_probe_read(&data.connmark, sizeof(data.connmark), &ct->mark);

  // Submit event to userspace.
  bpf_perf_event_output(ctx, &perf_acct_update, CUR_CPU_IDENTIFIER, &data, sizeof(data));

  // Set the deadline to the current timestamp plus the cooldown period.
  next = ts + cd;
  bpf_map_update_elem(&nextupd, &ct, &next, BPF_ANY);

  return 0;
}

SEC("kprobe/nf_conntrack_free")
int kprobe__nf_conntrack_free(struct pt_regs *ctx) {

  u64 ts = bpf_ktime_get_ns();

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  // Remove next-update entry for connection.
  bpf_map_delete_elem(&nextupd, &ct);

  // Below this point, the kprobe can return early,
  // make sure all bookkeeping is handled above.

  struct nf_conn_acct *acct_ext = 0;
  if (get_acct_ext(&acct_ext, ct))
    return 0;

  struct acct_event_t data = {
    .start = 0,
    .ts = ts,
    .cid = (u32)ct,
  };

  struct nf_conn_tstamp *ts_ext = 0;
  if (get_ts_ext(&ts_ext, ct) == 0)
    extract_tstamp(&data, ts_ext);

  extract_counters(&data, acct_ext);
  extract_tuple(&data, ct);
  extract_netns(&data, ct);
  bpf_probe_read(&data.connmark, sizeof(data.connmark), &ct->mark);

  bpf_perf_event_output(ctx, &perf_acct_end, CUR_CPU_IDENTIFIER, &data, sizeof(data));

  return 0;
}

char _license[] SEC("license") = "GPL";

__u32 _version SEC("version") = 0xFFFFFFFE;
