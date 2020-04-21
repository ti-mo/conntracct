#include <linux/kconfig.h>
#include "bpf_helpers.h"

#define _LINUX_BLKDEV_H // calls macros that contain inline asm, which BPF doesn't support
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_timestamp.h>

struct acct_event_t {
  u64 start;
  u64 ts;
  u64 cptr;
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

enum o_config {
  ConfigReady,
  ConfigMax,
};

enum o_config_ratecurve {
  ConfigCurve0Age,
  ConfigCurve0Interval,
  ConfigCurve1Age,
  ConfigCurve1Interval,
  ConfigCurve2Age,
  ConfigCurve2Interval,
  ConfigCurveMax,
};

// Magic value that userspace writes into the ConfigReady location when
// configuration from userspace has completed.
const int ready_val = 0x90;

// perf map to send update events to userspace.
struct bpf_map_def SEC("maps/perf_acct_update") perf_acct_update = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

// perf map to send destroy events to userspace.
struct bpf_map_def SEC("maps/perf_acct_end") perf_acct_end = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

// Hash that holds a kernel timestamp per flow indicating when
// the flow may send its next update event to userspace.
struct bpf_map_def SEC("maps/flow_cooldown") flow_cooldown = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(u64),
  .max_entries = 65535,
};

// Hash that holds a timestamp per flow indicating when the flow
// was first seen. Used to implement age-based event rate limiting.
struct bpf_map_def SEC("maps/flow_origin") flow_origin = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct nf_conn *),
  .value_size = sizeof(u64),
  .max_entries = 65535,
};

// Communication channel between the kprobe and the kretprobe.
// Holds a pointer to the nf_conn in the hot path (kprobe) and
// reads + deletes it in the kretprobe.
struct bpf_map_def SEC("maps/currct") currct = {
  .type = BPF_MAP_TYPE_PERCPU_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(struct nf_conn *),
  .max_entries = 2048,
};

// Map holding configuration values for this BPF program.
// Indexed by enum o_config.
struct bpf_map_def SEC("maps/config") config = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(enum o_config),
  .value_size = sizeof(u64),
  .max_entries = ConfigMax,
};

// Array holding pairs of (age, interval) values,
// used for age-based rate limiting.
// Indexed by enum o_config_ratecurve.
struct bpf_map_def SEC("maps/config_ratecurve") config_ratecurve = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(enum o_config_ratecurve),
  .value_size = sizeof(u64),
  .max_entries = ConfigCurveMax,
};

// probe_ready reads the `config` array map for the Ready flag.
// It returns true if the Ready flag is set to 0x90 (go).
static __inline bool probe_ready() {

  u64 oc_ready = ConfigReady;
  u64 *rp = bpf_map_lookup_elem(&config, &oc_ready);

  return (rp && *rp == ready_val);
}

// get_acct_ext gets a reference to the nf_conn's accounting extension.
// Returns non-zero on error.
static __inline int get_acct_ext(struct nf_conn_acct **acct_ext, struct nf_conn *ct) {

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
static __inline int get_ts_ext(struct nf_conn_tstamp **ts_ext, struct nf_conn *ct) {

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

// extract_counters extracts accounting info from an nf_conn into acct_event_t.
// Returns 0 if acct extension was present in ct.
static __inline int extract_counters(struct acct_event_t *data, struct nf_conn *ct) {

  struct nf_conn_acct *acct_ext = 0;
  if (get_acct_ext(&acct_ext, ct))
    return -1;

  struct nf_conn_counter ctr[IP_CT_DIR_MAX];
  bpf_probe_read(&ctr, sizeof(ctr), &acct_ext->counter);

  data->packets_orig = ctr[IP_CT_DIR_ORIGINAL].packets.counter;
  data->bytes_orig = ctr[IP_CT_DIR_ORIGINAL].bytes.counter;

  data->packets_ret = ctr[IP_CT_DIR_REPLY].packets.counter;
  data->bytes_ret = ctr[IP_CT_DIR_REPLY].bytes.counter;

  return 0;
}

// extract_tstamp extracts the start timestamp of nf_conn_tstamp inside an nf_conn
// into acct_event_t. Returns 0 if timestamp extension was present in ct.
static __inline int extract_tstamp(struct acct_event_t *data, struct nf_conn *ct) {

  struct nf_conn_tstamp *ts_ext = 0;
  if (get_ts_ext(&ts_ext, ct))
    return -1;

  bpf_probe_read(&data->start, sizeof(data->start), &ts_ext->start);

  return 0;
}

// extract_tuple extracts tuple information (proto, src/dest ip and port) of an nf_conn
// into an acct_event_t.
static __inline void extract_tuple(struct acct_event_t *data, struct nf_conn *ct) {

  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

  data->proto = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;

  data->srcaddr = tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
  data->dstaddr = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;

  data->srcport = tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
  data->dstport = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;

}

// extract_netns extracts the nf_conn's network namespace inode number into an acct_event_t.
static __inline void extract_netns(struct acct_event_t *data, struct nf_conn *ct) {

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

// curve_get returns an entry from the curve array as a signed 64-bit integer.
// Returns negative if an entry was not found at the requested index.
static __inline s64 curve_get(enum o_config_ratecurve curve_enum) {

  int offset = curve_enum;
  u64 *confp = bpf_map_lookup_elem(&config_ratecurve, &offset);
  if (confp)
    return *confp;

  return -1;
}

// flow_cooldown_expired returns true if the flow's cooldown period is over.
static __inline bool flow_cooldown_expired(struct nf_conn *ct, u64 ts) {

  // Look up the flow's cooldown expiration time.
  u64 *nextp = bpf_map_lookup_elem(&flow_cooldown, &ct);
  u64 next = 0;
  if (nextp)
    next = *nextp;

  // Cooldown has expired if the current timestamp is greater
  // or equal than the stored expiration time.
  return (ts >= next);
}

// flow_initialize_origin sets the first-seen timestamp of the nf_conn
// to ts. If pkts_total is larger than one, the flow is considered as old as
// the second age threshold (curve1age), to protect against event storms
// when the program is restarted.
// This call is write-once due to BPF_NOEXIST.
static __inline u64 flow_initialize_origin(struct nf_conn *ct, u64 ts, u64 pkts_total) {

  u64 origin = ts;

  // pkts_total is evaluated to account for flows that existed before
  if (pkts_total < 2)
    goto update;

  s64 curve1_age = curve_get(ConfigCurve1Age);
  if (curve1_age < 0)
    goto update;

  // Make sure current timestamp is larger than the curve point to prevent rollover.
  if (origin > curve1_age) {
    origin -= curve1_age;
  } else {
    // Clamp the origin to zero (boottime of the machine).
    origin = 0;
  }

update:
  bpf_map_update_elem(&flow_origin, &ct, &origin, BPF_NOEXIST);

  return origin;
}

// flow_get_age looks up the flow in the first-seen (origin)
// hashmap. The time elapsed between the origin and the given
// ts is returned. If there is no first-seen timestamp for the
// flow, returns a zero value.
static __inline u64 flow_get_age(struct nf_conn *ct, u64 ts) {

  // Initialize origin to the current timestamp so a lookup miss
  // causes a 0ns age to be returned. (new or unknown flows)
  u64 origin = ts;

  u64 *originp = bpf_map_lookup_elem(&flow_origin, &ct);
  if (originp)
    origin = *originp;

  return ts - origin;
}

// flow_get_interval returns the interval (cooldown period) to be set
// for the flow during the current event.
// Returns negative if the flow is younger than the minimum age threshold,
// or if an internal curve lookup error occurred.
static __inline s64 flow_get_interval(struct nf_conn *ct, u64 ts) {

  // Always returns a positive or 0 value.
  u64 age = flow_get_age(ct, ts);

  // Don't consider flows that are under a minimum age.
  // Return negative interval to signal that the event should be dropped.
  s64 curve0_age = curve_get(ConfigCurve0Age);
  if (curve0_age < 0) return -1;
  if (age < curve0_age)
    return -1;

  // Between age 0 and age 1, use interval 0.
  s64 curve1_age = curve_get(ConfigCurve1Age);
  if (curve1_age < 0) return -1;
  if (age < curve1_age)
    return curve_get(ConfigCurve0Interval);

  // Between age 1 and age 2, use interval 1.
  s64 curve2_age = curve_get(ConfigCurve2Age);
  if (curve2_age < 0) return -1;
  if (age < curve2_age)
    return curve_get(ConfigCurve1Interval);

  // Beyond age 2, use interval 2.
  return curve_get(ConfigCurve2Interval);
}

static __inline u64 flow_set_cooldown(struct nf_conn *ct, u64 ts) {

  // Get the update interval for this flow.
  // A negative result indicates that the event should be dropped
  // due to the flow being too young or a failing rate curve lookup.
  s64 interval = flow_get_interval(ct, ts);
  if (interval < 0)
    return 0;

  // Set the cooldown expiration time to the current timestamp plus
  // the cooldown period.
  u64 next = ts + interval;
  bpf_map_update_elem(&flow_cooldown, &ct, &next, BPF_ANY);

  return interval;
}

// flow_status_valid checks if the nf_conn has a non-zero 'status' field.
// When this field is zero, the packet (and flow) are at risk of being dropped
// early and not being inserted into the conntrack table. Conns should be
// ignored until they are valid.
static __inline bool flow_status_valid(struct nf_conn *ct) {
  u32 status;
  bpf_probe_read(&status, sizeof(status), &ct->status);
	return status != 0;
}

// flow_cleanup removes all possible map entries related to the connection.
static __inline void flow_cleanup(struct nf_conn *ct) {
  bpf_map_delete_elem(&flow_cooldown, &ct);
  bpf_map_delete_elem(&flow_origin, &ct);
}

// flow_sample_update samples an update event for an nf_conn.
static __inline u64 flow_sample_update(struct nf_conn *ct, u64 ts, struct pt_regs *ctx) {

  // Ignore flows with a zero status field.
  if (!flow_status_valid(ct))
    return 0;

  // Allocate event struct after all checks have succeeded.
  struct acct_event_t data = {
    .start = 0,
    .ts = ts,
    .cptr = (u64)ct,
  };

  // Pull counters onto the BPF stack first, so that we can make event rate
  // limiting decisions based on packet counters without doing unnecessary work.
  // Return if extracting counters fails, which is possible on untracked flows.
  if (extract_counters(&data, ct))
    return 0;

// Sample accounting events from the kernel using a curve-based rate limiter.
// On every event that is sent, the flow that caused it is given a cooldown
// period during which it cannot send more events. The length of this period
// depends on the age of the flow. The older the flow, the longer the period,
// and the lower the update frequency. The age thresholds and update intervals
// can be configured through the 'config_ratecurve' map.
  u64 pkts_total = (data.packets_orig + data.packets_ret);
  if (pkts_total > 1 && !flow_cooldown_expired(ct, ts))
    return 0;

  // Store a reference timestamp ('origin') to allow future event cycles to
  // determine the age of the flow. This is write-once and will only store
  // a value on the first call of each flow.
  flow_initialize_origin(ct, ts, pkts_total);

  // Set the cooldown expiration to the current timestamp plus a cooldown period
  // based on the age of the flow. flow_set_cooldown returns negative if
  // the event should be dropped due to the flow being too young or
  // because of an internal curve lookup error.
  if (flow_set_cooldown(ct, ts) < 0)
    return 0;

  // Extract proto, src/dst address and ports.
  extract_tuple(&data, ct);
  // Extract network namespace identifier (inode).
  extract_netns(&data, ct);
  // Extract the start timestamp of a flow.
  extract_tstamp(&data, ct);
  // Extract conntrack connection mark.
  bpf_probe_read(&data.connmark, sizeof(data.connmark), &ct->mark);

  // Submit event to userspace.
  bpf_perf_event_output(ctx, &perf_acct_update, BPF_F_CURRENT_CPU, &data, sizeof(data));

  return 0;
}

// __nf_conntrack_hash_insert is called after the conn's start timestamp has
// been calculated and its IPS_CONFIRMED bit has been set. This probe will
// sample the first packet in a flow only, after all policy decisions have been
// made.
//
// This is necessary because __nf_ct_refresh_acct is called very early in the
// call chain and includes flows that might still get dropped from the
// conntrack table for various (protocol-specific) reasons. In both probes,
// we check if the 'status' field is non-zero to avoid sampling packets that
// still need to undergo some policy processing.
SEC("kprobe/__nf_conntrack_hash_insert")
int kprobe____nf_conntrack_hash_insert(struct pt_regs *ctx) {

  if (!probe_ready())
    return 0;

  u64 ts = bpf_ktime_get_ns();

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  return flow_sample_update(ct, ts, ctx);
}

// Top half of the update sampler. Stash the nf_conn pointer to later process
// in a kretprobe after the counters have been updated.
SEC("kprobe/__nf_ct_refresh_acct")
int kprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  if (!probe_ready())
    return 0;

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  u32 pid = bpf_get_current_pid_tgid();

  // stash the conntrack pointer for lookup on return
  bpf_map_update_elem(&currct, &pid, &ct, BPF_ANY);

  return 0;
}

// Bottom half of the update sampler. Extract accounting data from the nf_conn.
SEC("kretprobe/__nf_ct_refresh_acct")
int kretprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  if (!probe_ready())
    return 0;

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

  return flow_sample_update(ct, ts, ctx);
}

// Sample destroy events. This probe sends destroy events to userspace as well
// as cleaning up internal rate limiting bookkeeping for the nf_conn.
SEC("kprobe/destroy_conntrack")
int kprobe__destroy_conntrack(struct pt_regs *ctx) {

  if (!probe_ready())
    return 0;

  u64 ts = bpf_ktime_get_ns();

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  // Remove references to this nf_conn from bookkeeping.
  flow_cleanup(ct);

  // Ignore flows with a zero status field.
  if (!flow_status_valid(ct))
    return 0;

  struct acct_event_t data = {
    .start = 0,
    .ts = ts,
    .cptr = (u64)ct,
  };

  // Ignore the event if the nf_conn doesn't contain counters.
  if (extract_counters(&data, ct))
    return 0;

  extract_tuple(&data, ct);
  extract_netns(&data, ct);
  extract_tstamp(&data, ct);
  bpf_probe_read(&data.connmark, sizeof(data.connmark), &ct->mark);

  bpf_perf_event_output(ctx, &perf_acct_end, BPF_F_CURRENT_CPU, &data, sizeof(data));

  return 0;
}

char _license[] SEC("license") = "GPL";

__u32 _version SEC("version") = 0xFFFFFFFE;
