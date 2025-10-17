#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#include "acct.h"

enum o_config {
  ConfigReady,
  ConfigMax,
};

// Magic value that userspace writes into the ConfigReady location when
// configuration from userspace has completed.
const int ready_val = 0x90;

// perf map to send update events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(value, struct event);
} perf_acct_update SEC(".maps");

// perf map to send destroy events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(value, struct event);
} perf_acct_end SEC(".maps");

// Map holding configuration values for this BPF program.
// Indexed by enum o_config.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, enum o_config);
    __type(value, __u64);
    __uint(max_entries, ConfigMax);
} config SEC(".maps");

// probe_ready reads the `config` array map for the Ready flag.
// It returns true if the Ready flag is set to 0x90 (go).
static __always_inline bool probe_ready() {
  u64 oc_ready = ConfigReady;
  u64 *rp = bpf_map_lookup_elem(&config, &oc_ready);

  return (rp && *rp == ready_val);
}

// flow_sample sends an event for ct with the given type.
static __always_inline void flow_sample(u64 *ctx, struct nf_conn *ct, enum event_type type) {
  if (!ct_valid(ct))
    return;

  // Allocate event struct after all checks have succeeded.
  struct event data = {
    .ts = bpf_ktime_get_ns(),
    .cptr = (u64)ct,
    .netns = ct->ct_net.net->ns.inum,
    .connmark = ct->mark,
  };

  // Pull counters onto the BPF stack first, so that we can make event rate
  // limiting decisions based on packet counters without doing unnecessary work.
  // Return if extracting counters fails, which is possible on untracked flows.
  if (!extract_extensions(&data, ct))
    return;

  if (type != CT_DESTROY) {
    // Sample accounting events from the kernel using a curve-based rate limiter.
    // On every event that is sent, the flow that caused it is given a cooldown
    // period during which it cannot send more events. The length of this period
    // depends on the age of the flow. The older the flow, the longer the period,
    // and the lower the update frequency. The age thresholds and update intervals
    // can be configured through the 'config_ratecurve' map.
    u64 pkts_total = (data.packets_orig + data.packets_ret);
    if (pkts_total > 1 && !flow_cooldown_expired(ct, data.ts))
      return;

    // Store a reference timestamp ('origin') to allow future event cycles to
    // determine the age of the flow. This is write-once and will only store
    // a value on the first call of each flow.
    flow_initialize_origin(ct, data.ts, pkts_total);

    // Set the cooldown expiration to the current timestamp plus a cooldown period
    // based on the age of the flow. flow_set_cooldown returns negative if
    // the event should be dropped due to the flow being too young or
    // because of an internal curve lookup error.
    if (flow_set_cooldown(ct, data.ts) < 0)
      return;
  }

  extract_tuple(&data, ct);

  if (type != CT_DESTROY)
    bpf_perf_event_output(ctx, &perf_acct_update, BPF_F_CURRENT_CPU, &data, sizeof(data));
  else
    bpf_perf_event_output(ctx, &perf_acct_end, BPF_F_CURRENT_CPU, &data, sizeof(data));

  return;
}

// __nf_conntrack_confirm sets the flow's IPS_CONFIRMED bit. This probe will
// sample the first packet in a flow only, after all policy decisions have been
// made.
SEC("fexit/__nf_conntrack_confirm")
int BPF_PROG(ct_new, struct sk_buff *skb) {
  if (!probe_ready())
    return 0;

  struct nf_conn *ct = skb_get_ct(skb);
  if (ct == NULL)
    return 0;

  flow_sample(ctx, ct, CT_NEW);

  return 0;
}

// __nf_ct_refresh_acct bumps acct counters.
SEC("fexit/__nf_ct_refresh_acct")
int BPF_PROG(ct_update, struct nf_conn *ct) {
  if (!probe_ready())
    return 0;

  flow_sample(ctx, ct, CT_UPDATE);

  return 0;
}

// nf_conntrack_free is the single funnel all conntrack teardown paths go
// through: gc worker expiry, lookup-time expiry, ctnetlink deletes, TCP
// RST/FIN kills, early drop and netns cleanup. Hooking it at function entry
// guarantees exactly one destroy event per flow, with the ct's extensions
// still intact; they are freed inside nf_conntrack_free itself.
//
// Expired flows are reaped lazily by the conntrack gc worker, so destroy
// events can arrive in batches long after a flow last saw traffic. The
// event's ts field records the time the flow was reaped, not when it went
// idle.
//
// Unconfirmed conntracks (e.g. clash resolution losers) are also freed
// through this path; flow_sample discards them via the IPS_CONFIRMED check
// in ct_valid.
SEC("fentry/nf_conntrack_free")
int BPF_PROG(ct_destroy, struct nf_conn *ct) {
  if (!probe_ready())
    return 0;

  flow_sample(ctx, ct, CT_DESTROY);

  flow_cleanup(ct);

  return 0;
}

char _license[] SEC("license") = "GPL";
