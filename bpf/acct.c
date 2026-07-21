#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#include "acct.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
  __type(value, struct event);
} ringbuf SEC(".maps");

// flow_sample sends an event for ct with the given type.
static __always_inline void flow_sample(struct nf_conn *ct, enum event_type type) {
  if (!ct_valid(ct))
    return;

  u64 ts = bpf_ktime_get_ns();
  struct nf_conn_acct *acct = ct_get_acct(ct);

  if (type != CT_DESTROY) {
    struct packets packets;
    if (!packets_read_acct(&packets, acct))
      return;

    // Sample accounting events from the kernel using a curve-based rate limiter.
    // On every event that is sent, the flow that caused it is given a cooldown
    // period during which it cannot send more events. The length of this period
    // depends on the age of the flow. The older the flow, the longer the period,
    // and the lower the update frequency. The age thresholds and update intervals
    // can be configured through the 'config_ratecurve' map.
    if (packets.total > 1 && !flow_cooldown_expired(ct, ts))
      return;

    // Store a reference timestamp ('origin') to allow future event cycles to
    // determine the age of the flow. This is write-once and will only store
    // a value on the first call of each flow.
    flow_initialize_origin(ct, ts, packets.total);

    // Set the cooldown expiration to the current timestamp plus a cooldown period
    // based on the age of the flow. flow_set_cooldown returns negative if
    // the event should be dropped due to the flow being too young or
    // because of an internal curve lookup error.
    if (flow_set_cooldown(ct, ts) < 0)
      return;
  }

  // Allocate event struct after all checks have succeeded.
  struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
  if (!e)
    return;

  *e = (struct event){
    .type = type,
    .ts = ts,
    .netns = ct->ct_net.net->ns.inum,
    .connmark = ct->mark,
  };

  if (!data_read_acct(e, ct_get_acct(ct)))
    goto release;

  if (!data_read_tstamp(e, ct_get_tstamp(ct)))
    goto release;

  extract_tuple(e, ct);

  bpf_ringbuf_submit(e, 0);

  return;

release:
  bpf_ringbuf_discard(e, 0);
  return;
}

// __nf_conntrack_confirm sets the flow's IPS_CONFIRMED bit. This probe will
// sample the first packet in a flow only, after all policy decisions have been
// made.
SEC("fexit/__nf_conntrack_confirm")
int BPF_PROG(ct_new, struct sk_buff *skb) {
  struct nf_conn *ct = skb_get_ct(skb);
  if (ct == NULL)
    return 0;

  flow_sample(ct, CT_NEW);

  return 0;
}

// __nf_ct_refresh_acct bumps acct counters.
SEC("fexit/__nf_ct_refresh_acct")
int BPF_PROG(ct_update, struct nf_conn *ct) {
  flow_sample(ct, CT_UPDATE);

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
  flow_sample(ct, CT_DESTROY);

  flow_cleanup(ct);

  return 0;
}

char _license[] SEC("license") = "GPL";
