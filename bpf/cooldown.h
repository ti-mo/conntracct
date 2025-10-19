#pragma once

// Hash that holds a timestamp per flow indicating when the flow
// was first seen. Used to implement age-based event rate limiting.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nf_conn *);
    __type(value, __u64);
    __uint(max_entries, 65535);
} flow_origin SEC(".maps");

// Hash that holds a kernel timestamp per flow indicating when
// the flow may send its next update event to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nf_conn *);
    __type(value, __u64);
    __uint(max_entries, 65535);
} flow_cooldown SEC(".maps");

struct curve_point {
  u64 age, interval;
};

volatile const struct curve_point curve0;
volatile const struct curve_point curve1;
volatile const struct curve_point curve2;

// flow_cooldown_expired returns true if the flow's cooldown period is over.
static __always_inline bool flow_cooldown_expired(struct nf_conn *ct, u64 ts) {
  u64 *nextp = bpf_map_lookup_elem(&flow_cooldown, &ct);
  u64 next = 0;
  if (nextp)
    next = *nextp;

  // Cooldown has expired if the current timestamp is greater
  // or equal than the stored expiration time.
  return (ts >= next);
}


// flow_get_age looks up the flow in the first-seen (origin)
// hashmap. The time elapsed between the origin and the given
// ts is returned. If there is no first-seen timestamp for the
// flow, returns a zero value.
static __always_inline u64 flow_get_age(struct nf_conn *ct, u64 ts) {
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
static __always_inline s64 flow_get_interval(struct nf_conn *ct, u64 ts) {
  // Always returns a positive or 0 value.
  u64 age = flow_get_age(ct, ts);

  // Don't consider flows that are under a minimum age.
  // Return negative interval to signal that the event should be dropped.
  if (age < curve0.age)
    return -1;

  // Between age 0 and age 1, use interval 0.
  if (age < curve1.age)
    return curve0.interval;

  // Between age 1 and age 2, use interval 1.
  if (age < curve2.age)
    return curve1.interval;

  // Beyond age 2, use interval 2.
  return curve2.interval;
}

static __always_inline u64 flow_set_cooldown(struct nf_conn *ct, u64 ts) {
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
