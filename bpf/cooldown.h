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

enum o_config_ratecurve {
  ConfigCurve0Age,
  ConfigCurve0Interval,
  ConfigCurve1Age,
  ConfigCurve1Interval,
  ConfigCurve2Age,
  ConfigCurve2Interval,
  ConfigCurveMax,
};

// Array holding pairs of (age, interval) values,
// used for age-based rate limiting.
// Indexed by enum o_config_ratecurve.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, enum o_config_ratecurve);
    __type(value, __u64);
    __uint(max_entries, ConfigCurveMax);
} config_ratecurve SEC(".maps");

// curve_get returns an entry from the curve array as a signed 64-bit integer.
// Returns negative if an entry was not found at the requested index.
static __always_inline s64 curve_get(enum o_config_ratecurve curve_enum) {
  int offset = curve_enum;
  u64 *confp = bpf_map_lookup_elem(&config_ratecurve, &offset);
  if (confp)
    return *confp;

  return -1;
}

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
