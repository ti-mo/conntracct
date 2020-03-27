package bpf

import "sync/atomic"

// ProbeStats holds various statistics and information about the
// BPF probe.
type ProbeStats struct {
	// total amount of events received from kernel
	PerfEventsTotal uint64 `json:"perf_events_total"`
	// total amount of bytes read from the BPF perf buffer(s)
	PerfBytesTotal uint64 `json:"perf_bytes_total"`

	// amount of update events received from the kernel
	PerfEventsUpdate uint64 `json:"perf_events_update"`
	// amount of overwritten (lost) events from the perf update buffer
	PerfEventsUpdateLost uint64 `json:"perf_events_update_lost"`
	// amount of destroy events received from the kernel
	PerfEventsDestroy uint64 `json:"perf_events_destroy"`
	// amount of overwritten (lost) events from the perf destroy buffer
	PerfEventsDestroyLost uint64 `json:"perf_events_destroy_lost"`
}

// incrPerfEventsTotal atomically increases the total event counter by one.
func (s *ProbeStats) incrPerfEventsTotal() {
	atomic.AddUint64(&s.PerfEventsTotal, 1)
	atomic.AddUint64(&s.PerfBytesTotal, EventLength)
}

// incrPerfEventsUpdate atomically increases the amount of update events
// read from the BPF perf ring(s).
func (s *ProbeStats) incrPerfEventsUpdate() {
	atomic.AddUint64(&s.PerfEventsUpdate, 1)
	s.incrPerfEventsTotal()
}

// incrPerfEventsUpdateLost atomically increases the amount of lost update
// perf events by the value of count.
func (s *ProbeStats) incrPerfEventsUpdateLost(count uint64) {
	atomic.AddUint64(&s.PerfEventsUpdateLost, count)
}

// incrPerfEventsDestroy atomically increases the amount of destroy events
// read from the BPF perf ring(s).
func (s *ProbeStats) incrPerfEventsDestroy() {
	atomic.AddUint64(&s.PerfEventsDestroy, 1)
	s.incrPerfEventsTotal()
}

// incrPerfEventsDestroyLost atomically increases the amount of lost destroy
// perf events by the value of count.
func (s *ProbeStats) incrPerfEventsDestroyLost(count uint64) {
	atomic.AddUint64(&s.PerfEventsDestroyLost, count)
}

// Get returns a copy of the Stats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *ProbeStats) Get() ProbeStats {
	return ProbeStats{
		PerfEventsTotal:       atomic.LoadUint64(&s.PerfEventsTotal),
		PerfBytesTotal:        atomic.LoadUint64(&s.PerfBytesTotal),
		PerfEventsUpdate:      atomic.LoadUint64(&s.PerfEventsUpdate),
		PerfEventsUpdateLost:  atomic.LoadUint64(&s.PerfEventsUpdateLost),
		PerfEventsDestroy:     atomic.LoadUint64(&s.PerfEventsDestroy),
		PerfEventsDestroyLost: atomic.LoadUint64(&s.PerfEventsDestroyLost),
	}
}
