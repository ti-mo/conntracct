package bpf

import "sync/atomic"

// Stats holds various statistics and information about the
// BPF probe.
type Stats struct {
	// total amount of events received from kernel
	PerfEventsTotal uint64 `json:"perf_events_total"`
	// total amount of bytes read from the BPF perf buffer(s)
	PerfBytesTotal uint64 `json:"perf_bytes_total"`
	// amount of overwritten (lost) events from the BPF perf buffer(s)
	PerfEventsLost uint64 `json:"perf_events_lost"`

	// amount of update events received from the kernel
	PerfEventsUpdate uint64 `json:"perf_events_update"`
	// amount of destroy events received from the kernel
	PerfEventsDestroy uint64 `json:"perf_events_destroy"`
}

// incrPerfEventsTotal atomically increases the total event counter by one.
func (s *Stats) incrPerfEventsTotal() {
	atomic.AddUint64(&s.PerfEventsTotal, 1)
	atomic.AddUint64(&s.PerfBytesTotal, EventLength)
}

// IncrPerfEventsUpdate atomically increases the amount of update events
// read from the BPF perf ring(s).
func (s *Stats) incrPerfEventsUpdate() {
	atomic.AddUint64(&s.PerfEventsUpdate, 1)
	s.incrPerfEventsTotal()
}

// IncrPerfEventsDestroy atomically increases the amount of destroy events
// read from the BPF perf ring(s).
func (s *Stats) incrPerfEventsDestroy() {
	atomic.AddUint64(&s.PerfEventsDestroy, 1)
	s.incrPerfEventsTotal()
}

// IncrPerfEventsLost atomically increases the amount of lost perf events.
func (s *Stats) incrPerfEventsLost() {
	atomic.AddUint64(&s.PerfEventsLost, 1)
}

// Get returns a copy of the Stats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *Stats) Get() Stats {
	return Stats{
		PerfEventsTotal:   atomic.LoadUint64(&s.PerfEventsTotal),
		PerfBytesTotal:    atomic.LoadUint64(&s.PerfBytesTotal),
		PerfEventsLost:    atomic.LoadUint64(&s.PerfEventsLost),
		PerfEventsUpdate:  atomic.LoadUint64(&s.PerfEventsUpdate),
		PerfEventsDestroy: atomic.LoadUint64(&s.PerfEventsDestroy),
	}
}
