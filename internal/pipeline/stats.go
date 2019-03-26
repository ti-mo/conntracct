package pipeline

import (
	"sync/atomic"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// Stats holds various statistics and information about the
// data processing pipeline.
type Stats struct {

	// amount of event structs received from kernel
	EventsTotal   uint64 `json:"events_total"`
	EventsUpdate  uint64 `json:"events_update"`
	EventsDestroy uint64 `json:"events_destroy"`

	UpdateSourceStats  *bpf.ConsumerStats `json:"update_source"`
	DestroySourceStats *bpf.ConsumerStats `json:"destroy_source"`
}

// incrEventsTotal atomically increases the total event counter by one.
func (s *Stats) incrEventsTotal() {
	atomic.AddUint64(&s.EventsTotal, 1)
}

// IncrEventsUpdate atomically increases the amount of update events
// read from the BPF perf ring(s).
func (s *Stats) IncrEventsUpdate() {
	atomic.AddUint64(&s.EventsUpdate, 1)
	s.incrEventsTotal()
}

// IncrEventsDestroy atomically increases the amount of destroy events
// read from the BPF perf ring(s).
func (s *Stats) IncrEventsDestroy() {
	atomic.AddUint64(&s.EventsDestroy, 1)
	s.incrEventsTotal()
}

// Get returns a copy of the Stats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *Stats) Get() Stats {

	out := Stats{
		EventsTotal:   atomic.LoadUint64(&s.EventsTotal),
		EventsUpdate:  atomic.LoadUint64(&s.EventsUpdate),
		EventsDestroy: atomic.LoadUint64(&s.EventsDestroy),
	}

	// Get Update source stats if present.
	if s.UpdateSourceStats != nil {
		s := s.UpdateSourceStats.Get()
		out.UpdateSourceStats = &s
	}

	// Get Destroy source stats if present.
	if s.DestroySourceStats != nil {
		s := s.DestroySourceStats.Get()
		out.DestroySourceStats = &s
	}

	return out
}
