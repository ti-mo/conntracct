package pipeline

import (
	"sync/atomic"
)

// Stats holds various statistics and information about the
// data processing pipeline.
type Stats struct {

	// amount of event structs received from kernel
	EventsTotal   uint64 `json:"events_total"`
	EventsUpdate  uint64 `json:"events_update"`
	EventsDestroy uint64 `json:"events_destroy"`

	// length of the Event queues
	UpdateQueueLen  uint64 `json:"update_queue_length"`
	DestroyQueueLen uint64 `json:"destroy_queue_length"`
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

// SetUpdateQueueLen atomically sets the update queue length.
func (s *Stats) SetUpdateQueueLen(l int) {
	atomic.StoreUint64(&s.UpdateQueueLen, uint64(l))
}

// SetDestroyQueueLen atomically sets the update queue length.
func (s *Stats) SetDestroyQueueLen(l int) {
	atomic.StoreUint64(&s.DestroyQueueLen, uint64(l))
}

// Get returns a copy of the Stats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *Stats) Get() Stats {
	return Stats{
		EventsTotal:     atomic.LoadUint64(&s.EventsTotal),
		EventsUpdate:    atomic.LoadUint64(&s.EventsUpdate),
		EventsDestroy:   atomic.LoadUint64(&s.EventsDestroy),
		UpdateQueueLen:  atomic.LoadUint64(&s.UpdateQueueLen),
		DestroyQueueLen: atomic.LoadUint64(&s.DestroyQueueLen),
	}
}
