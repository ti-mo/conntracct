package pipeline

import (
	"sync/atomic"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// Stats holds various statistics and information about the
// data processing pipeline.
type Stats struct {

	// total amount of event structs received from kernel
	EventsTotal uint64 `json:"events_total"`
	// total amount of bytes read from the BPF perf buffer(s)
	BytesTotal uint64 `json:"bytes_total"`

	// update events / bytes
	EventsUpdate uint64 `json:"events_update"`
	BytesUpdate  uint64 `json:"bytes_update"`

	// destroy events / bytes
	EventsDestroy uint64 `json:"events_destroy"`
	BytesDestroy  uint64 `json:"bytes_destroy"`

	// length of the Event queues
	UpdateQueueLen  uint64 `json:"update_queue_length"`
	DestroyQueueLen uint64 `json:"destroy_queue_length"`
}

// incrEventsTotal atomically increases the total event counter by one.
func (s *Stats) incrEventsTotal() {
	atomic.AddUint64(&s.EventsTotal, 1)
	atomic.AddUint64(&s.BytesTotal, bpf.EventLength)
}

// IncrEventsUpdate atomically increases the amount of update events
// read from the BPF perf ring(s).
func (s *Stats) IncrEventsUpdate() {
	atomic.AddUint64(&s.EventsUpdate, 1)
	atomic.AddUint64(&s.BytesUpdate, bpf.EventLength)
	s.incrEventsTotal()
}

// IncrEventsDestroy atomically increases the amount of destroy events
// read from the BPF perf ring(s).
func (s *Stats) IncrEventsDestroy() {
	atomic.AddUint64(&s.EventsDestroy, 1)
	atomic.AddUint64(&s.BytesDestroy, bpf.EventLength)
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
		BytesTotal:      atomic.LoadUint64(&s.BytesTotal),
		EventsUpdate:    atomic.LoadUint64(&s.EventsUpdate),
		BytesUpdate:     atomic.LoadUint64(&s.BytesUpdate),
		EventsDestroy:   atomic.LoadUint64(&s.EventsDestroy),
		BytesDestroy:    atomic.LoadUint64(&s.BytesDestroy),
		UpdateQueueLen:  atomic.LoadUint64(&s.UpdateQueueLen),
		DestroyQueueLen: atomic.LoadUint64(&s.DestroyQueueLen),
	}
}
