package bpf

import "sync/atomic"

// ConsumerStats holds various statistics and information about the
// BPF consumer.
type ConsumerStats struct {
	// amount of events received by the consumer
	EventsReceived uint64 `json:"events_received"`
	// amount of events that could not be received by the consumer
	EventsLost uint64 `json:"events_lost"`
	// length of the consumer's event queue
	EventQueueLength uint64 `json:"event_queue_length"`
}

// incrEventsReceived atomically increases the events received counter by one.
func (s *ConsumerStats) incrEventsReceived() {
	atomic.AddUint64(&s.EventsReceived, 1)
}

// incrEventsLost atomically increases the events lost counter by one.
func (s *ConsumerStats) incrEventsLost() {
	atomic.AddUint64(&s.EventsLost, 1)
}

// setQueueLength atomically sets the queue length of the consumer.
func (s *ConsumerStats) setQueueLength(l int) {
	atomic.StoreUint64(&s.EventQueueLength, uint64(l))
}

// Get returns a copy of the ConsumerStats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *ConsumerStats) Get() ConsumerStats {
	return ConsumerStats{
		EventsReceived:   atomic.LoadUint64(&s.EventsReceived),
		EventsLost:       atomic.LoadUint64(&s.EventsLost),
		EventQueueLength: atomic.LoadUint64(&s.EventQueueLength),
	}
}
