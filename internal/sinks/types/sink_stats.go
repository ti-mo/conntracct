package types

import "sync/atomic"

// SinkStats holds performance metrics about an accounting sink.
// All values are updated using atomic operations, so always use sync/atomic's
// Load*() methods to read values from the structure. The Get() convenience
// method returns a new instance of itself using atomic loads.
type SinkStats struct {
	// Amount of events Push()ed into the sink.
	EventsPushed uint64 `json:"events_pushed"`
	// Amount of events failed to be Push()ed into the sink.
	EventsDropped uint64 `json:"events_dropped"`

	// Current batch length of the sink.
	BatchLength uint64 `json:"batch_length"`
	// Amount of batches sent.
	BatchesSent uint64 `json:"batches_sent"`
	// Amount of batches failed to be sent.
	BatchesDropped uint64 `json:"batches_dropped"`
}

// IncrEventsPushed atomically increases the sink's event counter by one.
func (s *SinkStats) IncrEventsPushed() {
	atomic.AddUint64(&s.EventsPushed, 1)
}

// IncrEventsDropped atomically increases the sink's dropped event counter by one.
func (s *SinkStats) IncrEventsDropped() {
	atomic.AddUint64(&s.EventsDropped, 1)
}

// SetBatchLength sets the length of the current batch.
func (s *SinkStats) SetBatchLength(l int) {
	atomic.StoreUint64(&s.BatchLength, uint64(l))
}

// IncrBatchDropped atomically increases the sink's dropped batch counter by one.
func (s *SinkStats) IncrBatchDropped() {
	atomic.AddUint64(&s.BatchesDropped, 1)
}

// IncrBatchSent atomically increases the sink's sent batch counter by one.
func (s *SinkStats) IncrBatchSent() {
	atomic.AddUint64(&s.BatchesSent, 1)
}

// Get returns a copy of the SinkStats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *SinkStats) Get() SinkStats {
	return SinkStats{
		EventsPushed:   atomic.LoadUint64(&s.EventsPushed),
		EventsDropped:  atomic.LoadUint64(&s.EventsDropped),
		BatchLength:    atomic.LoadUint64(&s.BatchLength),
		BatchesSent:    atomic.LoadUint64(&s.BatchesSent),
		BatchesDropped: atomic.LoadUint64(&s.BatchesDropped),
	}
}
