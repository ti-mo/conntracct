package types

import "sync/atomic"

// SinkStats holds performance metrics about an accounting sink.
// All values are updated using atomic operations, so always use sync/atomic's
// Load*() methods to read values from the structure. The Get() convenience
// method returns a new instance of itself using atomic loads.
type SinkStats struct {
	// Amount of update events pushed into the sink.
	UpdateEventsPushed uint64 `json:"update_events_pushed"`
	// Amount of destroy events pushed into the sink.
	DestroyEventsPushed uint64 `json:"destroy_events_pushed"`

	// Amount of update events failed to be pushed into the sink.
	UpdateEventsDropped uint64 `json:"update_events_dropped"`
	// Amount of destroy events failed to be pushed into the sink.
	DestroyEventsDropped uint64 `json:"destroy_events_dropped"`

	// Current batch length of the sink.
	BatchLength uint64 `json:"batch_length"`

	// Amount of batches queued to be sent over the network.
	BatchesQueued uint64 `json:"batches_queued"`
	// Length of the network send queue.
	BatchQueueLength uint64 `json:"batch_queue_length"`

	// Amount of batches sent.
	BatchesSent uint64 `json:"batches_sent"`
	// Amount of batches failed to be sent.
	BatchesDropped uint64 `json:"batches_dropped"`
}

// IncrUpdateEventsPushed atomically increases the sink's update event counter by one.
func (s *SinkStats) IncrUpdateEventsPushed() {
	atomic.AddUint64(&s.UpdateEventsPushed, 1)
}

// IncrDestroyEventsPushed atomically increases the sink's destroy event counter by one.
func (s *SinkStats) IncrDestroyEventsPushed() {
	atomic.AddUint64(&s.DestroyEventsPushed, 1)
}

// IncrUpdateEventsDropped atomically increases the sink's dropped update event counter by one.
func (s *SinkStats) IncrUpdateEventsDropped() {
	atomic.AddUint64(&s.UpdateEventsDropped, 1)
}

// IncrDestroyEventsDropped atomically increases the sink's dropped destroy event counter by one.
func (s *SinkStats) IncrDestroyEventsDropped() {
	atomic.AddUint64(&s.DestroyEventsDropped, 1)
}

// SetBatchLength sets the length of the current batch.
func (s *SinkStats) SetBatchLength(l int) {
	atomic.StoreUint64(&s.BatchLength, uint64(l))
}

// IncrBatchesQueued atomically increases the sink's batches queued counter by one.
func (s *SinkStats) IncrBatchesQueued() {
	atomic.AddUint64(&s.BatchesQueued, 1)
}

// SetBatchQueueLength sets the length of the batch send queue.
func (s *SinkStats) SetBatchQueueLength(l int) {
	atomic.StoreUint64(&s.BatchQueueLength, uint64(l))
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
		UpdateEventsPushed:   atomic.LoadUint64(&s.UpdateEventsPushed),
		DestroyEventsPushed:  atomic.LoadUint64(&s.DestroyEventsPushed),
		UpdateEventsDropped:  atomic.LoadUint64(&s.UpdateEventsDropped),
		DestroyEventsDropped: atomic.LoadUint64(&s.DestroyEventsDropped),
		BatchLength:          atomic.LoadUint64(&s.BatchLength),
		BatchesQueued:        atomic.LoadUint64(&s.BatchesQueued),
		BatchQueueLength:     atomic.LoadUint64(&s.BatchQueueLength),
		BatchesSent:          atomic.LoadUint64(&s.BatchesSent),
		BatchesDropped:       atomic.LoadUint64(&s.BatchesDropped),
	}
}
