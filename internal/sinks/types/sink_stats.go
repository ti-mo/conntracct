package types

import "sync/atomic"

// SinkStats is an embeddable struct holding an SinkStatsData.
type SinkStats struct {
	data SinkStatsData
}

// SinkStatsData holds performance metrics about the the accounting sink.
type SinkStatsData struct {
	EventsPushed uint64 `json:"events_pushed"`

	BatchLength    uint64 `json:"batch_length"`
	BatchesSent    uint64 `json:"batches_sent"`
	BatchesDropped uint64 `json:"batches_dropped"`
}

// IncrEventsPushed atomically increases the sink's event counter by one.
func (s *SinkStats) IncrEventsPushed() {
	atomic.AddUint64(&s.data.EventsPushed, 1)
}

// SetBatchLength sets the length of the current batch.
func (s *SinkStats) SetBatchLength(l int) {
	atomic.StoreUint64(&s.data.BatchLength, uint64(l))
}

// IncrBatchDropped atomically increases the sink's dropped batch counter by one.
func (s *SinkStats) IncrBatchDropped() {
	atomic.AddUint64(&s.data.BatchesDropped, 1)
}

// IncrBatchSent atomically increases the sink's sent batch counter by one.
func (s *SinkStats) IncrBatchSent() {
	atomic.AddUint64(&s.data.BatchesSent, 1)
}

// Get returns a non-atomic snapshot of the stats data.
func (s *SinkStats) Get() SinkStatsData {
	return SinkStatsData{
		EventsPushed:   atomic.LoadUint64(&s.data.EventsPushed),
		BatchLength:    atomic.LoadUint64(&s.data.BatchLength),
		BatchesSent:    atomic.LoadUint64(&s.data.BatchesSent),
		BatchesDropped: atomic.LoadUint64(&s.data.BatchesDropped),
	}
}
