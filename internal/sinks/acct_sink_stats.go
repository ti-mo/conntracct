package sinks

import "sync/atomic"

// AcctSinkStats is an embeddable struct holding an AcctSinkStatsData.
type AcctSinkStats struct {
	data AcctSinkStatsData
}

// AcctSinkStatsData holds performance metrics about the the accounting sink.
type AcctSinkStatsData struct {
	EventsPushed uint64 `json:"events_pushed"`

	BatchLength    uint64 `json:"batch_length"`
	BatchesSent    uint64 `json:"batches_sent"`
	BatchesDropped uint64 `json:"batches_dropped"`
}

// IncrEventsPushed atomically increases the sink's event counter by one.
func (s *AcctSinkStats) IncrEventsPushed() {
	atomic.AddUint64(&s.data.EventsPushed, 1)
}

// SetBatchLength sets the length of the current batch.
func (s *AcctSinkStats) SetBatchLength(l int) {
	atomic.StoreUint64(&s.data.BatchLength, uint64(l))
}

// IncrBatchDropped atomically increases the sink's dropped batch counter by one.
func (s *AcctSinkStats) IncrBatchDropped() {
	atomic.AddUint64(&s.data.BatchesDropped, 1)
}

// IncrBatchSent atomically increases the sink's sent batch counter by one.
func (s *AcctSinkStats) IncrBatchSent() {
	atomic.AddUint64(&s.data.BatchesSent, 1)
}

// Get returns a non-atomic snapshot of the stats data.
func (s *AcctSinkStats) Get() AcctSinkStatsData {
	return AcctSinkStatsData{
		EventsPushed:   atomic.LoadUint64(&s.data.EventsPushed),
		BatchLength:    atomic.LoadUint64(&s.data.BatchLength),
		BatchesSent:    atomic.LoadUint64(&s.data.BatchesSent),
		BatchesDropped: atomic.LoadUint64(&s.data.BatchesDropped),
	}
}
