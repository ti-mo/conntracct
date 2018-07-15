package sinks

import "sync"

// AcctSinkStats is an embeddable struct holding an AcctSinkStatsData
// and a lock that serves as a write barrier to the data structure.
type AcctSinkStats struct {

	// monitoring and bookkeeping stats
	// member is exported to allow consumers to sidestep write barrier,
	// eg. update multiple counters in one transaction
	Data AcctSinkStatsData

	// mutex for stats operations
	statsLock sync.Mutex
}

// AcctSinkStatsData holds performance metrics about the the accounting sink.
type AcctSinkStatsData struct {
	EventsPushed uint64 `json:"events_pushed"`

	BatchLength    int    `json:"batch_length"`
	BatchesSent    uint64 `json:"batches_sent"`
	BatchesDropped uint64 `json:"batches_dropped"`
}

// Lock the write barrier of the statistics data.
func (s *AcctSinkStats) Lock() {
	s.statsLock.Lock()
}

// Unlock the write barrier of the statistics data.
func (s *AcctSinkStats) Unlock() {
	s.statsLock.Unlock()
}

// IncrEventsPushed atomically increases the sink's event counter by one.
// Do not call while holding a stats lock.
func (s *AcctSinkStats) IncrEventsPushed() {
	s.statsLock.Lock()
	s.Data.EventsPushed++
	s.statsLock.Unlock()
}

// SetBatchLength sets the length of the current batch.
// Do not call while holding a stats lock.
func (s *AcctSinkStats) SetBatchLength(l int) {
	s.statsLock.Lock()
	s.Data.BatchLength = l
	s.statsLock.Unlock()
}

// IncrBatchDropped atomically increases the sink's dropped batch counter by one.
// Do not call while holding a stats lock.
func (s *AcctSinkStats) IncrBatchDropped() {
	s.statsLock.Lock()
	s.Data.BatchesDropped++
	s.statsLock.Unlock()
}

// IncrBatchSent atomically increases the sink's sent batch counter by one.
// Do not call while holding a stats lock.
func (s *AcctSinkStats) IncrBatchSent() {
	s.statsLock.Lock()
	s.Data.BatchesSent++
	s.statsLock.Unlock()
}
