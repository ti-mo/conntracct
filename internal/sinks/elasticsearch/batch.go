package elasticsearch

// batch is a batch of events.
type batch []*event

// newBatch allocates a new InfluxDB point batch to the sink structure.
func (s *ElasticSink) newBatch() {
	// Allocate new batch and write it to the sink.
	s.batch = make(batch, 0, s.config.BatchSize)
	s.stats.SetBatchLength(0)
}

// addBatchEvent adds the given event to the current batch.
// If the operation causes the batch watermark to be reached,
// the batch is flushed. Do not call while holding batchMu.
func (s *ElasticSink) addBatchEvent(e *event) {

	s.batchMu.Lock()

	// Add the given point to the current batch.
	s.batch = append(s.batch, e)

	// Record the current batch length.
	batchLen := len(s.batch)
	s.stats.SetBatchLength(batchLen)

	// Flush the batch when the watermark is reached.
	if batchLen >= int(s.config.BatchSize) {
		s.flushBatch()
	}

	s.batchMu.Unlock()
}

// flushBatch sends the current batch to the send worker
// and allocates a new batch into the sink structure.
func (s *ElasticSink) flushBatch() {
	// Non-blocking send on sendChan.
	select {
	case s.sendChan <- s.batch:
		s.stats.IncrBatchesQueued()
		s.stats.SetBatchQueueLength(len(s.sendChan))
	default:
		// Log a dropped batch if no receiver is ready.
		s.stats.IncrBatchDropped()
	}

	// Allocate a new batch into the sink.
	s.newBatch()
}
