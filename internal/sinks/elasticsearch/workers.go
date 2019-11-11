package elasticsearch

import (
	"time"
)

// sendWorker receives batches from the sink's send channel
// and uses the elasticsearch client to send it to the database.
func (s *ElasticSink) sendWorker() {

	for {

		// Read a batch from the send queue.
		batch := <-s.sendChan

		// Store the size of the send queue.
		s.stats.SetBatchQueueLength(len(s.sendChan))

		// Send the batch.
		s.sendBatch(batch)
	}
}

// tickWorker starts a ticker that periodically flushes the active batch.
// If the batch is empty when the ticker fires, no action is taken.
func (s *ElasticSink) tickWorker(interval time.Duration) {

	t := time.NewTicker(interval)

	for {
		<-t.C

		s.batchMu.Lock()
		s.flushBatch()
		s.batchMu.Unlock()
	}
}
