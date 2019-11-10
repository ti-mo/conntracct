package elasticsearch

import (
	"time"
)

// sendWorker receives batches from the sink's send channel
// and uses the elasticsearch client to send it to the database.
func (s *ElasticSink) sendWorker() {

	for {

		// Read an event from the send queue.
		<-s.sendChan

		// Store the size of the send queue.
		s.stats.SetBatchQueueLength(len(s.sendChan))

		// Create an elastic bulk request.

		// Serialize all events in the batch.

		// Send the request.

		// Increase dropped batch counter.
		s.stats.IncrBatchDropped()
		// // Increase sent batch counter.
		// s.stats.IncrBatchSent()
	}
}

// tickWorker starts a ticker that periodically flushes the active batch.
// If the batch is empty when the ticker fires, no action is taken.
func (s *ElasticSink) tickWorker() {

	t := time.NewTicker(time.Second)

	for {
		<-t.C

		s.batchMu.Lock()

		// Only flush the batch when it contains points.
		if len(s.batch) != 0 {
			s.flushBatch()
		}

		s.batchMu.Unlock()
	}
}
