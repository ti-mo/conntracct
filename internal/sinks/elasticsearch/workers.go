package elasticsearch

import (
	"context"
	"time"

	elastic "github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"
)

// sendWorker receives batches from the sink's send channel
// and uses the elasticsearch client to send it to the database.
func (s *ElasticSink) sendWorker() {

	for {

		// Read a batch from the send queue.
		batch := <-s.sendChan

		// Store the size of the send queue.
		s.stats.SetBatchQueueLength(len(s.sendChan))

		// Create an elastic bulk request.
		// TODO(timo): Make the index name configurable and dynamic.
		bulk := s.client.Bulk().Index("conntracct")

		// Create index requests for each event in the batch.
		reqs := make([]elastic.BulkableRequest, 0, len(batch))
		for _, e := range batch {
			reqs = append(reqs, elastic.NewBulkIndexRequest().Doc(e))
		}

		// Add all index requests to the bulk request.
		bulk.Add(reqs...)

		// Send the request.
		resp, err := bulk.Do(context.Background())
		if err != nil {
			// Increase dropped batch counter.
			s.stats.IncrBatchDropped()
			log.WithField("sink", s.config.Name).Error("error sending batch: ", err.Error())
			continue
		}

		// Increase sent batch counter.
		s.stats.IncrBatchSent()

		// Check for requests that failed to index.
		failed := resp.Failed()
		if len(failed) != 0 {
			for _, f := range failed {
				// Increase the counter of events that failed to be indexed.
				s.stats.IncrBatchEventsFailed()
				log.WithField("sink", s.config.Name).WithField("type", f.Error.Type).
					WithField("status", f.Status).Error("error indexing event: ", f.Error.Reason)
			}
		}
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
