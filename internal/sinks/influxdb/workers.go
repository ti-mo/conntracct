package influxdb

import (
	"time"

	log "github.com/sirupsen/logrus"
)

// sendWorker receives batches from the sink's send channel
// and uses the InfluxDB client to send it to the database.
func (s *InfluxSink) sendWorker() {

	for {

		b := <-s.sendChan

		// Store the size of the send queue.
		s.stats.SetBatchQueueLength(len(s.sendChan))

		// Write the batch
		if err := s.client.Write(b); err != nil {
			log.Errorf("InfluxDB sink '%s': Error writing batch: %s. Batch dropped.", s.config.Name, err)

			// Increase dropped batch counter.
			s.stats.IncrBatchDropped()
			continue
		}

		// Increase sent batch counter.
		s.stats.IncrBatchSent()
	}
}

// tickWorker starts a ticker that periodically flushes the active batch.
// If the batch is empty when the ticker fires, no action is taken.
func (s *InfluxSink) tickWorker() {

	t := time.NewTicker(time.Second)

	for {
		<-t.C

		s.batchMu.Lock()

		// Only flush the batch when it contains points.
		if len(s.batch.Points()) != 0 {
			s.flushBatch()
		}

		s.batchMu.Unlock()
	}
}
