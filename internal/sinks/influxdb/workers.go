package influxdb

import log "github.com/sirupsen/logrus"

// sendWorker receives batches from the sink's send channel
// and uses the InfluxDB client to send it to the database.
func (s *InfluxAcctSink) sendWorker() {

	for {

		b := <-s.sendChan

		// Write the batch
		if err := s.client.Write(b); err != nil {
			log.Errorf("InfluxDB sink '%s': Error writing batch: %s. Batch dropped.", s.name, err)

			// Increase dropped batch counter
			s.IncrBatchDropped()
			continue
		}

		// Increase sent batch counter
		s.IncrBatchSent()
	}
}
