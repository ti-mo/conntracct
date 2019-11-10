package influxdb

import influx "github.com/influxdata/influxdb/client/v2"

// newBatch allocates a new InfluxDB point batch to the sink structure.
func (s *InfluxSink) newBatch() {

	b, err := influx.NewBatchPoints(influx.BatchPointsConfig{
		Precision: "ns", // nanosecond precision timestamps
		Database:  s.config.Database,
	})

	if err != nil {
		panic(err)
	}

	s.batch = b
	s.stats.SetBatchLength(0)
}

// addBatchPoint adds the given point to the current batch.
// If the operation causes the batch watermark to be reached,
// the batch is flushed. Do not call while holding batchMu.
func (s *InfluxSink) addBatchPoint(pt *influx.Point) {

	s.batchMu.Lock()

	// Add the given point to the current batch.
	s.batch.AddPoint(pt)

	// Record the current batch length.
	batchLen := len(s.batch.Points())
	s.stats.SetBatchLength(batchLen)

	// Flush the batch when the watermark is reached.
	if batchLen >= int(s.config.BatchSize) {
		s.flushBatch()
	}

	s.batchMu.Unlock()
}

// flushBatch sends the current batch to the send worker
// and allocates a new batch into the sink structure.
func (s *InfluxSink) flushBatch() {
	// Non-blocking send on sendChan.
	select {
	case s.sendChan <- s.batch:
	default:
		// Log a dropped batch if no receiver is ready.
		s.stats.IncrBatchDropped()
	}

	// Allocate a new batch into the sink.
	s.newBatch()
}
