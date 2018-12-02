package influxdb

import (
	"strconv"
	"sync"
	"time"

	influx "github.com/influxdata/influxdb/client/v2"
	"gitlab.com/0ptr/conntracct/internal/sinks"
	"gitlab.com/0ptr/conntracct/pkg/bpf"
)

const (
	defaultBatchWatermark = 128
)

// InfluxAcctSink is an accounting sink implementing an InfluxDB client.
type InfluxAcctSink struct {

	// name of the sink
	name string

	// sink had Init() called on it successfully
	init bool

	// reference to the sink's configuration
	config sinks.AcctSinkConfig

	// influx driver client handle
	client influx.Client

	// channel the workers receive influx batches on
	sendChan chan influx.BatchPoints

	// data point batch
	batchMu sync.Mutex
	batch   influx.BatchPoints

	// sink stats
	stats sinks.AcctSinkStats
}

// Init initializes the InfluxDB accounting sink.
func (s *InfluxAcctSink) Init(sc sinks.AcctSinkConfig) error {

	// Make sure the sink has a name given in its configuration
	if sc.Name == "" {
		return errSinkName
	}

	// Construct InfluxDB UDP configuration and client
	conf := influx.UDPConfig{
		Addr:        sc.Addr,
		PayloadSize: int(sc.PayloadSize),
	}

	c, err := influx.NewUDPClient(conf)
	if err != nil {
		return err
	}

	// Set default batch watermark
	if sc.BatchWatermark == 0 {
		sc.BatchWatermark = defaultBatchWatermark
	}

	// Make a buffered channel for sendworkers
	s.sendChan = make(chan influx.BatchPoints, 64)

	s.newBatch()     // initial empty batch
	s.name = sc.Name // sink name
	s.client = c     // client handle
	s.config = sc    // config

	go s.sendWorker()
	go s.tickWorker()

	// Mark the sink as initialized
	s.init = true

	return nil
}

// Push an accounting event into the buffer of the InfluxDB accounting sink.
// Adds data points to the InfluxDB client buffer in a thread-safe manner.
func (s *InfluxAcctSink) Push(e bpf.AcctEvent) {

	// Create a point and add to batch
	tags := map[string]string{
		"conn_id":  strconv.FormatUint(uint64(e.ConnectionID), 10),
		"src_addr": e.SrcAddr.String(),
		"dst_addr": e.DstAddr.String(),
		"dst_port": strconv.FormatUint(uint64(e.DstPort), 10),
		"proto":    protoIntStr(e.Proto),
		"connmark": strconv.FormatUint(uint64(e.Connmark), 16),
	}

	// Optionally set flows' source ports (since they're random in most cases)
	if s.config.EnableSrcPort {
		tags["src_port"] = strconv.FormatUint(uint64(e.SrcPort), 10)
	}

	// https://github.com/influxdata/influxdb/issues/7801
	// The InfluxDB wire protocol and Go client supports uints and will mark them as such,
	// though the current version (1.6) has this behind a build flag as it's not yet
	// generally available. Only send signed ints for now until this is more widely deployed.
	fields := map[string]interface{}{
		"bytes_orig":   int64(e.BytesOrig),
		"bytes_ret":    int64(e.BytesRet),
		"packets_orig": int64(e.PacketsOrig),
		"packets_ret":  int64(e.PacketsRet),
	}

	pt, err := influx.NewPoint("ct_acct", tags, fields, time.Now())
	if err != nil {
		panic(err.Error())
	}

	// Add the point to the batch
	s.batchMu.Lock()
	s.batch.AddPoint(pt)

	batchLen := len(s.batch.Points())

	// Record statistics
	// Manually manage sink stats lock to update counters in one transaction
	s.stats.Lock()
	s.stats.Data.BatchLength = batchLen
	s.stats.Data.EventsPushed++
	s.stats.Unlock()

	// Flush the batch when the watermark is reached
	if batchLen >= int(s.config.BatchWatermark) {
		s.sendChan <- s.batch
		s.newBatch()
	}

	s.batchMu.Unlock()
}

// Name gets the name of the InfluxDB accounting sink.
func (s *InfluxAcctSink) Name() string {
	return s.name
}

// IsInit checks if the InfluxDB accounting sink was successfully initialized.
func (s *InfluxAcctSink) IsInit() bool {
	return s.init
}

// Stats returns the InfluxDB accounting sink's statistics structure.
func (s *InfluxAcctSink) Stats() sinks.AcctSinkStatsData {
	return s.stats.Data
}

// New returns a new InfluxDB accounting sink.
func New() InfluxAcctSink {
	return InfluxAcctSink{}
}
