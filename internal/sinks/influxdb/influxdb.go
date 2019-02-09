package influxdb

import (
	"strconv"
	"sync"
	"time"

	influx "github.com/influxdata/influxdb/client/v2"

	"github.com/ti-mo/conntracct/internal/sinks/helpers"
	"github.com/ti-mo/conntracct/internal/sinks/types"
	"github.com/ti-mo/conntracct/pkg/boottime"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

const (
	defaultBatchSize = 128
)

// InfluxSink is an accounting sink implementing an InfluxDB client.
type InfluxSink struct {

	// Sink had Init() called on it successfully.
	init bool

	// Sink's configuration object.
	config types.SinkConfig

	// Boot time of the machine. (estimated)
	bootTime time.Time

	// Influx driver client handle.
	client influx.Client

	// Channel the network workers receive influx batches on.
	sendChan chan influx.BatchPoints

	// Data point batch.
	batchMu sync.Mutex
	batch   influx.BatchPoints

	// Sink stats.
	stats types.SinkStats
}

// New returns a new InfluxDB accounting sink.
func New() InfluxSink {
	return InfluxSink{}
}

// Init initializes the InfluxDB accounting sink.
func (s *InfluxSink) Init(sc types.SinkConfig) error {

	// Validate / sanitize input.
	if sc.Name == "" {
		return errEmptySinkName
	}
	if sc.Address == "" {
		return errEmptySinkAddress
	}
	if sc.BatchSize == 0 {
		sc.BatchSize = defaultBatchSize
	}

	var c influx.Client
	var err error

	switch sc.Type {
	case types.InfluxUDP:
		// Construct InfluxDB UDP configuration and client.
		conf := influx.UDPConfig{
			Addr:        sc.Address,
			PayloadSize: int(sc.UDPPayloadSize),
		}

		c, err = influx.NewUDPClient(conf)
		if err != nil {
			return err
		}
	case types.InfluxHTTP:
		// Construct InfluxDB HTTP configuration and client.
		conf := influx.HTTPConfig{
			Addr:     sc.Address,
			Username: sc.Username,
			Password: sc.Password,
			Timeout:  sc.Timeout,
		}

		c, err = influx.NewHTTPClient(conf)
		if err != nil {
			return err
		}
	default:
		return errInvalidSinkType
	}

	// Estimate the machine's boot time, for absolute event timestamps.
	s.bootTime = boottime.Estimate()

	// Make a buffered channel for sendworkers.
	s.sendChan = make(chan influx.BatchPoints, 64)

	s.newBatch()  // initial empty batch
	s.client = c  // client handle
	s.config = sc // config

	go s.sendWorker()
	go s.tickWorker()

	// Mark the sink as initialized.
	s.init = true

	return nil
}

// Push an accounting event into the buffer of the InfluxDB accounting sink.
// Adds data points to the InfluxDB client buffer in a thread-safe manner.
func (s *InfluxSink) Push(e bpf.Event) {

	// Create a point and add to batch.
	tags := map[string]string{
		"conn_id":  strconv.FormatUint(uint64(e.ConnectionID), 10),
		"src_addr": e.SrcAddr.String(),
		"dst_addr": e.DstAddr.String(),
		"dst_port": strconv.FormatUint(uint64(e.DstPort), 10),
		"proto":    helpers.ProtoIntStr(e.Proto),
		"connmark": strconv.FormatUint(uint64(e.Connmark), 16),
		"netns":    strconv.FormatUint(uint64(e.NetNS), 10),
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

	// To obtain the absolute time stamp of an event in kernel space,
	// we add its (monotonic) time stamp to the estimated boot time of the kernel.
	ts := s.bootTime.Add(time.Duration(e.Timestamp))

	pt, err := influx.NewPoint("ct_acct", tags, fields, ts)
	if err != nil {
		panic(err.Error())
	}

	// Add the point to the batch.
	s.batchMu.Lock()
	s.batch.AddPoint(pt)

	batchLen := len(s.batch.Points())

	// Record statistics.
	s.stats.SetBatchLength(batchLen)
	s.stats.IncrEventsPushed()

	// Flush the batch when the watermark is reached.
	if batchLen >= int(s.config.BatchSize) {
		s.sendChan <- s.batch
		s.newBatch()
	}

	s.batchMu.Unlock()
}

// Name gets the name of the InfluxDB accounting sink.
func (s *InfluxSink) Name() string {
	return s.config.Name
}

// IsInit checks if the InfluxDB accounting sink was successfully initialized.
func (s *InfluxSink) IsInit() bool {
	return s.init
}

// WantUpdate always returns true.
func (s *InfluxSink) WantUpdate() bool {
	return true
}

// WantDestroy always returns true, InfluxDB receives destroy events. (flow totals)
func (s *InfluxSink) WantDestroy() bool {
	return true
}

// Stats returns the InfluxDB accounting sink's statistics structure.
func (s *InfluxSink) Stats() types.SinkStatsData {
	return s.stats.Get()
}

// newBatch writes a new InfluxDB client batch to the sink.
func (s *InfluxSink) newBatch() {

	b, err := influx.NewBatchPoints(influx.BatchPointsConfig{
		Precision: "ns", // nanosecond precision timestamps
	})

	if err != nil {
		panic(err)
	}

	s.batch = b
}
