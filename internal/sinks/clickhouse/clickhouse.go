package clickhouse

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/internal/config"
	"github.com/ti-mo/conntracct/internal/sinks/types"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// ClickhouseSink is an accounting sink implementing a ClickHouse client.
// It is only intended for flow archival (completed/destroyed flows).
type ClickhouseSink struct {

	// Sink had Init() called on it successfully.
	init bool

	// Sink's configuration object.
	config config.SinkConfig

	// ClickHouse driver connection handle.
	conn clickhouse.Conn

	// Channel the send workers receive batches on.
	sendChan chan batch

	// Data point batch.
	batchMu sync.Mutex
	batch   batch

	// Sink stats.
	stats types.SinkStats

	// Save all events as time series or only track latest state
	latestValues bool
}

// New returns a new ClickHouse accounting sink.
func New() ClickhouseSink {
	return ClickhouseSink{}
}

// Init initializes the ClickHouse accounting sink.
func (s *ClickhouseSink) Init(sc config.SinkConfig) error {

	if sc.Name == "" {
		return errEmptySinkName
	}

	// Configure default values on the sink configuration.
	sinkDefaults(&sc)


	// Create a ClickHouse client.
	opts := clientOptions(sc)
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return fmt.Errorf("error creating ClickHouse connection: %w", err)
	}

	s.config = sc
	s.conn = conn
	s.latestValues = sc.LatestValues

	if s.latestValues {
		// install database scheme for latest entry tracking
		if err := s.installLatestSchema(sc.Database); err != nil {
			log.WithField("sink", sc.Name).Fatalf("error configuring timeseries schema: %s", err.Error())
		}
	} else {
		// Intstall database schema for timestamped state tracking
		if err := s.installTimeseriesSchema(sc.Database); err != nil {
			log.WithField("sink", sc.Name).Fatalf("error configuring latest schema: %s", err.Error())
		}
	}

	// Start workers.
	s.sendChan = make(chan batch, 64)
	log.WithField("sink", sc.Name).Debugf("configuring batch setup")

	s.newBatch() // initial empty batch

	go s.sendWorker()
	go s.tickWorker(time.Second * 5)

	// Mark the sink as initialized.
	s.init = true

	return nil
}

// PushUpdate pushes an update event into the buffer of the ClickHouse accounting sink.
func (s *ClickhouseSink) PushUpdate(e bpf.Event) {
	// Wrap the BPF event in a structure to be inserted into the database.
	ce := event{
		State: "established",
		Event: &e,
	}

	s.transformEvent(&ce)
	s.addBatchEvent(&ce)
}

// PushDestroy pushes a destroy event into the buffer of the ClickHouse accounting sink.
func (s *ClickhouseSink) PushDestroy(e bpf.Event) {
	// Wrap the BPF event in a structure to be inserted into the database.
	ce := event{
		State: "finished",
		Event: &e,
	}

	s.transformEvent(&ce)
	s.addBatchEvent(&ce)
}

// IsInit returns true if the ClickHouse accounting sink was successfully initialized.
func (s *ClickhouseSink) IsInit() bool {
	return s.init
}

// Name returns the ClickHouse sink's name.
func (s *ClickhouseSink) Name() string {
	return s.config.Name
}

// Stats returns the ClickHouse accounting sink's statistics structure.
func (s *ClickhouseSink) Stats() types.SinkStats {
	return s.stats.Get()
}

// WantUpdate returns true if the ClickHouse sink is configured to accept update events.
func (s *ClickhouseSink) WantUpdate() bool {
	return true
}

// WantDestroy returns true if the ClickHouse sink is configured to accept destroy events.
func (s *ClickhouseSink) WantDestroy() bool {
	return true
}

// installSchema sets up the data schema for the given database in ClickHouse.
// It creates a table for flow data with appropriate column types based on the mappings.
func (s *ClickhouseSink) installTimeseriesSchema(db string) error {
	// Create table for flow data.
	// We use the MergeTree engine which is the most common for OLAP-style tables in ClickHouse.
	// Modify it based on your actual partitioning and primary key logic.

	tableName := fmt.Sprintf("%s_flows", db)
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s.%s (
			flow_id UInt64,
			hostname String,
			state String,
			bytes_orig UInt64,
			bytes_ret UInt64,
			bytes_total UInt64,
			packets_orig UInt64,
			packets_ret UInt64,
			packets_total UInt64,
			connmark Int32,
			src_addr IPv6,
			src_port Int32,
			dst_addr IPv6,
			dst_port Int32,
			netns Int64,
			proto_name String,
			start DateTime,
			timestamp DateTime
		) ENGINE = MergeTree()
		ORDER BY (flow_id, hostname, netns, start)
		PARTITION BY toYYYYMM(start)
		PRIMARY KEY (flow_id)
		SETTINGS index_granularity = 8192
	`, db, tableName)

	// ) ENGINE = ReplacingMergeTree(timestamp)
	// Execute the query to create the table.
	if err := s.conn.Exec(context.Background(), query); err != nil {
		return fmt.Errorf("error creating table: %w", err)
	}

	log.WithField("sink", s.config.Name).Debugf("Installed schema for table '%s' in database '%s'", tableName, db)

	return nil
}

// installSchema sets up the data schema for the given database in ClickHouse.
// It creates a table for flow data with appropriate column types based on the mappings.
func (s *ClickhouseSink) installLatestSchema(db string) error {
	// Create table for flow data.
	// We use the MergeTree engine which is the most common for OLAP-style tables in ClickHouse.
	// Modify it based on your actual partitioning and primary key logic.

	tableName := fmt.Sprintf("%s_flows", db)
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s.%s (
			flow_id UInt64,
			hostname String,
			state String,
			bytes_orig UInt64,
			bytes_ret UInt64,
			bytes_total UInt64,
			packets_orig UInt64,
			packets_ret UInt64,
			packets_total UInt64,
			connmark Int32,
			src_addr IPv6,
			src_port Int32,
			dst_addr IPv6,
			dst_port Int32,
			netns Int64,
			proto_name String,
			start DateTime,
			timestamp DateTime
		) ENGINE = ReplacingMergeTree(timestamp)
		ORDER BY (flow_id, hostname, netns, start)
		PARTITION BY toYYYYMM(start)
		PRIMARY KEY (flow_id)
		SETTINGS index_granularity = 8192
	`, db, tableName)

	// ) ENGINE = ReplacingMergeTree(timestamp)
	// Execute the query to create the table.
	if err := s.conn.Exec(context.Background(), query); err != nil {
		return fmt.Errorf("error creating table: %w", err)
	}

	log.WithField("sink", s.config.Name).Debugf("Installed schema for table '%s' in database '%s'", tableName, db)

	return nil
}
