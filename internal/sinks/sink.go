package sinks

import (
	"fmt"

	"github.com/ti-mo/conntracct/internal/sinks/influxdb"
	"github.com/ti-mo/conntracct/internal/sinks/stdout"
	"github.com/ti-mo/conntracct/internal/sinks/types"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// An Sink represents a timeseries database or other store
// that can accept accounting info.
type Sink interface {

	// Initialize the sink with the given configuration.
	Init(types.SinkConfig) error

	// Check whether or not the sink is initialized.
	IsInit() bool

	// Get the sink's name.
	Name() string

	// Check which kind of events this sink is interested in.
	WantUpdate() bool
	WantDestroy() bool

	// Enqueue an accounting event to the sink driver.
	// Implementation MUST be thread-safe.
	Push(bpf.AcctEvent)

	// Get a snapshot copy of the sink's performance statistics.
	Stats() types.SinkStatsData
}

// New returns a new, initialized Sink based on the type of
// the given SinkConfig.
func New(cfg types.SinkConfig) (Sink, error) {

	var sink Sink

	switch cfg.Type {
	// InfluxDB driver handles UDP and TCP modes internally.
	case types.InfluxUDP, types.InfluxHTTP:
		idb := influxdb.New()
		if err := idb.Init(cfg); err != nil {
			return nil, err
		}
		sink = &idb
	// stdout driver can write to either stdout or stderr.
	case types.StdOut, types.StdErr:
		std := stdout.New()
		if err := std.Init(cfg); err != nil {
			return nil, err
		}
		sink = &std
	default:
		return nil, fmt.Errorf("sink type '%s' not implemented", cfg.Type)
	}

	return sink, nil
}
