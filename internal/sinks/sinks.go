package sinks

import (
	"fmt"

	"github.com/ti-mo/conntracct/pkg/bpf"

	"github.com/ti-mo/conntracct/internal/sinks/dummy"
	"github.com/ti-mo/conntracct/internal/sinks/elasticsearch"
	"github.com/ti-mo/conntracct/internal/sinks/influxdb"
	"github.com/ti-mo/conntracct/internal/sinks/stdout"
	"github.com/ti-mo/conntracct/internal/sinks/types"
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

	// Returns true if the sink wants to receive update events.
	WantUpdate() bool
	// Returns true if the sink wants to receive destroy events.
	WantDestroy() bool

	// Push an update event to the sink driver. Implementation must be thread-safe.
	PushUpdate(bpf.Event)
	// Push a destroy event to the sink driver. Implementation must be thread-safe.
	PushDestroy(bpf.Event)

	// Get a snapshot copy of the sink's performance statistics.
	Stats() types.SinkStats
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
	case types.Elastic:
		es := elasticsearch.New()
		if err := es.Init(cfg); err != nil {
			return nil, err
		}
		sink = &es
	// stdout driver can write to either stdout or stderr.
	case types.StdOut, types.StdErr:
		std := stdout.New()
		if err := std.Init(cfg); err != nil {
			return nil, err
		}
		sink = &std
	case types.Dummy:
		d := dummy.New()
		_ = d.Init(cfg)
		sink = &d
	default:
		return nil, fmt.Errorf("sink type '%s' not implemented", cfg.Type)
	}

	return sink, nil
}
