package sinks

import "gitlab.com/0ptr/conntracct/pkg/bpf"

// An AcctSink represents a timeseries database or other store
// that can accept accounting info.
type AcctSink interface {

	// Initialize the sink with the given configuration.
	Init(AcctSinkConfig) error

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
	Stats() AcctSinkStatsData
}

// AcctSinkConfig represents the configuration of an accounting sink.
type AcctSinkConfig struct {

	// Flush batch when it holds this many points.
	BatchWatermark uint32

	// Maximum network payload size, only for UDP-based sinks.
	UDPPayloadSize uint16

	// Whether or not the sink should receive the flows' source ports.
	EnableSrcPort bool

	// Name of the sink.
	Name string

	// Target address of the sink's backing driver.
	Addr string
}
