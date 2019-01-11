package sinks

import "gitlab.com/0ptr/conntracct/pkg/bpf"

// An AcctSink represents a timeseries database or other
// that can accept accounting info.
type AcctSink interface {

	// Initialize and configure the sink
	Init(AcctSinkConfig) error

	// Check whether or not the sink it initialized
	IsInit() bool

	// Get the sink's name
	Name() string

	// Enqueue an accounting event to the sink driver
	// _MUST_ have a thread-safe implementation
	Push(bpf.AcctEvent)

	// Get the sink's performance statistics
	Stats() AcctSinkStatsData
}

// AcctSinkConfig represents the configuration of an accounting sink.
type AcctSinkConfig struct {
	// Flush batch when it holds this many points.
	BatchWatermark uint32

	// Whether or not the sink should receive the flows' source ports.
	EnableSrcPort bool

	// Maximum network payload size, for UDP-based sinks.
	PayloadSize uint16

	// Name of the sink.
	Name string

	// Target address of the sink's backing driver.
	Addr string
}
