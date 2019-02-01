package types

// SinkType represents the type of Sink.
//go:generate stringer -type=SinkType
type SinkType uint8

// Enum of supported sink types.
const (
	StdOut SinkType = iota
	StdErr
	InfluxUDP
	InfluxHTTP
	Elastic
)
