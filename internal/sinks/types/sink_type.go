package types

// SinkType represents the type of Sink.
//go:generate stringer -type=SinkType
type SinkType uint8

// Enum of supported sink types.
const (
	Dummy SinkType = iota
	StdOut
	StdErr
	InfluxUDP
	InfluxHTTP
	Elastic
)
