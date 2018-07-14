package pipeline

import "gitlab.com/0ptr/conntracct/pkg/bpf"

// An AcctSink represents a timeseries database or other
// that can accept accounting info.
type AcctSink interface {

	// Enqueue an accounting event to the sink driver
	Push(bpf.AcctEvent)
}
