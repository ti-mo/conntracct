package pipeline

import "github.com/iovisor/gobpf/elf"

// Pipeline is a structure representing the conntracct
// data ingest pipeline.
type Pipeline struct {

	// acct elf module handle
	acctModule *elf.Module

	// list of sinks for accounting data
	acctSinks []AcctSink

	// pipeline statistics
	Stats Stats
}

// Stats holds various statistics and information about the
// data processing pipeline
type Stats struct {

	// amount of `acct_event` structs received from kernel
	AcctPerfEvents uint64 `json:"acct_perf_events"`
	// amount of bytes read from the BPF perf buffer
	AcctPerfBytes uint64 `json:"acct_perf_bytes"`
	// length of the AcctEvent queue
	AcctEventQueueLen int `json:"acct_event_queue_length"`
}

// New creates a new Pipeline structure.
func New() *Pipeline {
	return &Pipeline{}
}

// Cleanup gracefully tears down all resources of a Pipeline structure.
func (i *Pipeline) Cleanup() error {

	if err := i.acctModule.Close(); err != nil {
		return err
	}

	return nil
}
