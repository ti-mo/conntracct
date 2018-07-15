package pipeline

import (
	"github.com/iovisor/gobpf/elf"
	log "github.com/sirupsen/logrus"
	"gitlab.com/0ptr/conntracct/internal/sinks"
)

// Pipeline is a structure representing the conntracct
// data ingest pipeline.
type Pipeline struct {

	// acct elf module handle
	acctModule *elf.Module

	// list of sinks for accounting data
	acctSinks []sinks.AcctSink

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

// RegisterAcctSink registers a sink for accounting data
// to the pipeline.
func (p *Pipeline) RegisterAcctSink(s sinks.AcctSink) error {

	// Make sure the sink is initialized before using
	if !s.IsInit() {
		return errSinkNotInit
	}

	// Add the acctSink to the pipeline
	p.acctSinks = append(p.acctSinks, s)

	log.Infof("Registered accounting sink '%s' to pipeline", s.Name())

	return nil
}

// GetAcctSinks gets a list of accounting sinks registered to the pipeline.
func (p *Pipeline) GetAcctSinks() []sinks.AcctSink {
	return p.acctSinks
}

// Cleanup gracefully tears down all resources of a Pipeline structure.
func (p *Pipeline) Cleanup() error {

	if err := p.acctModule.Close(); err != nil {
		return err
	}

	return nil
}
