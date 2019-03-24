package pipeline

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/internal/sinks"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// Pipeline is a structure representing the conntracct
// data ingest pipeline.
type Pipeline struct {
	start sync.Once

	init            sync.Once
	acctProbe       *bpf.Probe
	acctUpdateChan  chan bpf.Event
	acctDestroyChan chan bpf.Event

	acctSinkMu sync.RWMutex
	acctSinks  []sinks.Sink

	stats *Stats
}

// New creates a new Pipeline structure.
func New() *Pipeline {
	return &Pipeline{
		stats: &Stats{},
	}
}

// RegisterSink registers a sink for accounting data
// to the pipeline.
func (p *Pipeline) RegisterSink(s sinks.Sink) error {

	// Make sure the sink is initialized before using.
	if !s.IsInit() {
		return errSinkNotInit
	}

	// Warn the user about conntrack wait timeouts
	// if the sink consumes destroy events.
	if s.WantDestroy() {
		warnSysctl()
	}

	p.acctSinkMu.Lock()
	defer p.acctSinkMu.Unlock()

	// Add the acctSink to the pipeline.
	p.acctSinks = append(p.acctSinks, s)

	log.Infof("Registered accounting sink '%s' to pipeline", s.Name())

	return nil
}

// GetSinks gets a list of accounting sinks registered to the pipeline.
func (p *Pipeline) GetSinks() []sinks.Sink {

	p.acctSinkMu.RLock()
	defer p.acctSinkMu.RUnlock()

	return p.acctSinks
}

// Stop gracefully tears down all resources of a Pipeline structure.
func (p *Pipeline) Stop() error {
	// Stop the accounting probe.
	return p.acctProbe.Stop()
}

// Stats returns a snapshot copy of the pipeline's statistics.
func (p *Pipeline) Stats() Stats {
	return p.stats.Get()
}
