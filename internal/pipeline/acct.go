package pipeline

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/internal/config"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// Init initializes the pipeline. Only runs once, subsequent calls are no-ops.
func (p *Pipeline) Init(pc *config.ProbeConfig) error {
	if pc == nil {
		return errProbeConfig
	}

	var err error

	p.init.Do(func() {
		err = p.initProbe(pc)
	})

	return err
}

// initProbe initializes the accounting probe and consumers.
// Should only be called once, eg. gated behind a sync.Once.
func (p *Pipeline) initProbe(pc *config.ProbeConfig) error {
	// Extract BPF configuration from app configuration.
	cfg := pc.BPFConfig()

	// Create a new accounting probe.
	ap, err := bpf.NewProbe(cfg)
	if err != nil {
		return fmt.Errorf("initializing BPF probe: %w", err)
	}

	log.Infof("Loaded BPF programs")

	// Register accounting event consumers.
	// From the perspective of the pipeline, these are event sources.
	ac := bpf.NewConsumer("PipelineAcct", make(chan bpf.Event, 1024))
	if err := ap.RegisterConsumer(ac); err != nil {
		return fmt.Errorf("registering acct consumer to probe: %w", err)
	}
	// Store references to the source and its stats.
	p.acctSource = ac
	p.stats.AcctSourceStats = ac.Stats()
	log.Debugf("Registered Probe consumer %s", ac.Name())

	// Save the Probe reference to the pipeline.
	p.acctProbe = ap

	return nil
}

// Start starts all resources registered to the pipeline.
func (p *Pipeline) Start() error {

	if p.acctProbe == nil {
		return errAcctNotInitialized
	}

	var err error

	p.start.Do(func() {
		err = p.startAcct()
	})

	return err
}

// startAcct starts the Probe and starts goroutines reading Events from
// update and destroy sources.
func (p *Pipeline) startAcct() error {
	// Start the conntracct event consumer.
	go p.acctUpdateWorker()

	// Start the Probe.
	if err := p.acctProbe.Start(); err != nil {
		return fmt.Errorf("starting probe: %w", err)
	}

	log.Info("Started accounting probe and workers")

	return nil
}

// acctUpdateWorker reads from the pipeline's event channel
// and delivers events to all registered sinks listening for events.
func (p *Pipeline) acctUpdateWorker() {
	c := p.acctSource.Events()
	for {
		e, ok := <-c
		if !ok {
			log.Debug("Pipeline's update event channel closed, stopping worker.")
			break
		}

		// Record pipeline statistics.
		switch e.Type {
		case bpf.New:
			p.stats.IncrEventsNew()
		case bpf.Update:
			p.stats.IncrEventsUpdate()
		case bpf.Destroy:
			p.stats.IncrEventsDestroy()
		}

		// Fan out to all registered accounting sinks.
		p.acctSinkMu.RLock()
		for _, s := range p.acctSinks {
			if e.Type == bpf.New && s.WantNew() {
				s.Push(e)
			}
			if e.Type == bpf.Update && s.WantUpdate() {
				s.Push(e)
			}
			if e.Type == bpf.Destroy && s.WantDestroy() {
				s.Push(e)
			}
		}
		p.acctSinkMu.RUnlock()
	}
}
