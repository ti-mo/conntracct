package pipeline

import (
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// Init initializes the pipeline. Only runs once, subsequent calls are no-ops.
func (p *Pipeline) Init() error {

	var err error
	p.init.Do(func() {
		err = p.initAcct()
	})

	return err
}

// initAcct initializes the accounting probe and consumers.
// Should only be called once, eg. gated behind a sync.Once.
func (p *Pipeline) initAcct() error {
	cfg := bpf.Config{}

	// Create a new accounting probe.
	ap, err := bpf.NewProbe(cfg)
	if err != nil {
		return errors.Wrap(err, "initializing BPF probe")
	}
	log.Infof("Inserted probe version %s", ap.Kernel().Version)

	// Register accounting update/destroy event consumers.
	// From the perspective of the pipeline, these are sources.
	au := bpf.NewConsumer("PipelineAcctUpdate", make(chan bpf.Event, 1024), bpf.ConsumerUpdate)
	if err := ap.RegisterConsumer(au); err != nil {
		return errors.Wrap(err, "registering update consumer to probe")
	}
	// Store references to the source and its stats.
	p.acctUpdateSource = au
	p.stats.UpdateSourceStats = au.Stats()
	log.Debug("Registered Probe consumer " + au.Name())

	ad := bpf.NewConsumer("PipelineAcctDestroy", make(chan bpf.Event, 1024), bpf.ConsumerDestroy)
	if err := ap.RegisterConsumer(ad); err != nil {
		return errors.Wrap(err, "registering destroy consumer to probe")
	}
	// Store references to the source and its stats.
	p.acctDestroySource = ad
	p.stats.DestroySourceStats = ad.Stats()
	log.Debug("Registered Probe consumer " + ad.Name())

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
	go p.acctDestroyWorker()

	// Start the Probe.
	if err := p.acctProbe.Start(); err != nil {
		return errors.Wrap(err, "starting Probe")
	}

	log.Info("Started accounting probe and workers")

	return nil
}

// acctUpdateWorker reads from the pipeline's update event channel
// and delivers events to all registered sinks listening for update events.
// This code closely resembles acctDestroyWorker due to this being in the hot
// path, avoiding as much branching and unnecessary work as possible.
func (p *Pipeline) acctUpdateWorker() {

	c := p.acctUpdateSource.Events()

	for {
		ae, ok := <-c
		if !ok {
			log.Debug("Pipeline's update event channel closed, stopping worker.")
			break
		}

		// Record pipeline statistics.
		p.stats.IncrEventsUpdate()

		// Fan out to all registered accounting sinks.
		p.acctSinkMu.RLock()
		for _, s := range p.acctSinks {
			if s.WantUpdate() {
				s.Push(ae)
			}
		}
		p.acctSinkMu.RUnlock()
	}
}

// acctDestroyWorker is a copy of acctUpdateWorker, but for destroy events.
func (p *Pipeline) acctDestroyWorker() {

	c := p.acctDestroySource.Events()

	for {
		ae, ok := <-c
		if !ok {
			log.Debug("Pipeline's destroy event channel closed, stopping worker.")
			break
		}

		// Record pipeline statistics.
		p.stats.IncrEventsDestroy()

		// Fan out to all registered accounting sinks.
		p.acctSinkMu.RLock()
		for _, s := range p.acctSinks {
			if s.WantDestroy() {
				s.Push(ae)
			}
		}
		p.acctSinkMu.RUnlock()
	}
}
