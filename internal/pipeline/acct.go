package pipeline

import (
	"sync/atomic"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"gitlab.com/0ptr/conntracct/pkg/bpf"
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
	cfg := bpf.AcctConfig{CooldownMillis: 2000}

	// Create a new accounting probe.
	ap, err := bpf.NewAcctProbe(cfg)
	if err != nil {
		return errors.Wrap(err, "initializing BPF probe")
	}
	log.Infof("Inserted probe version %s", ap.Kernel().Version)

	// Store channel reference so we can launch consumers on them.
	p.acctUpdateChan = make(chan bpf.AcctEvent, 1024)
	p.acctDestroyChan = make(chan bpf.AcctEvent, 1024)

	// Register accounting update/destroy event consumers.
	au := bpf.NewAcctConsumer("AcctUpdate", p.acctUpdateChan, bpf.ConsumerUpdate)
	if err := ap.RegisterConsumer(au); err != nil {
		return errors.Wrap(err, "registering update consumer to probe")
	}
	log.Debug("Registered pipeline consumer AcctUpdate")

	ad := bpf.NewAcctConsumer("AcctDestroy", p.acctDestroyChan, bpf.ConsumerDestroy)
	if err := ap.RegisterConsumer(ad); err != nil {
		return errors.Wrap(err, "registering destroy consumer to probe")
	}
	log.Debug("Registered pipeline consumer AcctDestroy")

	// Save the AcctProbe reference to the pipeline.
	p.acctProbe = ap

	return nil
}

// Start starts all resources registered to the pipeline.
func (p *Pipeline) Start() error {

	if p.acctProbe == nil {
		return errAcctNotInitialized
	}

	p.start.Do(func() {
		p.startAcct()
	})

	return nil
}

// startAcct starts the AcctProbe and starts goroutines reading AcctEvents from
// update and destroy channels.
func (p *Pipeline) startAcct() error {

	// Start the conntracct event consumer.
	go p.acctUpdateWorker()
	go p.acctDestroyWorker()

	// Start the AcctProbe.
	if err := p.acctProbe.Start(); err != nil {
		return errors.Wrap(err, "starting AcctProbe")
	}

	log.Info("Started accounting probe and workers")

	return nil
}

// acctUpdateWorker reads from the pipeline's update event channel
// and delivers events to all registered sinks listening for update events.
// This code closely resembles acctDestroyWorker due to this being in the hot
// path, avoiding as much branching and unnecessary work as possible.
func (p *Pipeline) acctUpdateWorker() {
	for {
		ae, ok := <-p.acctUpdateChan
		if !ok {
			log.Debug("Pipeline's update event channel closed, stopping worker.")
			break
		}

		// Record pipeline statistics.
		atomic.AddUint64(&p.Stats.AcctEventsTotal, 1)
		atomic.AddUint64(&p.Stats.AcctBytesTotal, bpf.AcctEventLength)
		atomic.AddUint64(&p.Stats.AcctEventsUpdate, 1)
		atomic.AddUint64(&p.Stats.AcctBytesUpdate, bpf.AcctEventLength)
		atomic.StoreUint64(&p.Stats.AcctUpdateQueueLen, uint64(len(p.acctUpdateChan)))

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
	for {
		ae, ok := <-p.acctDestroyChan
		if !ok {
			log.Debug("Pipeline's destroy event channel closed, stopping worker.")
			break
		}

		// Record pipeline statistics.
		atomic.AddUint64(&p.Stats.AcctEventsTotal, 1)
		atomic.AddUint64(&p.Stats.AcctBytesTotal, bpf.AcctEventLength)
		atomic.AddUint64(&p.Stats.AcctEventsDestroy, 1)
		atomic.AddUint64(&p.Stats.AcctBytesDestroy, bpf.AcctEventLength)
		atomic.StoreUint64(&p.Stats.AcctDestroyQueueLen, uint64(len(p.acctDestroyChan)))

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
