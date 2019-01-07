package pipeline

import (
	log "github.com/sirupsen/logrus"

	"gitlab.com/0ptr/conntracct/pkg/bpf"
)

// InitAcct sets up the pipeline with an
func (p *Pipeline) InitAcct() error {

	p.acctMu.Lock()
	defer p.acctMu.Unlock()

	if p.acctProbe != nil {
		return errAcctAlreadyInitialized
	}

	cfg := bpf.AcctConfig{CooldownMillis: 2000}

	p.acctChan = make(chan bpf.AcctEvent, 1024)

	// Create a new accounting probe.
	ap, err := bpf.New(cfg)
	if err != nil {
		log.Fatalln("Initializing BPF probe:", err)
	}
	log.Infof("Inserted probe version %s", ap.Kernel().Version)

	// Create and register a new accounting consumer using
	// the pipeline's AcctEvent channel.
	ac := bpf.NewAcctConsumer("AcctPipeline", p.acctChan)
	if err := ap.RegisterConsumer(ac); err != nil {
		log.Fatalln("Registering consumer to probe:", err)
	}
	log.Info("Registered probe consumer AcctPipeline")

	// Save the AcctProbe reference to the pipeline.
	p.acctProbe = ap

	return nil
}

// StartAcct starts the acctEventWorker and the AcctProbe,
// and starts ingesting accounting events into the Pipeline.
func (p *Pipeline) StartAcct() error {

	p.acctMu.Lock()
	defer p.acctMu.Unlock()

	if p.acctProbe == nil {
		return errAcctNotInitialized
	}

	// Start the conntracct event consumer.
	go p.acctEventWorker(p.acctChan)

	// Start the AcctProbe.
	if err := p.acctProbe.Start(); err != nil {
		log.Fatalln("Starting AcctProbe:", err)
	}
	log.Info("Started BPF accounting probe")

	return nil
}

// acctEventWorker receives from a bpf.AcctEvent channel
// and delivers to all AcctEvent sinks registered to the pipeline.
// TODO: Allow multiple instances of this goroutine to be run.
func (p *Pipeline) acctEventWorker(aec chan bpf.AcctEvent) {
	for {
		ae, ok := <-aec
		if !ok {
			log.Info("AcctEvent channel closed, stopping acctEventWorker")
			break
		}

		// Save last-received perf count to ingest object
		// TODO: Make thread-safe
		p.Stats.AcctPerfEvents = ae.EventID
		p.Stats.AcctPerfBytes = ae.EventID * bpf.AcctEventLength
		p.Stats.AcctEventQueueLen = len(aec)

		// Fan out to all registered accounting sinks.
		for _, s := range p.acctSinks {
			s.Push(ae)
		}
	}
}
