package pipeline

import (
	log "github.com/sirupsen/logrus"

	"gitlab.com/0ptr/conntracct/pkg/bpf"
)

// RunAcct starts collecting conntrack accounting data
// from the local Linux host.
func (p *Pipeline) RunAcct() error {

	if p.acctModule != nil {
		return errAcctAlreadyInitialized
	}

	// Channel for lost message IDs when perf ring buffer is full.
	ael := make(chan uint64)

	mod, aec, pv, err := bpf.Init(ael)
	if err != nil {
		log.Fatalln("Initializing BPF probe:", err)
	}

	log.Infof("Inserted probe version %s.", pv)

	// Save the elf module to ingest object.
	p.acctModule = mod

	go p.acctEventWorker(aec)

	go func() {
		for {
			ae, ok := <-ael
			if !ok {
				log.Info("BPF lost channel closed, exiting read loop")
				break
			}

			log.Errorf("Dropped BPF event '%v', possible congestion", ae)
		}
	}()

	log.Info("Started BPF accounting probe.")

	return nil
}

// acctEventWorker receives from a bpf.AcctEvent channel
// and delivers to all AcctEvent sinks registered to the pipeline.
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

		p.acctPush(ae)
	}
}

// acctPush	pushes a bpf.AcctEvent into all registered accounting sinks.
func (p *Pipeline) acctPush(ae bpf.AcctEvent) {
	for _, s := range p.acctSinks {
		s.Push(ae)
	}
}
