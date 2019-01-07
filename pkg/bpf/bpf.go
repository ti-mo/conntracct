package bpf

import (
	"fmt"
	"sync"
	"sync/atomic"

	"gitlab.com/0ptr/conntracct/pkg/kernel"

	"github.com/iovisor/gobpf/elf"
	"github.com/pkg/errors"
)

const acctPerfMap = "acct_events"

// AcctProbe is an instance of a BPF probe running in the kernel.
type AcctProbe struct {

	// gobpf/elf objects.
	module  *elf.Module
	perfMap *elf.PerfMap

	// Target kernel of the loaded probe.
	kernel kernel.Kernel

	// List of event consumers of the probe.
	consumerMu sync.RWMutex
	consumers  []*AcctConsumer

	// Amount of lost BPF perf events.
	lostChan chan uint64
	lost     uint64

	// Communication channels with the perfWorker.
	perfChan chan []byte
	errChan  chan error

	// Started status of the probe.
	startMu sync.Mutex
	started bool
}

// New instantiates an AcctProbe using the given AcctConfig.
// Loads the BPF program into the kernel but does not attach its kprobes yet.
func New(cfg AcctConfig) (*AcctProbe, error) {

	kr, err := kernelRelease()
	if err != nil {
		return nil, err
	}

	// Select the correct BPF probe from the library.
	br, k, err := Select(kr)
	if err != nil {
		return nil, errors.Wrap(err, "selecting BPF probe")
	}

	// Instantiate AcctProbe with selected target kernel struct.
	ap := AcctProbe{
		kernel: k,
	}

	// Scan kallsyms before attempting BPF load to avoid arcane error output from eBPF attach.
	err = checkProbeKsyms(k.Probes)
	if err != nil {
		return nil, err
	}

	// Load the module from the bytes.Reader and insert into the kernel.
	ap.module = elf.NewModuleFromReader(br)
	if err := ap.module.Load(nil); err != nil {
		return nil, errors.Wrap(err, "failed to load ELF binary")
	}

	// Apply probe configuration.
	if err := configureProbe(ap.module, cfg); err != nil {
		return nil, errors.Wrap(err, "configuring BPF probe")
	}

	return &ap, nil
}

// Start attaches the BPF program's kprobes and starts polling the perf ring buffer.
func (ap *AcctProbe) Start() error {

	ap.startMu.Lock()
	defer ap.startMu.Unlock()

	if ap.started {
		return errProbeStarted
	}

	// Enable all kprobes in target kernel's probe list.
	for _, p := range ap.kernel.Probes {
		if err := ap.module.EnableKprobe(p, 0); err != nil {
			return errors.Wrap(err, "enabling kprobe")
		}
	}

	ap.perfChan = make(chan []byte, 1024)
	ap.lostChan = make(chan uint64)
	ap.errChan = make(chan error)

	// Set up the acct_events perf map with an event and lost channel.
	pm, err := elf.InitPerfMap(ap.module, acctPerfMap, ap.perfChan, ap.lostChan)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("InitPerfMap %s", acctPerfMap))
	}
	ap.perfMap = pm

	// Start worker watching errChan for errors.
	// go errWorker(ap)

	// Start the event message decoder and fanout worker.
	go perfWorker(ap)

	// Start worker counting the amount of lost messages.
	go lostWorker(ap)

	// Start polling the BPF perf ring buffer, starting message flow
	// into the AcctProbe's perfChan.
	pm.PollStart()

	ap.started = true

	return nil
}

// Stop stops the BPF program and releases all its related resources.
// TODO: Implement this properly.
func (ap *AcctProbe) Stop() error {
	return ap.module.Close()
}

// Kernel returns the target kernel structure of the selected probe.
func (ap *AcctProbe) Kernel() kernel.Kernel {
	return ap.kernel
}

// perfWorker reads binary events from the AcctProbe's event channel,
// unmarshals the events into AcctEvents and sends them on all registered
// consumers' event channels. Exits if perfChan is closed.
func perfWorker(ap *AcctProbe) {

	var eventID uint64

	var eb []byte
	var ok bool

	for {
		// Receive binary acct_event struct from BPF.
		eb, ok = <-ap.perfChan
		if !ok {
			ap.errChan <- errPerfChanClosed
			break
		}

		var ae AcctEvent
		err := ae.UnmarshalBinary(eb)
		if err != nil {
			ap.errChan <- errors.Wrap(err, "error unmarshaling AcctEvent byte array")
		}

		// Increment goroutine's event counter and send in acct message.
		eventID++
		ae.EventID = eventID

		// Fanout to all registered consumers.
		ap.consumerMu.RLock()
		for _, c := range ap.consumers {
			// Non-blocking send on the consumer's event channel.
			select {
			case c.events <- ae:
			default:
				// Increment the consumer's lost counter if AcctEvent
				// could not be sent on the channel.
				atomic.AddUint64(&c.lost, 1)
			}
		}
		ap.consumerMu.RUnlock()
	}
}

// lostWorker increments the AcctProbe's lost field for every message
// received on its lostChan. Exits if lostChan is closed.
func lostWorker(ap *AcctProbe) {

	for {
		_, ok := <-ap.lostChan
		if !ok {
			ap.errChan <- errLostChanClosed
			break
		}

		atomic.AddUint64(&ap.lost, 1)
	}
}
