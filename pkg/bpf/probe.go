package bpf

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

var (
	nfCTHashInsert  string
	nfCTRefreshAcct string
	nfCTDelete      string
)

func init() {
	spec, err := loadAcct()
	if err != nil {
		panic(err)
	}

	var specs acctSpecs
	if err := spec.Assign(&specs); err != nil {
		panic(err)
	}

	nfCTHashInsert = specs.KprobeNfConntrackHashInsert.AttachTo
	nfCTRefreshAcct = specs.KprobeNfCtRefreshAcct.AttachTo
	nfCTDelete = specs.KprobeNfCtDelete.AttachTo
}

// Probe is an instance of a BPF probe running in the kernel.
type Probe struct {
	// ebpf-go resources.
	objs          *acctObjects
	updateReader  *perf.Reader
	destroyReader *perf.Reader
	links         []link.Link

	// List of event consumers of the probe.
	consumerMu sync.RWMutex
	consumers  []*Consumer

	// Channel for receiving IDs of lost perf events.
	lost chan uint64

	// Started status of the probe.
	startMu sync.Mutex
	started bool

	stats *ProbeStats
}

// NewProbe instantiates a Probe using the given Config.
// Loads the BPF program into the kernel but does not attach its kprobes yet.
func NewProbe(cfg Config) (*Probe, error) {
	var objs acctObjects
	if err := loadAcctObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading acct objects: %w", err)
	}

	ap := Probe{
		objs:  &objs,
		stats: &ProbeStats{},
	}

	if err := ap.configure(cfg); err != nil {
		return nil, fmt.Errorf("configure probe: %w", err)
	}

	return &ap, nil
}

// Start attaches the BPF program's kprobes and starts polling the perf ring buffer.
func (ap *Probe) Start() error {
	ap.startMu.Lock()
	defer ap.startMu.Unlock()

	if ap.started {
		return errProbeStarted
	}

	ap.lost = make(chan uint64)

	// Set up Readers for reading events from the perf ring buffers.
	r, err := perf.NewReader(ap.objs.PerfAcctUpdate, 4096)
	if err != nil {
		return fmt.Errorf("create acct update perf reader: %w", err)
	}
	ap.updateReader = r

	r, err = perf.NewReader(ap.objs.PerfAcctEnd, 4096)
	if err != nil {
		return fmt.Errorf("create acct destroy perf reader: %w", err)
	}
	ap.destroyReader = r

	// Start event decoder/fanout workers.
	go ap.updateWorker()
	go ap.destroyWorker()

	l, err := link.Kprobe(nfCTHashInsert, ap.objs.KprobeNfConntrackHashInsert, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe %s: %w", nfCTHashInsert, err)
	}
	ap.links = append(ap.links, l)

	l, err = link.Kprobe(nfCTRefreshAcct, ap.objs.KprobeNfCtRefreshAcct, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe %s: %w", nfCTRefreshAcct, err)
	}
	ap.links = append(ap.links, l)

	l, err = link.Kretprobe(nfCTRefreshAcct, ap.objs.KretprobeNfCtRefreshAcct, nil)
	if err != nil {
		return fmt.Errorf("attach kretprobe %s: %w", nfCTRefreshAcct, err)
	}
	ap.links = append(ap.links, l)

	l, err = link.Kprobe(nfCTDelete, ap.objs.KprobeNfCtDelete, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe %s: %w", nfCTDelete, err)
	}
	ap.links = append(ap.links, l)

	ap.started = true

	return nil
}

// Stop stops the BPF program and releases all its related resources.
// Closes all Probe's channels. Can only be called after Start().
func (ap *Probe) Stop() error {
	ap.startMu.Lock()
	defer ap.startMu.Unlock()

	if !ap.started {
		return errProbeNotStarted
	}

	if err := ap.updateReader.Close(); err != nil {
		return err
	}

	if err := ap.destroyReader.Close(); err != nil {
		return err
	}

	close(ap.lost)

	for _, l := range ap.links {
		if err := l.Close(); err != nil {
			return err
		}
	}

	ap.objs.Close()

	return nil
}

// Stats returns a snapshot copy of the Probe's statistics.
func (ap *Probe) Stats() ProbeStats {
	return ap.stats.Get()
}

// updateWorker reads binady flow update events from the Probe's ring buffer,
// unmarshals the events into Event structures and sends them on all registered
// consumers' event channels.
func (ap *Probe) updateWorker() {
	for {
		rec, err := ap.updateReader.Read()
		if err != nil {
			// Reader closed, gracefully exit the read loop.
			if errors.Is(err, os.ErrClosed) {
				return
			}
			panic(fmt.Sprint("unexpected error reading from updateReader:", err))
		}

		// Log the amount of lost samples and skip processing the sample.
		if rec.LostSamples > 0 {
			ap.stats.incrPerfEventsUpdateLost(rec.LostSamples)
			continue
		}

		ap.stats.incrPerfEventsUpdate()

		var ae Event
		if err := ae.unmarshalBinary(rec.RawSample); err != nil {
			panic(err)
		}

		// Fan out update event to all registered consumers.
		ap.fanoutEvent(ae, true)
	}
}

// destroyWorker reads binary destroy events from the Probe's ring buffer,
// unmarshals the events into Event structures and sends them on all registered
// consumers' event channels .
func (ap *Probe) destroyWorker() {
	for {
		rec, err := ap.destroyReader.Read()
		if err != nil {
			// Reader closed, gracefully exit the read loop.
			if errors.Is(err, os.ErrClosed) {
				return
			}
			panic(fmt.Sprint("unexpected error reading from destroyReader:", err))
		}

		// Log the amount of lost samples and skip processing the sample.
		if rec.LostSamples > 0 {
			ap.stats.incrPerfEventsDestroyLost(rec.LostSamples)
			continue
		}

		ap.stats.incrPerfEventsDestroy()

		var ae Event
		if err := ae.unmarshalBinary(rec.RawSample); err != nil {
			panic(err)
		}

		// Fan out destroy event to all registered consumers.
		ap.fanoutEvent(ae, false)
	}
}

// fanoutEvent sends the given Event to all registered consumers.
// The update flag specifies whether the event is an update (true) or destroy
// (false) event.
func (ap *Probe) fanoutEvent(ae Event, update bool) {
	// Take a read lock on the consumers so we don't send to closed or already
	// unregistered consumer channels.
	ap.consumerMu.RLock()

	for _, c := range ap.consumers {
		// Require the update/destroy condition of the event to match
		// the requested event type of the consumer.
		if (update && c.WantUpdate()) || (!update && c.WantDestroy()) {
			// Non-blocking send to the consumer's event channel.
			select {
			case c.events <- ae:
				c.stats.setQueueLength(len(c.events))
				c.stats.incrEventsReceived()
			default:
				// If the channel can't be written to immediately,
				// increment the consumer's lost counter.
				c.stats.incrEventsLost()
			}
		}
	}

	ap.consumerMu.RUnlock()
}
