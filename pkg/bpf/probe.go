package bpf

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Probe is an instance of a BPF probe running in the kernel.
type Probe struct {
	// ebpf-go resources.
	objs    *acctObjects
	ringbuf *ringbuf.Reader
	links   []link.Link

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
	spec, err := loadAcct()
	if err != nil {
		return nil, fmt.Errorf("loading acct specs: %w", err)
	}
	var specs acctSpecs
	if err := spec.Assign(&specs); err != nil {
		return nil, fmt.Errorf("assigning acct specs: %w", err)
	}
	if err := configure(&specs, cfg); err != nil {
		return nil, fmt.Errorf("configure acct specs: %w", err)
	}

	var objs acctObjects
	err = spec.LoadAndAssign(&objs, nil)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return nil, fmt.Errorf("verifier error loading acct objects: %+v", ve)
	}
	if err != nil {
		return nil, fmt.Errorf("loading acct objects: %w", err)
	}

	ap := Probe{
		objs:  &objs,
		stats: &ProbeStats{},
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
	r, err := ringbuf.NewReader(ap.objs.Ringbuf)
	if err != nil {
		return fmt.Errorf("create acct ringbuf reader: %w", err)
	}
	ap.ringbuf = r

	// Start event decoder/fanout workers.
	go ap.updateWorker()

	l, err := link.AttachTracing(link.TracingOptions{Program: ap.objs.CtNew})
	if err != nil {
		return fmt.Errorf("attach new %s: %w", ap.objs.CtNew, err)
	}
	ap.links = append(ap.links, l)

	l, err = link.AttachTracing(link.TracingOptions{Program: ap.objs.CtUpdate})
	if err != nil {
		return fmt.Errorf("attach update %s: %w", ap.objs.CtUpdate, err)
	}
	ap.links = append(ap.links, l)

	l, err = link.AttachTracing(link.TracingOptions{Program: ap.objs.CtDestroy})
	if err != nil {
		return fmt.Errorf("attach destroy %s: %w", ap.objs.CtDestroy, err)
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

	if err := ap.ringbuf.Close(); err != nil {
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

// updateWorker reads binary flow update events from the Probe's ring buffer,
// unmarshals the events into Event structures and sends them on all registered
// consumers' event channels.
func (ap *Probe) updateWorker() {
	for {
		rec, err := ap.ringbuf.Read()
		if err != nil {
			// Reader closed, gracefully exit the read loop.
			if errors.Is(err, os.ErrClosed) {
				return
			}
			panic(fmt.Sprint("unexpected error reading from updateReader:", err))
		}

		ap.stats.incrRingbufEventsTotal()

		var ae Event
		if err := ae.unmarshalBinary(rec.RawSample); err != nil {
			panic(err)
		}

		// Fan out update event to all registered consumers.
		ap.fanoutEvent(ae)
	}
}

// fanoutEvent sends the given Event to all registered consumers.
// The update flag specifies whether the event is an update (true) or destroy
// (false) event.
func (ap *Probe) fanoutEvent(e Event) {
	// Take a read lock on the consumers so we don't send to closed or already
	// unregistered consumer channels.
	ap.consumerMu.RLock()

	for _, c := range ap.consumers {
		// Non-blocking send to the consumer's event channel.
		select {
		case c.events <- e:
			c.stats.setQueueLength(len(c.events))
			c.stats.incrEventsReceived()
		default:
			// If the channel can't be written to immediately,
			// increment the consumer's lost counter.
			c.stats.incrEventsLost()
		}
	}

	ap.consumerMu.RUnlock()
}
