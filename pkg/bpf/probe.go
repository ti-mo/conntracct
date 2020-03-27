package bpf

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/ti-mo/conntracct/pkg/kernel"
)

var (
	// Pseudorandom number for generating a 'unique' group name for the
	// tracing events created for the kernel symbols we want to trace.
	traceGroupSuffix string

	traceEventsPath = "/sys/kernel/debug/tracing/kprobe_events"

	errInvalidProbeKind = errors.New("only kprobe and kretprobe probes are supported")
)

func init() {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	traceGroupSuffix = fmt.Sprintf("%x", b)
}

const perfUpdateMap = "perf_acct_update"
const perfDestroyMap = "perf_acct_end"

// Probe is an instance of a BPF probe running in the kernel.
type Probe struct {

	// cilium/ebpf resources.
	collection    *ebpf.Collection
	updateReader  *perf.Reader
	destroyReader *perf.Reader

	// Target kernel of the loaded probe.
	kernel kernel.Kernel

	// List of event consumers of the probe.
	consumerMu sync.RWMutex
	consumers  []*Consumer

	// Channel for receiving IDs of lost perf events.
	lost chan uint64

	// perfWorker error channel.
	errs chan error

	// Started status of the probe.
	startMu sync.Mutex
	started bool

	stats *ProbeStats
}

// NewProbe instantiates a Probe using the given Config.
// Loads the BPF program into the kernel but does not attach its kprobes yet.
func NewProbe(cfg Config) (*Probe, error) {

	kr, err := kernelRelease()
	if err != nil {
		return nil, err
	}

	// Select the correct BPF probe from the library.
	br, k, err := Select(kr)
	if err != nil {
		return nil, errors.Wrap(err, "selecting BPF probe")
	}

	// Instantiate Probe with selected target kernel struct.
	ap := Probe{
		kernel: k,
		stats:  &ProbeStats{},
	}

	// Scan kallsyms before attempting BPF load to avoid arcane error output from eBPF attach.
	err = checkProbeKsyms(k.Probes)
	if err != nil {
		return nil, err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(br)
	if err != nil {
		return nil, errors.Wrap(err, "loading collection spec")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, errors.Wrap(err, "creating collection")
	}
	ap.collection = coll

	// Apply probe configuration.
	if err := ap.configure(cfg); err != nil {
		return nil, errors.Wrap(err, "configuring BPF probe")
	}

	return &ap, nil
}

func probeName(kind, symbol string) string {
	return kind + "_" + symbol
}

func probeGroup() string {
	return "conntracct_" + traceGroupSuffix
}

func probeEventEntry(group, kind, symbol string) string {

	k := "p"
	if kind == "kretprobe" {
		k = "r"
	}
	return fmt.Sprintf("%s:%s/%s %s", k, group, probeName(kind, symbol), symbol)
}

func getTraceEventID(group, name string) (int, error) {

	fname := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", group, name)
	fb, err := ioutil.ReadFile(fname)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, err
		}
		return 0, fmt.Errorf("cannot read kprobe id: %v", err)
	}

	tid, err := strconv.Atoi(strings.TrimSpace(string(fb)))
	if err != nil {
		return 0, fmt.Errorf("invalid kprobe id: %v", err)
	}

	return tid, nil
}

func openTraceEvent(group, kind, symbol string) (int, error) {

	if kind != "kprobe" && kind != "kretprobe" {
		return 0, errInvalidProbeKind
	}

	f, err := os.OpenFile(traceEventsPath, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return 0, fmt.Errorf("cannot open %s: %v", traceEventsPath, err)
	}
	defer f.Close()

	pe := probeEventEntry(group, kind, symbol)
	if _, err = f.WriteString(pe); err != nil {
		return 0, fmt.Errorf("writing %q to kprobe_events: %v", pe, err)
	}

	tid, err := getTraceEventID(group, probeName(kind, symbol))
	if err != nil {
		return 0, fmt.Errorf("getting trace event ID: %s", err)
	}

	return tid, nil
}

// perfEventOpenAttach creates a new perf event on tracepoint tid and binds a
// BPF program's progFd to it.
func perfEventOpenAttach(tid int, progFd int) (int, error) {

	attrs := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(tid),
	}

	// Create a perf event that fires each time the given tracepoint
	// (kernel symbol) is hit.
	efd, err := unix.PerfEventOpen(attrs, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return 0, fmt.Errorf("perf_event_open error: %v", err)
	}

	// Enable the perf event.
	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return 0, fmt.Errorf("enabling perf event: %v", err)
	}

	// Set the BPF program to execute each time the perf event fires.
	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_SET_BPF, progFd); err != nil {
		return 0, fmt.Errorf("attaching bpf program to perf event: %v", err)
	}

	return efd, nil
}

// perfEventDisable disables the perf event efd.
func perfEventDisable(efd int) error {
	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		return fmt.Errorf("disabling perf event: %v", err)
	}
	return nil
}

// Start attaches the BPF program's kprobes and starts polling the perf ring buffer.
func (ap *Probe) Start() error {

	ap.startMu.Lock()
	defer ap.startMu.Unlock()

	if ap.started {
		return errProbeStarted
	}

	for _, p := range ap.kernel.Probes {
		// Open a trace event for each of the kernel symbols we want to hook.
		// These events can be routed to the perf subsystem, where BPF programs
		// can be attached to them.
		tid, err := openTraceEvent(probeGroup(), p.Kind, p.Name)
		if err != nil {
			return err
		}

		prog, ok := ap.collection.Programs[p.ProgramName()]
		if !ok {
			return fmt.Errorf("looking up program '%s' in BPF collection", p.ProgramName())
		}

		// Create a perf event using the trace event opened above, and attach
		// a BPF program to it.
		if _, err := perfEventOpenAttach(tid, prog.FD()); err != nil {
			return fmt.Errorf("opening perf event: %v", err)
		}
	}

	ap.lost = make(chan uint64)
	ap.errs = make(chan error)

	// Set up Readers for reading events from the perf ring buffers.
	r, err := perf.NewReader(ap.collection.Maps[perfUpdateMap], 4096)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("NewReader for %s", perfUpdateMap))
	}
	ap.updateReader = r

	r, err = perf.NewReader(ap.collection.Maps[perfDestroyMap], 4096)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("NewReader for %s", perfDestroyMap))
	}
	ap.destroyReader = r

	// Start event decoder/fanout workers.
	go ap.updateWorker()
	go ap.destroyWorker()

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

	// TODO: Disable perf events.
	// TODO: Clean up tracepoints.

	close(ap.lost)
	close(ap.errs)

	return nil
}

// Kernel returns the target kernel structure of the selected probe.
func (ap *Probe) Kernel() kernel.Kernel {
	return ap.kernel
}

// ErrChan returns an initialized Probe's unbuffered error channel.
// The error channel is unbuffered because it doesn't make sense to have
// stale error data. If there is no ready consumer on the channel, errors
// are dropped.
// Returns nil if the Probe has not been Start()ed yet.
func (ap *Probe) ErrChan() chan error {
	return ap.errs
}

// Stats returns a snapshot copy of the Probe's statistics.
func (ap *Probe) Stats() ProbeStats {
	return ap.stats.Get()
}

// sendError safely sends a message on the Probe's unbuffered errChan.
// If there is no ready channel receiver, sendError is a no-op. A return value
// of true means the error was successfully sent on the channel.
func (ap *Probe) sendError(err error) bool {
	select {
	case ap.errs <- err:
		return true
	default:
		return false
	}
}

// updateWorker reads binady flow update events from the Probe's ring buffer,
// unmarshals the events into Event structures and sends them on all registered
// consumers' event channels.
func (ap *Probe) updateWorker() {

	for {
		rec, err := ap.updateReader.Read()
		if err != nil {
			// Reader closed, gracefully exit the read loop.
			if perf.IsClosed(err) {
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
			ap.sendError(errors.Wrap(err, "error unmarshaling Event byte array"))
			continue
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
			if perf.IsClosed(err) {
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
			ap.sendError(errors.Wrap(err, "error unmarshaling Event byte array"))
			continue
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
