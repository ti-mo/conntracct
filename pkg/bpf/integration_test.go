// +build integration

package bpf

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/conntracct/pkg/udpecho"
	"golang.org/x/sys/unix"
)

// Mock UDP server listen port.
const (
	udpServ = 1342
)

var (
	acctProbe      *Probe
	errChanTimeout = errors.New("timeout")
)

func TestMain(m *testing.M) {

	var err error

	cfg := Config{
		Curve0: CurvePoint{
			Age:  0 * time.Millisecond,
			Rate: 10 * time.Millisecond,
		},
		Curve1: CurvePoint{
			Age:  50 * time.Millisecond,
			Rate: 25 * time.Millisecond,
		},
		Curve2: CurvePoint{
			Age:  100 * time.Millisecond,
			Rate: 50 * time.Millisecond,
		},
	}

	// Set the required sysctl's for the probe to gather accounting data.
	err = Sysctls(false)
	if err != nil {
		log.Fatal(err)
	}

	// Create and start the Probe.
	acctProbe, err = NewProbe(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := acctProbe.Start(); err != nil {
		log.Fatal(err)
	}
	go errWorker(acctProbe.ErrChan())

	// Create and start the localhost UDP listener.
	c := udpecho.ListenAndEcho(1342)

	// Run tests, save the return code.
	rc := m.Run()

	// Tear down resources.
	acctProbe.Stop()
	c.Close()

	os.Exit(rc)
}

// Checks if the first packet in a flow is logged, and that
// a further read from the channel times out.
func TestProbeFirstPacket(t *testing.T) {

	// Create and register consumer.
	ac, in := newUpdateConsumer(t)

	// Create UDP client.
	mc := udpecho.Dial(udpServ)

	// Filter BPF Events based on client port.
	out := filterSourcePort(in, mc.ClientPort())

	mc.Ping(1)
	ev, err := readTimeout(out, 5)
	assert.EqualValues(t, 1, ev.PacketsOrig+ev.PacketsRet, ev.String())
	require.NoError(t, err)

	// Send another ping, and expect it to not be logged.
	// Further attempt(s) to read from the channel should time out.
	mc.Ping(1)
	ev, err = readTimeout(out, 5)
	assert.EqualError(t, err, "timeout", ev.String())

	require.NoError(t, acctProbe.RemoveConsumer(ac))
}

// Run through all three age/interval curve points to test
// if the probe is sending and dropping the right events.
// Tests the following curve (values in milliseconds):
// Age: 0, Interval: 10
// Age: 50, Interval: 25
// Age: 100, Interval: 50
func TestProbeCurve(t *testing.T) {

	// Create and register consumer.
	ac, in := newUpdateConsumer(t)

	// Create UDP client.
	mc := udpecho.Dial(udpServ)

	// Filter BPF Events based on client port.
	out := filterSourcePort(in, mc.ClientPort())

	// Send a two-way ping,
	mc.Ping(1)
	// expect the first packet to be logged,
	ev, err := readTimeout(out, 5)
	assert.EqualValues(t, 1, ev.PacketsOrig+ev.PacketsRet, ev.String())
	require.NoError(t, err)
	// and the response to be dropped.
	ev, err = readTimeout(out, 1)
	// This also means events are drained.
	assert.EqualError(t, err, "timeout", ev.String())

	// Wait out the first cooldown period (10ms).
	time.Sleep(10 * time.Millisecond)

	// Checkpoint: about 11ms after the first packet
	// due to the forced 1ms read timeout earlier.

	// Send another two-way ping,
	mc.Ping(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)
	// and expect it to be the 3rd packet in this flow.
	assert.EqualValues(t, 3, ev.PacketsOrig+ev.PacketsRet, ev.String())

	// Wait until the flow is older than the second age on the curve.
	time.Sleep(40 * time.Millisecond)

	// Checkpoint: about 51ms after the first packet.
	// The flow is now between the 2nd and the 3rd age curve point,
	// setting its cooldown period to 25ms.

	// Send another two-way ping,
	mc.Ping(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)
	// and expect it to be the 5th packet in this flow.
	assert.EqualValues(t, 5, ev.PacketsOrig+ev.PacketsRet, ev.String())
	// Expect the response to be dropped again.
	ev, err = readTimeout(out, 1)
	// This also means events are drained.
	assert.EqualError(t, err, "timeout", ev.String())

	// Checkpoint: 52ms
	// Wait for a duration equal to the _first_ interval on the curve,
	// and expect the event to be dropped. This validates the switching
	// to a higher interval along with the flow's age.
	time.Sleep(10 * time.Millisecond)

	mc.Ping(1)
	// Expect the response to be dropped again.
	ev, err = readTimeout(out, 1)
	// This also means events are drained.
	assert.EqualError(t, err, "timeout", ev.String())

	// Checkpoint: 63ms
	// Wait for the remaining 14ms of the cooldown of the 5th packet.
	time.Sleep(14 * time.Millisecond)

	mc.Ping(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)
	// Expect it to be the 9th packet in the flow.
	assert.EqualValues(t, 9, ev.PacketsOrig+ev.PacketsRet, ev.String())

	// Checkpoint: 77ms
	// Wait for the flow to reach at least 100ms of age.
	time.Sleep(25 * time.Millisecond)

	mc.Ping(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)
	// Expect it to be the 11th packet in the flow.
	assert.EqualValues(t, 11, ev.PacketsOrig+ev.PacketsRet, ev.String())

	// Checkpoint: 102ms
	// Wait for a duration equal to the _second_ interval on the curve.
	time.Sleep(25 * time.Millisecond)

	mc.Ping(1)
	// Expect the response to be dropped again.
	ev, err = readTimeout(out, 1)
	// This also means events are drained.
	assert.EqualError(t, err, "timeout", ev.String())

	// Checkpoint: 128ms
	// Wait out the full cooldown period of the 11th packet.
	time.Sleep(24 * time.Millisecond)

	mc.Ping(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)
	// Expect it to be the 15th packet in the flow.
	assert.EqualValues(t, 15, ev.PacketsOrig+ev.PacketsRet, ev.String())

	// Remove the consumer from the probe.
	require.NoError(t, acctProbe.RemoveConsumer(ac))
}

// Verify as many fields as possible based on information obtained from other
// sources. This checks whether the BPF program is reading the correct offsets
// from kernel memory.
func TestProbeVerify(t *testing.T) {

	// Create and register consumer.
	ac, in := newUpdateConsumer(t)

	// Create UDP client.
	mc := udpecho.Dial(udpServ)

	// Filter BPF Events based on client port.
	out := filterSourcePort(in, mc.ClientPort())

	// Generate a single dummy event.
	mc.Nop(1)
	ev, err := readTimeout(out, 5)
	require.NoError(t, err)

	// Network Namespace
	ns, err := getNSID()
	require.NoError(t, err)
	assert.EqualValues(t, ns, ev.NetNS, ev.String())

	// Timestamp is always 0 on the first packet, since it passes
	// the conntrack accounting code before being in 'confirmed' state.
	// The nf_conn_tstamp is written in the confirmation routine.
	assert.EqualValues(t, 0, ev.Start, ev.String())

	// Connmark (default 0)
	assert.EqualValues(t, 0, ev.Connmark, ev.String())

	// Accounting
	assert.EqualValues(t, 1, ev.PacketsOrig, ev.String())
	assert.EqualValues(t, 31, ev.BytesOrig, ev.String())
	assert.EqualValues(t, 0, ev.PacketsRet, ev.String())
	assert.EqualValues(t, 0, ev.BytesRet, ev.String())

	// Connection tuple
	assert.EqualValues(t, udpServ, ev.DstPort, ev.String())
	assert.EqualValues(t, mc.ClientPort(), ev.SrcPort, ev.String())
	assert.EqualValues(t, net.IPv4(127, 0, 0, 1), ev.SrcAddr, ev.String())
	assert.EqualValues(t, net.IPv4(127, 0, 0, 1), ev.DstAddr, ev.String())
	assert.EqualValues(t, 17, ev.Proto, ev.String())

	// Wait for the first cooldown period to be over.
	time.Sleep(10 * time.Millisecond)

	// Generate a second event.
	mc.Nop(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)

	// The nf_conn should be in 'confirmed' state,
	// so the start timestamp should be written.
	assert.NotEqual(t, 0, ev.Start, ev.String())

	require.NoError(t, acctProbe.RemoveConsumer(ac))
}

// filterSourcePort returns an unbuffered channel of Events
// that has its event stream filtered by the given source port.
func filterSourcePort(in chan Event, port uint16) chan Event {
	out := make(chan Event)
	go filterWorker(in, out,
		func(ev Event) bool {
			if ev.SrcPort == port {
				return true
			}
			return false
		})

	return out
}

// filterWorker sends an Event from in to out if the given function f yields true.
func filterWorker(in <-chan Event, out chan<- Event, f func(Event) bool) {
	for {
		ev, ok := <-in
		if !ok {
			close(out)
			return
		}

		if f(ev) {
			out <- ev
		}
	}
}

// errWorker listens for errors on the Probe's error channel.
// Terminates the test suite when an error occurs.
func errWorker(ec <-chan error) {
	for err := range ec {
		log.Fatal("unexpected error from Probe:", err)
	}
}

// readTimeout attempts a read from an Event channel, timing out
// when a message wasn't read after ms milliseconds.
func readTimeout(c <-chan Event, ms uint) (Event, error) {
	select {
	case ev := <-c:
		return ev, nil
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return Event{}, errChanTimeout
	}
}

// newUpdateConsumer creates and registers an Consumer for a test.
func newUpdateConsumer(t *testing.T) (*Consumer, chan Event) {
	c := make(chan Event, 2048)
	ac := NewConsumer(t.Name(), c, ConsumerUpdate)
	require.NoError(t, acctProbe.RegisterConsumer(ac))

	return ac, c
}

// getNSID gets the inode of the current process' network namespace.
func getNSID() (uint64, error) {
	path := fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), syscall.Gettid())
	fd, err := unix.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}

	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return 0, err
	}

	return s.Ino, nil
}
