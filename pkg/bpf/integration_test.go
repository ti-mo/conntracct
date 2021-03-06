// +build integration

package bpf

import (
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/jsimonetti/rtnetlink/rtnl"
	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ti-mo/conntracct/pkg/udpecho"
)

// Mock UDP server listen port.
const (
	udpServ  = 4444
	bindAddr = "127.0.1.1"
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

	// Set up a dummy network namespace and immediately close it.
	// One of the steps of preparing a namespace includes installing an nftables ruleset.
	// This ruleset contains a conntrack matcher, which will automatically cause the correct
	// conntrack kernel module to be loaded. This means we don't have to explicitly modprobe.
	_, _, f, err := prepareNetNS(9999)
	f()
	if err != nil {
		log.Fatal(err)
	}

	// Create and start the Probe.
	// For this to succeed, a conntrack kernel module needs to have been pre-loaded.
	acctProbe, err = NewProbe(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := acctProbe.Start(); err != nil {
		log.Fatal(err)
	}

	// Run tests, save the return code.
	rc := m.Run()

	// Tear down resources.
	if err := acctProbe.Stop(); err != nil {
		log.Fatal(err)
	}

	os.Exit(rc)
}

// Checks if the first packet in a flow is logged, and that
// a further read from the channel times out.
func TestProbeFirstPacket(t *testing.T) {

	// Create and register consumer.
	ac, in := newUpdateConsumer(t)

	// Set up a new network namespace to run tests.
	mc, _, cfn, err := prepareNetNS(udpServ)
	require.NoError(t, err, "preparing netns")
	defer cfn()

	// Filter BPF Events based on client port.
	out := filterSourcePort(in, mc.ClientPort())

	mc.Ping(1)
	ev, err := readTimeout(out, 5)
	require.NoError(t, err)
	assert.EqualValues(t, 1, ev.PacketsOrig+ev.PacketsRet, ev.String())

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

	// Set up a new network namespace to run tests.
	mc, _, cfn, err := prepareNetNS(udpServ)
	require.NoError(t, err, "preparing netns")
	defer cfn()

	// Filter BPF Events based on client port.
	out := filterSourcePort(in, mc.ClientPort())

	// Send a two-way ping,
	mc.Ping(1)
	// expect the first packet to be logged,
	ev, err := readTimeout(out, 5)
	require.NoError(t, err)
	assert.EqualValues(t, 1, ev.PacketsOrig+ev.PacketsRet, ev.String())
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

	// Set up a new network namespace to run tests.
	mc, ns, cfn, err := prepareNetNS(udpServ)
	require.NoError(t, err, "preparing netns")
	defer cfn()

	// Filter BPF Events based on client port.
	out := filterSourcePort(in, mc.ClientPort())

	// Generate a single dummy event.
	mc.Nop(1)
	ev, err := readTimeout(out, 5)
	require.NoError(t, err)

	// Network namespace.
	assert.EqualValues(t, ns, ev.NetNS, ev.String())

	// Timestamps
	assert.NotEqual(t, 0, ev.Start, ev.String())
	assert.NotEqual(t, 0, ev.Timestamp, ev.String())

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
	assert.EqualValues(t, net.IPv4(127, 0, 1, 1), ev.SrcAddr, ev.String())
	assert.EqualValues(t, net.IPv4(127, 0, 1, 1), ev.DstAddr, ev.String())
	assert.EqualValues(t, 17, ev.Proto, ev.String())

	start := ev.Start
	ts := ev.Timestamp

	// Wait for the first cooldown period to be over.
	time.Sleep(10 * time.Millisecond)

	// Generate a second event.
	mc.Nop(1)
	ev, err = readTimeout(out, 5)
	require.NoError(t, err)

	// Start timestamp should carry the same value between multiple events.
	assert.EqualValues(t, start, ev.Start, ev.String())
	// Make sure the timestamp value increased over the previous sample.
	assert.True(t, ev.Timestamp > ts)

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

// prepareNetNS creates a Conn in a new network namespace to use for testing.
// Returns the UDP server and client, the netns identifier and error, if any.
func prepareNetNS(port uint16) (*udpecho.MockUDPClient, uint64, func(), error) {

	// Lock the current goroutine to the OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get the current network namespace and
	// return the thread to it before unlocking.
	oldns, err := netns.Get()
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() {
		if err := netns.Set(oldns); err != nil {
			log.Fatal(err)
		}
	}()

	// Allocate new network namespace.
	newns, err := netns.New()
	if err != nil {
		return nil, 0, nil, errors.Wrap(err, "creating network namespace")
	}

	// Set up network interfaces inside the new netns.
	if err := setupInterface(newns); err != nil {
		return nil, 0, nil, errors.Wrap(err, "setting up interfaces")
	}

	// Set up nftables rules inside network namespace.
	if err := setupNFTables(port, newns); err != nil {
		return nil, 0, nil, errors.Wrap(err, "setting up nftables")
	}

	// Set the required sysctl's for the probe to gather accounting data.
	if err := Sysctls(false); err != nil {
		return nil, 0, nil, errors.Wrap(err, "applying sysctl")
	}

	// Create UDP listener inside network namespace.
	srv := udpecho.ListenAndEcho(bindAddr, port)

	// Create UDP client inside network namespace.
	client := udpecho.Dial(bindAddr, port)

	// Closer function passed to the caller to conveniently
	// close all resources.
	closer := func() {
		client.Close()
		srv.Close()
		newns.Close()
	}

	return client, netnsInode(newns), closer, nil
}

type CTState int

const (
	IPCTEstablished CTState = iota // IP_CT_ESTABLISHED
	_                              // IP_CT_RELATED
	IPCTNew                        // IP_CT_NEW
)

// ctStateBit replicates the behaviour of the NF_CT_STATE_BIT kernel macro.
func ctStateBit(state CTState) uint32 {
	return 1 << (uint32(state) + 1)
}

func setupNFTables(port uint16, ns netns.NsHandle) error {

	nftc := nftables.Conn{
		NetNS: int(ns),
	}

	nftc.FlushRuleset()

	table := &nftables.Table{
		Name:   "conntracct",
		Family: nftables.TableFamily(unix.NFPROTO_INET),
	}
	nftc.AddTable(table)

	policy := nftables.ChainPolicyDrop
	chain := &nftables.Chain{
		Name:     "ct_chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	}
	nftc.AddChain(chain)

	// Allow outgoing packets belonging to new and existing connections
	// towards server port.
	nftc.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{

			// UDP L4 Protocol
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},

			// UDP Destination Port
			&expr.Payload{
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // destination port
				Len:          2,
				DestRegister: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(port),
			},

			// New connections.
			// By matching on a conntrack state somewhere in the chain, we enable connection
			// tracking on all packets that are accepted somewhere in this chain.
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(ctStateBit(IPCTNew) | ctStateBit(IPCTEstablished)),
				Xor:            []uint8{0x0, 0x0, 0x0, 0x0},
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpNeq,
				Data:     []uint8{0x0, 0x0, 0x0, 0x0},
			},

			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Allow outgoing return packets belonging to
	// existing connections from server port.
	nftc.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{

			// UDP L4 Protocol
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},

			// UDP Source Port
			&expr.Payload{
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // source port
				Len:          2,
				DestRegister: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(port),
			},

			// Established connections.
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(ctStateBit(IPCTEstablished)),
				Xor:            []uint8{0x0, 0x0, 0x0, 0x0},
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpNeq,
				Data:     []uint8{0x0, 0x0, 0x0, 0x0},
			},

			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	if err := nftc.Flush(); err != nil {
		return err
	}

	return nil
}

func setupInterface(ns netns.NsHandle) error {

	// Dial a connection to the rtnetlink socket. Specify the netns
	// since netlink spawns a worker on a fresh OS thread. This thread
	// needs to be moved into the netns.
	conn, err := rtnl.Dial(&netlink.Config{NetNS: int(ns)})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Get the interface Index. This func runs on a goroutine
	// that is already locked to a new netns.
	link, err := net.InterfaceByName("lo")
	if err != nil {
		return errors.Wrap(err, "getting 'lo' ifindex")
	}

	// Bring up the link.
	if err := conn.LinkUp(link); err != nil {
		return errors.Wrap(err, "setting up link 'lo'")
	}

	// Add the address to the link.
	if err := conn.AddrAdd(link, rtnl.MustParseAddr(bindAddr+"/32")); err != nil {
		return errors.Wrap(err, "adding address to 'lo'")
	}

	return err
}

func netnsInode(ns netns.NsHandle) uint64 {

	if ns == -1 {
		panic("cannot get inode of a closed netns")
	}

	var s syscall.Stat_t
	if err := syscall.Fstat(int(ns), &s); err != nil {
		panic("error calling Fstat() on NsHandle: " + err.Error())
	}

	return s.Ino
}
