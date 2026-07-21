package bpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"unsafe"

	"lukechampine.com/blake3"
)

var hashPool = sync.Pool{
	New: func() interface{} {
		// Output size is 32 bits.
		return blake3.New(4, nil)
	},
}

// EventLength is the length of the struct sent by BPF.
const EventLength = 108

//go:generate go tool stringer -type=EventType
type EventType uint32

const (
	New EventType = 1 << iota
	Update
	Destroy
)

// Event is an accounting event delivered to userspace from the Probe.
type Event struct {
	Start       uint64     `json:"start"`     // epoch timestamp of flow start
	Timestamp   uint64     `json:"timestamp"` // ktime of event, relative to machine boot time
	FlowID      uint32     `json:"flow_id"`
	Connmark    uint32     `json:"connmark"`
	SrcAddr     netip.Addr `json:"src_addr"`
	DstAddr     netip.Addr `json:"dst_addr"`
	PacketsOrig uint64     `json:"packets_orig"`
	BytesOrig   uint64     `json:"bytes_orig"`
	PacketsRet  uint64     `json:"packets_ret"`
	BytesRet    uint64     `json:"bytes_ret"`
	SrcPort     uint16     `json:"src_port"`
	DstPort     uint16     `json:"dst_port"`
	NetNS       uint32     `json:"netns"`
	Type        EventType  `json:"type"`
	Proto       uint8      `json:"proto"`

	connPtr uint64
}

// unmarshalBinary unmarshals a slice of bytes received from the
// kernel's eBPF perf map into a struct using the machine's native endianness.
func (e *Event) unmarshalBinary(b []byte) error {
	if len(b) != EventLength {
		return fmt.Errorf("input byte array incorrect length %d (expected %d): %v", len(b), EventLength, b)
	}

	e.Start = *(*uint64)(unsafe.Pointer(&b[0]))
	e.Timestamp = *(*uint64)(unsafe.Pointer(&b[8]))
	e.connPtr = *(*uint64)(unsafe.Pointer(&b[16]))

	// Build an IPv4 address if only the first four bytes
	// of the nf_inet_addr union are filled.
	e.SrcAddr = addrFromBPF([16]byte(b[24:40]))
	e.DstAddr = addrFromBPF([16]byte(b[40:56]))

	e.PacketsOrig = *(*uint64)(unsafe.Pointer(&b[56]))
	e.BytesOrig = *(*uint64)(unsafe.Pointer(&b[64]))
	e.PacketsRet = *(*uint64)(unsafe.Pointer(&b[72]))
	e.BytesRet = *(*uint64)(unsafe.Pointer(&b[80]))

	e.Connmark = *(*uint32)(unsafe.Pointer(&b[88]))
	e.NetNS = *(*uint32)(unsafe.Pointer(&b[92]))

	// Only extract ports for UDP and TCP.
	e.Proto = b[100]
	if e.Proto == 6 || e.Proto == 17 {
		e.SrcPort = binary.BigEndian.Uint16(b[96:98])
		e.DstPort = binary.BigEndian.Uint16(b[98:100])
	}

	// Generate and set the Event's FlowID.
	e.FlowID = e.hashFlow()

	return nil
}

// hashFlow calculates a flow hash base on the the Event's
// source and destination address, ports, protocol and connection ID.
func (e *Event) hashFlow() uint32 {

	// Get a Hasher from the pool.
	h := hashPool.Get().(*blake3.Hasher)

	// Source/Destination Address.
	_, _ = h.Write(e.SrcAddr.AsSlice())
	_, _ = h.Write(e.DstAddr.AsSlice())

	b := make([]byte, 2)

	// Source Port.
	binary.BigEndian.PutUint16(b, e.SrcPort)
	_, _ = h.Write(b)

	// Destination Port.
	binary.BigEndian.PutUint16(b, e.DstPort)
	_, _ = h.Write(b)

	// Protocol.
	_, _ = h.Write([]byte{e.Proto})

	// nf_conn struct kernel pointer.
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, e.connPtr)
	_, _ = h.Write(b)

	// Calculate the hash.
	// Shift one position to the right to fit the FlowID into a
	// signed integer field, eg. in elasticsearch.
	out := binary.LittleEndian.Uint32(h.Sum(nil)) >> 1

	// Reset and return the Hasher to the pool.
	h.Reset()
	hashPool.Put(h)

	return out
}

// String returns a readable string representation of the Event.
func (e *Event) String() string {
	return fmt.Sprintf("%+v", *e)
}

// addrFromBPF returns a netip.Addr from a byte array representing an IPv4 or
// IPv6 address from the kernel.
//
// If the input array contains any non-zero bytes past the first 4, it is
// considered an IPv6 address.
func addrFromBPF(b [16]byte) netip.Addr {
	for _, v := range b[4:] {
		if v != 0 {
			return netip.AddrFrom16(b)
		}
	}
	return netip.AddrFrom4([4]byte(b[:4]))
}
