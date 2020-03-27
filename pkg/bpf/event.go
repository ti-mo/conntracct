package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
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
const EventLength = 104

// Event is an accounting event delivered to userspace from the Probe.
type Event struct {
	Start       uint64 `json:"start"`     // epoch timestamp of flow start
	Timestamp   uint64 `json:"timestamp"` // ktime of event, relative to machine boot time
	FlowID      uint32 `json:"flow_id"`
	Connmark    uint32 `json:"connmark"`
	SrcAddr     net.IP `json:"src_addr"`
	DstAddr     net.IP `json:"dst_addr"`
	PacketsOrig uint64 `json:"packets_orig"`
	BytesOrig   uint64 `json:"bytes_orig"`
	PacketsRet  uint64 `json:"packets_ret"`
	BytesRet    uint64 `json:"bytes_ret"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	NetNS       uint32 `json:"netns"`
	Proto       uint8  `json:"proto"`

	connectionID uint32
}

// unmarshalBinary unmarshals a slice of bytes received from the
// kernel's eBPF perf map into a struct using the machine's native endianness.
func (e *Event) unmarshalBinary(b []byte) error {

	if len(b) != EventLength {
		return fmt.Errorf("input byte array incorrect length %d (expected %d)", len(b), EventLength)
	}

	e.Start = *(*uint64)(unsafe.Pointer(&b[0]))
	e.Timestamp = *(*uint64)(unsafe.Pointer(&b[8]))
	e.connectionID = *(*uint32)(unsafe.Pointer(&b[16]))
	e.Connmark = *(*uint32)(unsafe.Pointer(&b[20]))

	// Build an IPv4 address if only the first four bytes
	// of the nf_inet_addr union are filled.
	// Assigning 4 bytes directly into IP() is incorrect,
	// an IPv4 is stored in the last 4 bytes of an IP().
	if isIPv4(b[24:40]) {
		e.SrcAddr = net.IPv4(b[24], b[25], b[26], b[27])
	} else {
		e.SrcAddr = net.IP(b[24:40])
	}

	if isIPv4(b[40:56]) {
		e.DstAddr = net.IPv4(b[40], b[41], b[42], b[43])
	} else {
		e.DstAddr = net.IP(b[40:56])
	}

	e.PacketsOrig = *(*uint64)(unsafe.Pointer(&b[56]))
	e.BytesOrig = *(*uint64)(unsafe.Pointer(&b[64]))
	e.PacketsRet = *(*uint64)(unsafe.Pointer(&b[72]))
	e.BytesRet = *(*uint64)(unsafe.Pointer(&b[80]))

	e.NetNS = *(*uint32)(unsafe.Pointer(&b[92]))

	// Only extract ports for UDP and TCP.
	e.Proto = b[96]
	if e.Proto == 6 || e.Proto == 17 {
		e.SrcPort = binary.BigEndian.Uint16(b[88:90])
		e.DstPort = binary.BigEndian.Uint16(b[90:92])
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
	_, _ = h.Write(e.SrcAddr)
	_, _ = h.Write(e.DstAddr)

	b := make([]byte, 2)

	// Source Port.
	binary.BigEndian.PutUint16(b, e.SrcPort)
	_, _ = h.Write(b)

	// Destination Port.
	binary.BigEndian.PutUint16(b, e.DstPort)
	_, _ = h.Write(b)

	// Protocol.
	_, _ = h.Write([]byte{e.Proto})

	b = make([]byte, 4)

	// Connection ID.
	binary.BigEndian.PutUint32(b, e.connectionID)
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

// isIPv4 checks if everything but the first 4 bytes of a bytearray
// are zero. The nf_inet_addr C struct holds an IPv4 address in the
// first 4 bytes followed by zeroes. Does not execute a bounds check.
func isIPv4(s []byte) bool {
	for _, v := range s[4:] {
		if v != 0 {
			return false
		}
	}
	return true
}
