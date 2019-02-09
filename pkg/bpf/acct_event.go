package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// EventLength is the length of the struct sent by BPF.
const EventLength = 104

// Event is an accounting event delivered to userspace from the Probe.
type Event struct {
	Start        uint64 // epoch timestamp of flow start
	Timestamp    uint64 // ktime timestamp of event
	ConnectionID uint32
	Connmark     uint32
	SrcAddr      net.IP
	DstAddr      net.IP
	PacketsOrig  uint64
	BytesOrig    uint64
	PacketsRet   uint64
	BytesRet     uint64
	SrcPort      uint16
	DstPort      uint16
	NetNS        uint32
	Proto        uint8
}

// UnmarshalBinary unmarshals a binary Event representation
// into a struct, using the machine's native endianness.
func (e *Event) UnmarshalBinary(b []byte) error {

	if len(b) != EventLength {
		return fmt.Errorf("input byte array incorrect length %d", len(b))
	}

	e.Start = *(*uint64)(unsafe.Pointer(&b[0]))
	e.Timestamp = *(*uint64)(unsafe.Pointer(&b[8]))
	e.ConnectionID = *(*uint32)(unsafe.Pointer(&b[16]))
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

	// Only extract ports for UDP and TCP.
	e.Proto = b[96]
	if e.Proto == 6 || e.Proto == 17 {
		e.SrcPort = binary.BigEndian.Uint16(b[88:90])
		e.DstPort = binary.BigEndian.Uint16(b[90:92])
	}

	e.NetNS = *(*uint32)(unsafe.Pointer(&b[92]))

	return nil
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
