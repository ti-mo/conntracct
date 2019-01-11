package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// AcctEventLength is the length of the struct sent by BPF.
const AcctEventLength = 96

// AcctEvent is a kernelspace probe delivered
// by the 'acct' BPF program.
type AcctEvent struct {
	Timestamp    uint64
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

	// Decoder metadata for monitoring/tracing
	EventID uint64
}

// UnmarshalBinary unmarshals a binary AcctEvent representation
// into a struct, using the machine's native endianness.
func (e *AcctEvent) UnmarshalBinary(b []byte) error {

	if len(b) != AcctEventLength {
		return fmt.Errorf("input byte array incorrect length %d", len(b))
	}

	e.Timestamp = *(*uint64)(unsafe.Pointer(&b[0]))
	e.ConnectionID = *(*uint32)(unsafe.Pointer(&b[8]))
	e.Connmark = *(*uint32)(unsafe.Pointer(&b[12]))

	// Build an IPv4 address if only the first four bytes
	// of the nf_inet_addr union are filled.
	// Assigning 4 bytes directly into IP() is incorrect,
	// an IPv4 is stored in the last 4 bytes of an IP().
	if isIPv4(b[16:32]) {
		e.SrcAddr = net.IPv4(b[16], b[17], b[18], b[19])
	} else {
		e.SrcAddr = net.IP(b[16:32])
	}

	if isIPv4(b[32:48]) {
		e.DstAddr = net.IPv4(b[32], b[33], b[34], b[35])
	} else {
		e.DstAddr = net.IP(b[32:48])
	}

	e.PacketsOrig = *(*uint64)(unsafe.Pointer(&b[48]))
	e.BytesOrig = *(*uint64)(unsafe.Pointer(&b[56]))
	e.PacketsRet = *(*uint64)(unsafe.Pointer(&b[64]))
	e.BytesRet = *(*uint64)(unsafe.Pointer(&b[72]))

	// Only extract ports for UDP and TCP
	e.Proto = b[88]
	if e.Proto == 6 || e.Proto == 17 {
		e.SrcPort = binary.BigEndian.Uint16(b[80:82])
		e.DstPort = binary.BigEndian.Uint16(b[82:84])
	}

	e.NetNS = *(*uint32)(unsafe.Pointer(&b[84]))

	return nil
}

// String returns a readable string representation of the AcctEvent.
func (e *AcctEvent) String() string {
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
