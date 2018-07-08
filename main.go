package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

type acctEvent struct {
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
	Proto        uint8
}

// UnmarshalBinary unmarshals a binary acctEvent representation
// into a struct, using the machine's native endianness.
func (e *acctEvent) UnmarshalBinary(b []byte) error {

	if len(b) != 88 {
		return fmt.Errorf("input byte array incorrect length %d", len(b))
	}

	e.Timestamp = *(*uint64)(unsafe.Pointer(&b[0]))
	e.ConnectionID = *(*uint32)(unsafe.Pointer(&b[8]))
	e.Connmark = *(*uint32)(unsafe.Pointer(&b[12]))

	// Build an IPv4 address if only the first four bytes
	// of the nf_inet_addr union are filled.
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

	e.Proto = b[84]

	// Only extract ports for UDP and TCP
	if e.Proto == 6 || e.Proto == 17 {
		e.SrcPort = binary.BigEndian.Uint16(b[80:82])
		e.DstPort = binary.BigEndian.Uint16(b[82:84])
	}

	return nil
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

func main() {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	module := elf.NewModule("bpf/acct.o")
	if err := module.Load(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close program: %v", err)
		}
	}()

	if err := module.EnableKprobe("kprobe/__nf_ct_refresh_acct", 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable kprobe: %v\n", err)
		os.Exit(1)
	}

	if err := module.EnableKprobe("kretprobe/__nf_ct_refresh_acct", 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable kretprobe: %v\n", err)
		os.Exit(1)
	}

	if err := module.EnableKprobe("kprobe/nf_conntrack_free", 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable kprobe: %v\n", err)
		os.Exit(1)
	}

	eventChan := make(chan []byte)
	lostChan := make(chan uint64)

	acctEvents, err := elf.InitPerfMap(module, "acct_events", eventChan, lostChan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open perf map: %v\n", err.Error())
		os.Exit(1)
	}

	go func() {
		var e acctEvent

		for {
			event := <-eventChan

			err := e.UnmarshalBinary(event)
			if err != nil {
				log.Fatalf("failed to decode received data: %s\n", err)
			}

			fmt.Println(e)
		}
	}()

	acctEvents.PollStart()
	<-sig
	acctEvents.PollStop()
}
