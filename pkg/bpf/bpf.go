package bpf

import (
	"fmt"
	"log"

	"github.com/iovisor/gobpf/elf"
)

// InitBPF loads the acct BPF probe, enables its Kprobes
// and perf map and returns their handles to the caller.
func InitBPF() (*elf.Module, *elf.PerfMap, chan []byte, chan uint64, error) {

	// Load functions that insert records into a map last
	// to prevent stale records in BPF maps.
	probes := []string{
		"kprobe/nf_conntrack_free",
		"kretprobe/__nf_ct_refresh_acct",
		"kprobe/__nf_ct_refresh_acct",
	}

	// TODO: Load BPF object with statik or bindata
	// TODO: Scan kallsyms before attempting BPF load to avoid arcane error output

	module := elf.NewModule("bpf/acct.o")
	if err := module.Load(nil); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to load program: %v", err)
	}

	// Enable all kprobes in 'probes'
	for _, p := range probes {
		if err := module.EnableKprobe(p, 0); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to enable kprobe: %v", err)
		}
	}

	eventChan := make(chan []byte)
	lostChan := make(chan uint64)

	// Set up the acct_events perf map with an event and lost channel
	acctEvents, err := elf.InitPerfMap(module, "acct_events", eventChan, lostChan)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to open acct_events perf map: %v", err.Error())
	}

	return module, acctEvents, eventChan, lostChan, nil
}

// ReadPerf starts a goroutine to decode binary BPF perf map output from the
// []byte channel into the returned AcctEvent channel. Calls PollStart() on the
// given elf.PerfMap.
func ReadPerf(pm *elf.PerfMap, ebc chan []byte) chan AcctEvent {

	aec := make(chan AcctEvent)

	// Start BPF output decoder in the background
	go func() {

		var eb []byte
		var ok bool

		for {
			// Receive binary acct_event struct from BPF
			eb, ok = <-ebc
			if !ok {
				log.Println("BPF acct_event channel closed, exiting read loop")

				// Close the downstream AcctEvent channel
				close(aec)
				break
			}

			// Instantiate new AcctEvent and decode
			var ae AcctEvent
			err := ae.UnmarshalBinary(eb)
			if err != nil {
				log.Fatalf("error decoding BPF acct_event bytestring: %s\n", err)
			}

			aec <- ae
		}
	}()

	// Start polling the BPF perf ring buffer
	pm.PollStart()

	return aec
}

// Init initializes the `bpf` package's accounting infrastructure and BPF
// message decoder. Convenience method over InitBPF() and ReadPerf().
func Init() (*elf.Module, chan AcctEvent, chan uint64, error) {

	// Initialize accounting infrastructure
	mod, pm, ec, lc, err := InitBPF()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error initializing acct BPF module: %v", err)
	}

	// Start BPF acct_event decoder in background
	ev := ReadPerf(pm, ec)

	return mod, ev, lc, nil

}
