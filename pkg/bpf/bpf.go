package bpf

import (
	"fmt"
	"strings"

	"gitlab.com/0ptr/conntracct/pkg/kallsyms"

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

	// Scan kallsyms before attempting BPF load to avoid arcane error output from eBPF attach.
	err := checkProbeKsyms(probes)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	module := elf.NewModule("bpf/acct.o")
	if err := module.Load(nil); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to load program: %v", err)
	}

	// Enable all kprobes in probe list.
	for _, p := range probes {
		if err := module.EnableKprobe(p, 0); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to enable kprobe: %v", err)
		}
	}

	eventChan := make(chan []byte)
	lostChan := make(chan uint64)

	// Set up the acct_events perf map with an event and lost channel.
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

		var eventID uint64

		var eb []byte
		var ok bool

		for {
			// Receive binary acct_event struct from BPF
			eb, ok = <-ebc
			if !ok {
				// Close the downstream AcctEvent channel
				close(aec)
				break
			}

			// Instantiate new AcctEvent and decode
			var ae AcctEvent

			err := ae.UnmarshalBinary(eb)
			if err != nil {
				panic(fmt.Sprintf("error unmarshaling BPF acct_event bytestring: %s", err))
			}

			// Increment goroutine's event counter and send in acct message
			eventID = eventID + 1
			ae.EventID = eventID

			aec <- ae
		}
	}()

	// Start polling the BPF perf ring buffer
	pm.PollStart()

	return aec
}

// Init initializes the package's accounting infrastructure and BPF
// message decoder. Convenience method over InitBPF() and ReadPerf().
func Init() (*elf.Module, chan AcctEvent, chan uint64, error) {

	// Initialize accounting infrastructure
	mod, pm, ec, lc, err := InitBPF()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error during eBPF init: %v", err)
	}

	// Start BPF acct_event decoder in background
	ev := ReadPerf(pm, ec)

	return mod, ev, lc, nil
}

// checkProbeKsyms checks whether a list of k(ret)probes have their target functions
// present in the kernel. Expects strings in the format of k(ret)probe/<kernel-symbol>.
func checkProbeKsyms(probes []string) error {

	// Parse /proc/kallsyms and store result in kallsyms package.
	err := kallsyms.Refresh()
	if err != nil {
		return err
	}

	for _, p := range probes {
		ps := strings.Split(p, "/")
		if len(ps) != 2 {
			return fmt.Errorf(errFmtSplitKprobe, p)
		}

		sym := ps[1]

		sf, err := kallsyms.Find(sym)
		if err != nil {
			return err
		}

		if !sf {
			return fmt.Errorf(errFmtSymNotFound, sym)
		}
	}

	return nil
}
