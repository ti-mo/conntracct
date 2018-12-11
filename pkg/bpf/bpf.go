package bpf

import (
	"fmt"
	"strings"

	"github.com/iovisor/gobpf/elf"
	"gitlab.com/0ptr/conntracct/pkg/kallsyms"
)

// Init initializes the package's accounting infrastructure and BPF
// message decoder. Convenience method over InitBPF() and ReadPerf().
func Init(lc chan uint64) (*elf.Module, chan AcctEvent, string, error) {

	kr, err := KernelRelease()
	if err != nil {
		return nil, nil, "", err
	}

	// Intermediate channel for binary perf map output towards the decoder.
	ec := make(chan []byte)

	// Load the appropriate BPF probe for the running kernel version.
	mod, pm, pv, err := Load(kr, ec, lc)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error during eBPF init: %v", err)
	}

	// Event channel with decoded AcctEvent structures.
	ed := make(chan AcctEvent)

	// Start BPF acct_event decoder in background.
	ReadPerf(pm, ec, ed)

	return mod, ed, pv, nil
}

// Load loads the acct BPF probe, attaches its Kprobes and perf map
// and returns their handles to the caller.
func Load(kr string, ec chan []byte, lc chan uint64) (*elf.Module, *elf.PerfMap, string, error) {

	// Load functions that insert records into a map last
	// to prevent stale records in BPF maps.
	probes := []string{
		"kprobe/nf_conntrack_free",
		"kretprobe/__nf_ct_refresh_acct",
		"kprobe/__nf_ct_refresh_acct",
	}

	// Scan kallsyms before attempting BPF load to avoid arcane error output from eBPF attach.
	err := checkProbeKsyms(probes)
	if err != nil {
		return nil, nil, "", err
	}

	// Select the correct BPF probe from the library.
	br, pv, err := Select(kr)
	if err != nil {
		return nil, nil, "", err
	}

	// Load the module from the bytes.Reader and insert into the kernel.
	module := elf.NewModuleFromReader(br)
	if err := module.Load(nil); err != nil {
		return nil, nil, "", fmt.Errorf("failed to load program: %v", err)
	}

	// Enable all kprobes in probe list.
	for _, p := range probes {
		if err := module.EnableKprobe(p, 0); err != nil {
			return nil, nil, "", fmt.Errorf("failed to enable kprobe: %v", err)
		}
	}

	// Set up the acct_events perf map with an event and lost channel.
	acctEvents, err := elf.InitPerfMap(module, "acct_events", ec, lc)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to open acct_events perf map: %v", err.Error())
	}

	return module, acctEvents, pv, nil
}

// ReadPerf starts a goroutine to decode binary BPF perf map output from the
// []byte channel into the returned AcctEvent channel. Calls PollStart() on the
// given elf.PerfMap.
func ReadPerf(pm *elf.PerfMap, ebc chan []byte, edc chan AcctEvent) {

	// Start BPF output decoder in the background.
	go func() {

		var eventID uint64

		var eb []byte
		var ok bool

		for {
			// Receive binary acct_event struct from BPF.
			eb, ok = <-ebc
			if !ok {
				// Close the downstream AcctEvent channel.
				close(edc)
				break
			}

			// Instantiate new AcctEvent and decode.
			var ae AcctEvent

			err := ae.UnmarshalBinary(eb)
			if err != nil {
				panic(fmt.Sprintf("error unmarshaling BPF acct_event bytestring: %s", err))
			}

			// Increment goroutine's event counter and send in acct message.
			eventID = eventID + 1
			ae.EventID = eventID

			edc <- ae
		}
	}()

	// Start polling the BPF perf ring buffer.
	pm.PollStart()
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
