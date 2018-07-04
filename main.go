package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/elf"
)

func main() {
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
}
