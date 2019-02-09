package bpf

import (
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/pkg/errors"
)

var (
	// Map indices of configuration values for acct probe.
	configCooldown = 0
)

const (
	bpfAny = 0 // BPF_ANY
)

// Config is a configuration object for the acct BPF probe.
type Config struct {
	CooldownMillis uint32
}

// configureProbe sets configuration values in the probe's config map.
func configureProbe(mod *elf.Module, cfg Config) error {

	cm := mod.Map("config")

	if cfg.CooldownMillis != 0 {
		cd := cfg.CooldownMillis * 1000000 // 1 ms = 1 million ns
		if err := mod.UpdateElement(cm, unsafe.Pointer(&configCooldown), unsafe.Pointer(&cd), bpfAny); err != nil {
			return errors.Wrap(err, "cooldown")
		}
	}

	return nil
}
