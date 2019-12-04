package bpf

import (
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/ti-mo/gobpf/elf"
)

var (
	errCurve0Age = errors.New("Curve point 0's Age needs to be lower than point 1's and point 2's")
	errCurve1Age = errors.New("Curve point 1's Age needs to be lower than point 2's")
)

// Config is a configuration object for the acct BPF probe.
type Config struct {
	// Curve* are curve points representing update intervals
	// when flows reach a certain age. For example, when a flow
	// is 0ms old, it will send an event every 20s. When it reaches
	// an age of 1 minute, it will send an event every 60s, etc.
	Curve0 CurvePoint
	Curve1 CurvePoint
	Curve2 CurvePoint
}

// A CurvePoint represents an age/rate pair.
// It defines the update rate of a flow that is older than the given age.
type CurvePoint struct {
	Age  time.Duration
	Rate time.Duration
}

const (
	bpfAny     = 0    // BPF_ANY
	readyValue = 0x90 // Go!
)

// configOffset represents an offset in the probe's `config` BPF array.
type configOffset uint8

// Enum of indices in the probe's `config` BPF array.
const (
	configReady configOffset = iota
)

// curveOffset represents an offset in the probe's `curve` BPF array.
type curveOffset uint8

// Enum of indices in the probe's `curve` BPF array.
const (
	curve0Age curveOffset = iota
	curve0Rate
	curve1Age
	curve1Rate
	curve2Age
	curve2Rate
)

// configureProbe sets configuration values in the probe's config map.
func configureProbe(mod *elf.Module, cfg Config) error {

	// Set sane defaults on the configuration structure.
	cfg.probeDefaults()

	if err := probeConfigVerify(cfg); err != nil {
		return errors.Wrap(err, "verifying probe configuration")
	}

	configMap := mod.Map("config")
	curveMap := mod.Map("config_ratecurve")

	k, v := curve0Age, cfg.Curve0.Age.Nanoseconds()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve0Age in config_ratecurve")
	}

	k, v = curve0Rate, cfg.Curve0.Rate.Nanoseconds()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve0Rate in config_ratecurve")
	}

	k, v = curve1Age, cfg.Curve1.Age.Nanoseconds()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve1Age in config_ratecurve")
	}

	k, v = curve1Rate, cfg.Curve1.Rate.Nanoseconds()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve1Rate in config_ratecurve")
	}

	k, v = curve2Age, cfg.Curve2.Age.Nanoseconds()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve2Age in config_ratecurve")
	}

	k, v = curve2Rate, cfg.Curve2.Rate.Nanoseconds()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve2Rate in config_ratecurve")
	}

	// Set the ready bit in the probe's config map to make it start sending traffic.
	cfgKey, v := configReady, readyValue
	if err := mod.UpdateElement(configMap, unsafe.Pointer(&cfgKey), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "configReady in config")
	}

	return nil
}

// configureProbeDefaults manipulates the given Config to set it up with
// default values.
func (cfg *Config) probeDefaults() {

	// Curve point 0.

	// Don't touch Curve0.AgeMillis, it can remain 0.
	// We allow the user to modify this if they want to ignore
	// flows younger than a certain age.

	if cfg.Curve0.Rate == 0 {
		cfg.Curve0.Rate = 20 * time.Second
	}

	// Curve point 1.
	if cfg.Curve1.Age == 0 {
		cfg.Curve1.Age = 60 * time.Second
	}

	if cfg.Curve1.Rate == 0 {
		cfg.Curve1.Rate = 60 * time.Second
	}

	// Curve point 2.
	if cfg.Curve2.Age == 0 {
		cfg.Curve2.Age = 5 * time.Minute
	}

	if cfg.Curve2.Rate == 0 {
		cfg.Curve2.Rate = 5 * time.Minute
	}
}

func probeConfigVerify(cfg Config) error {

	// Ensure curve0 lower than curve1 and curve2.
	if cfg.Curve0.Age >= cfg.Curve1.Age ||
		cfg.Curve0.Age >= cfg.Curve2.Age {
		return errCurve0Age
	}

	// Ensure curve1 between curve0 and curve2.
	if cfg.Curve1.Age >= cfg.Curve2.Age {
		return errCurve1Age
	}

	return nil
}
