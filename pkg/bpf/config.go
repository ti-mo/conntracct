package bpf

import (
	"unsafe"

	"github.com/pkg/errors"

	"github.com/iovisor/gobpf/elf"
)

var (
	errCurve0Age = errors.New("Curve point 0's Age needs to be lower than point 1's and point 2's")
	errCurve1Age = errors.New("Curve point 1's Age needs to be between point 1's and point 2's")
	errCurve2Age = errors.New("Curve point 2's Age needs to be higher than point 1's and point 2's")
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

// A CurvePoint represents an age/interval pair, in milliseconds.
// It defines the update Interval of a flow that is older than the given Age.
type CurvePoint struct {
	AgeMillis      uint32
	IntervalMillis uint32
}

// AgeNanos returns the CurvePoint's Age specifier in nanoseconds.
func (p CurvePoint) AgeNanos() uint64 {
	return uint64(p.AgeMillis * 1000000) // 1 ms = 1 million ns
}

// IntervalNanos returns the CurvePoint's Interval specifier in nanoseconds.
func (p CurvePoint) IntervalNanos() uint64 {
	return uint64(p.IntervalMillis * 1000000) // 1 ms = 1 million ns
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
	curve0Interval
	curve1Age
	curve1Interval
	curve2Age
	curve2Interval
)

// configureProbe sets configuration values in the probe's config map.
func configureProbe(mod *elf.Module, cfg Config) error {

	// Set sane defaults on the configuration structure.
	probeDefaults(&cfg)

	if err := probeConfigVerify(cfg); err != nil {
		return errors.Wrap(err, "verifying probe configuration")
	}

	configMap := mod.Map("config")
	curveMap := mod.Map("config_ratecurve")

	k, v := curve0Age, cfg.Curve0.AgeNanos()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve0Age in config_ratecurve")
	}

	k, v = curve0Interval, cfg.Curve0.IntervalNanos()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve0Interval in config_ratecurve")
	}

	k, v = curve1Age, cfg.Curve1.AgeNanos()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve1Age in config_ratecurve")
	}

	k, v = curve1Interval, cfg.Curve1.IntervalNanos()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve1Interval in config_ratecurve")
	}

	k, v = curve2Age, cfg.Curve2.AgeNanos()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve2Age in config_ratecurve")
	}

	k, v = curve2Interval, cfg.Curve2.IntervalNanos()
	if err := mod.UpdateElement(curveMap, unsafe.Pointer(&k), unsafe.Pointer(&v), bpfAny); err != nil {
		return errors.Wrap(err, "Curve2Interval in config_ratecurve")
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
func probeDefaults(cfg *Config) {

	// Curve point 0.

	// Don't touch Curve0.AgeMillis, it should remain 0.
	// We allow the user to modify this if they want to ignore
	// flows younger than a certain age.

	if cfg.Curve0.IntervalMillis == 0 {
		cfg.Curve0.IntervalMillis = 20000 // 20 seconds
	}

	// Curve point 1.
	if cfg.Curve1.AgeMillis == 0 {
		cfg.Curve1.AgeMillis = 60000 // 60 seconds
	}

	if cfg.Curve1.IntervalMillis == 0 {
		cfg.Curve1.IntervalMillis = 60000 // 60 seconds
	}

	// Curve point 2.
	if cfg.Curve2.AgeMillis == 0 {
		cfg.Curve2.AgeMillis = 300000 // 300 seconds
	}

	if cfg.Curve2.IntervalMillis == 0 {
		cfg.Curve2.IntervalMillis = 300000 // 300 seconds
	}
}

func probeConfigVerify(cfg Config) error {

	if cfg.Curve0.AgeMillis > cfg.Curve1.AgeMillis ||
		cfg.Curve0.AgeMillis > cfg.Curve2.AgeMillis {
		return errCurve0Age
	}

	if cfg.Curve1.AgeMillis < cfg.Curve0.AgeMillis ||
		cfg.Curve1.AgeMillis > cfg.Curve2.AgeMillis {
		return errCurve1Age
	}

	if cfg.Curve2.AgeMillis < cfg.Curve0.AgeMillis ||
		cfg.Curve2.AgeMillis < cfg.Curve1.AgeMillis {
		return errCurve2Age
	}

	return nil
}
