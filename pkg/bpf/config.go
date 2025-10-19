package bpf

import (
	"errors"
	"fmt"
	"time"
)

var (
	errCurve0Age = errors.New("curve point 0's Age needs to be lower than point 1's and point 2's")
	errCurve1Age = errors.New("curve point 1's Age needs to be lower than point 2's")
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

func (p CurvePoint) marshal() *acctCurvePoint {
	return &acctCurvePoint{
		Age:      uint64(p.Age.Nanoseconds()),
		Interval: uint64(p.Rate.Nanoseconds()),
	}
}

// configure configures specs using cfg.
func configure(specs *acctSpecs, cfg Config) error {
	// Set sane defaults on the configuration structure.
	cfg.defaults()

	if err := probeConfigVerify(cfg); err != nil {
		return fmt.Errorf("verifying probe configuration: %w", err)
	}

	if err := specs.Curve0.Set(cfg.Curve0.marshal()); err != nil {
		return fmt.Errorf("setting curve0: %w", err)
	}
	if err := specs.Curve1.Set(cfg.Curve1.marshal()); err != nil {
		return fmt.Errorf("setting curve1: %w", err)
	}
	if err := specs.Curve2.Set(cfg.Curve2.marshal()); err != nil {
		return fmt.Errorf("setting curve2: %w", err)
	}

	return nil
}

// configureProbeDefaults manipulates the given Config to set it up with
// default values.
func (cfg *Config) defaults() {
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
