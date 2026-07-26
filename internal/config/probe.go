package config

import (
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// defProbeConfig is the default probe configuration.
var defProbeConfig = ProbeConfig{
	RateCurve: Curve{
		Zero: CurvePoint{
			Age:  0,
			Rate: 5 * time.Second,
		},
		One: CurvePoint{
			Age:  30 * time.Second,
			Rate: 15 * time.Second,
		},
		Two: CurvePoint{
			Age:  1 * time.Minute,
			Rate: 30 * time.Second,
		},
	},
}

// ProbeConfig represents the configuration of an accounting probe.
type ProbeConfig struct {
	RateCurve Curve `mapstructure:"rate_curve"`
}

func (pc *ProbeConfig) String() string {
	return fmt.Sprintf("ProbeConfig{RateCurve: %s}", pc.RateCurve)
}

// Curve is the probe's rate curve configuration.
type Curve struct {
	Zero CurvePoint `mapstructure:"0"`
	One  CurvePoint `mapstructure:"1"`
	Two  CurvePoint `mapstructure:"2"`
}

func (c *Curve) String() string {
	return fmt.Sprintf("{Zero: %s, One: %s, Two: %s}", c.Zero, c.One, c.Two)
}

// CurvePoint is an age/rate point in the probe's rate curve.
type CurvePoint struct {
	// The age a flow must have to be affected by this rate.
	Age time.Duration `mapstructure:"age"`
	// The update rate of the flow.
	Rate time.Duration `mapstructure:"rate"`
}

func (cp *CurvePoint) String() string {
	return fmt.Sprintf("[from:%s, every:%s]", cp.Age, cp.Rate)
}

// DecodeProbeConfigMap extracts a ProbeConfig from a string map of
// configuration data as provided by Viper.
func DecodeProbeConfigMap(cfg map[string]any) (*ProbeConfig, error) {
	out := defProbeConfig
	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused: true,
		DecodeHook:  mapstructure.StringToTimeDurationHookFunc(),
		Result:      &out,
	})
	if err != nil {
		return nil, fmt.Errorf("creating config decoder: %w", err)
	}

	if err := d.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decoding probe configuration: %w", err)
	}

	return &out, nil
}

// BPFConfig extracts a pkg/bpf.Config from a ProbeConfig.
func (pc *ProbeConfig) BPFConfig() bpf.Config {
	return bpf.Config{
		Curve0: bpf.CurvePoint{
			Age:  pc.RateCurve.Zero.Age,
			Rate: pc.RateCurve.Zero.Rate,
		},
		Curve1: bpf.CurvePoint{
			Age:  pc.RateCurve.One.Age,
			Rate: pc.RateCurve.One.Rate,
		},
		Curve2: bpf.CurvePoint{
			Age:  pc.RateCurve.Two.Age,
			Rate: pc.RateCurve.Two.Rate,
		},
	}
}
