package config

import (
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// DefaultProbeConfig is the default probe configuration.
var DefaultProbeConfig = ProbeConfig{
	RateCurve: &Curve{
		Zero: &CurvePoint{
			Age:  durationPtr(0),
			Rate: durationPtr(20 * time.Second),
		},
		One: &CurvePoint{
			Age:  durationPtr(1 * time.Minute),
			Rate: durationPtr(1 * time.Minute),
		},
		Two: &CurvePoint{
			Age:  durationPtr(5 * time.Minute),
			Rate: durationPtr(5 * time.Minute),
		},
	},
}

// ProbeConfig represents the configuration of an accounting probe.
type ProbeConfig struct {
	// Probe Rate Curve structure.
	RateCurve *Curve `mapstructure:"rate_curve"`
}

// Default recursively sets the given default values on the ProbeConfig.
// Finds any nil values in the configuration tree and initializes them
// to the given default.
func (pc *ProbeConfig) Default(def ProbeConfig) {
	// No ratecurve specified, copy a pointer to the whole default structure.
	if pc.RateCurve == nil {
		pc.RateCurve = def.RateCurve
	} else {
		pc.RateCurve.Default(*def.RateCurve)
	}
}

func (pc *ProbeConfig) String() string {
	return fmt.Sprintf("ProbeConfig{RateCurve: %s}", pc.RateCurve)
}

// Curve is the probe's rate curve configuration.
type Curve struct {
	Zero *CurvePoint `mapstructure:"0"`
	One  *CurvePoint `mapstructure:"1"`
	Two  *CurvePoint `mapstructure:"2"`
}

// Default recursively sets the given default values on the Curve.
func (c *Curve) Default(def Curve) {

	if c.Zero == nil {
		c.Zero = def.Zero
	} else {
		c.Zero.Default(*def.Zero.Age, *def.Zero.Rate)
	}

	if c.One == nil {
		c.One = def.One
	} else {
		c.One.Default(*def.One.Age, *def.One.Rate)
	}

	if c.Two == nil {
		c.Two = def.Two
	} else {
		c.Two.Default(*def.Two.Age, *def.Two.Rate)
	}
}

func (c *Curve) String() string {
	return fmt.Sprintf("{Zero: %s, One: %s, Two: %s}", c.Zero, c.One, c.Two)
}

// CurvePoint is an age/rate point in the probe's rate curve.
type CurvePoint struct {
	// The age a flow must have to be affected by this rate.
	Age *time.Duration `mapstructure:"age"`
	// The update rate of the flow.
	Rate *time.Duration `mapstructure:"rate"`
}

// Default initializes nil age or rate fields on the CurvePoint to the given values.
func (cp *CurvePoint) Default(age, rate time.Duration) {
	if cp.Age == nil {
		cp.Age = &age
	}
	if cp.Rate == nil {
		cp.Rate = &rate
	}
}

func (cp *CurvePoint) String() string {
	return fmt.Sprintf("[from:%s, every:%s]", cp.Age, cp.Rate)
}

// DecodeProbeConfigMap extracts a ProbeConfig from a string map of
// configuration data as provided by Viper.
func DecodeProbeConfigMap(cfg map[string]interface{}) (*ProbeConfig, error) {

	var out ProbeConfig

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Result:     &out,
	})
	if err != nil {
		panic(err)
	}

	// Decode sink configuration map into SinkConfig.
	if err := d.Decode(cfg); err != nil {
		return nil, err
	}

	return &out, nil
}

// BPFConfig extracts a pkg/bpf.Config from a ProbeConfig.
func (pc *ProbeConfig) BPFConfig() bpf.Config {
	return bpf.Config{
		Curve0: bpf.CurvePoint{
			Age:  *pc.RateCurve.Zero.Age,
			Rate: *pc.RateCurve.Zero.Rate,
		},
		Curve1: bpf.CurvePoint{
			Age:  *pc.RateCurve.One.Age,
			Rate: *pc.RateCurve.One.Rate,
		},
		Curve2: bpf.CurvePoint{
			Age:  *pc.RateCurve.Two.Age,
			Rate: *pc.RateCurve.Two.Rate,
		},
	}
}
