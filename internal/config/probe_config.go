package config

import (
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// ProbeConfig represents the configuration of an accounting probe.
type ProbeConfig struct {
	// Probe Rate Curve structure.
	RateCurve ProbeConfigCurve `mapstructure:"rate_curve"`
}

// ProbeConfigCurve is the probe's rate curve configuration.
type ProbeConfigCurve struct {
	Zero ProbeConfigCurvePoint `mapstructure:"0"`
	One  ProbeConfigCurvePoint `mapstructure:"1"`
	Two  ProbeConfigCurvePoint `mapstructure:"2"`
}

// ProbeConfigCurvePoint is an age/rate point in the probe's rate curve.
type ProbeConfigCurvePoint struct {
	// The age a flow must have to be affected by this rate.
	Age time.Duration `mapstructure:"age"`
	// The update rate of the flow.
	Rate time.Duration `mapstructure:"rate"`
}

// DecodeProbeConfigMap extracts ProbeConfig from configuration data.
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

// BPFConfig extracts a pkg/bpf.Config from a ProbeConfig
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
