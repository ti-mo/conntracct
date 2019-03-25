package types

import (
	"fmt"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
)

// SinkConfig represents the configuration of an accounting sink.
type SinkConfig struct {

	// Flush batch when it holds this many points.
	BatchSize uint32 `mapstructure:"batchSize"`

	// Maximum network payload size, only for UDP-based sinks.
	UDPPayloadSize uint16 `mapstructure:"udpPayloadSize"`

	// The type of accounting sink.
	Type SinkType `mapstructure:"type"`

	// Whether or not the sink should receive the flows' source ports.
	EnableSrcPort bool `mapstructure:"enableSrcPort"`

	// Name of the sink.
	Name string `mapstructure:"-"`

	// Target address of the sink's backing storage.
	Address string `mapstructure:"address"`

	// Username of the sink's backing storage.
	Username string `mapstructure:"username"`

	// Password of the sink's backing storage.
	Password string `mapstructure:"password"`

	// Database name of the sink's backing storage.
	Database string `mapstructure:"database"`

	// Write timeout of the sink's backing storage.
	Timeout time.Duration `mapstructure:"timeout"`
}

// DecodeSinkConfigMap extracts a map of SinkConfigs from configuration data.
// The value of the string map is expected to be a nested string-map-interface
// with the annotated fields of a SinkConfig.
func DecodeSinkConfigMap(cfg map[string]interface{}) ([]SinkConfig, error) {

	out := make([]SinkConfig, 0, len(cfg))

	for name, params := range cfg {
		sc := SinkConfig{
			Name: name, // ignored by mapstructure, use map key as name
		}

		d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: stringToSinkTypeHookFunc(), // decode strings to SinkTypes
			Result:     &sc,                        // destination struct of decode operation
		})
		if err != nil {
			panic(err)
		}

		// Decode sink configuration map into SinkConfig.
		if err := d.Decode(params); err != nil {
			return nil, err
		}

		out = append(out, sc)
	}

	return out, nil
}

// stringToSinkTypeHookFunc returns a mapstructure.DecodeHookFunc that converts
// strings to SinkTypes.
func stringToSinkTypeHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t != reflect.TypeOf(SinkType(0)) {
			return data, nil
		}

		switch data {
		case "dummy":
			return Dummy, nil
		case "stdout":
			return StdOut, nil
		case "stderr":
			return StdErr, nil
		case "influxdb-udp":
			return InfluxUDP, nil
		case "influxdb-http":
			return InfluxHTTP, nil
		case "elastic", "elasticsearch":
			return Elastic, nil
		default:
			return SinkType(0), fmt.Errorf("failed parsing sink type %v", data)
		}
	}
}
