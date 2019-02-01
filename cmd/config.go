package cmd

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/ti-mo/conntracct/internal/pipeline"
	"github.com/ti-mo/conntracct/internal/sinks"
	"github.com/ti-mo/conntracct/internal/sinks/types"
)

var (
	// Key names in configuration file.
	cfgAPIEnabled    = "api_enabled"
	cfgAPIEndpoint   = "api_endpoint"
	cfgSysctlManage  = "sysctl_manage"
	cfgPProfEnabled  = "pprof_enabled"
	cfgPProfEndpoint = "pprof_endpoint"

	cfgSinks = "sinks"

	// Default application configuration.
	cfgDefaults = map[string]interface{}{
		// HTTP API endpoint.
		cfgAPIEnabled:  true,
		cfgAPIEndpoint: "localhost:8000",

		// Sinks for accounting data.
		cfgSinks: map[string]interface{}{
			"stdout": map[string]interface{}{
				"type":        "stdout",
				"sourcePorts": true,
			},
		},

		// Automatically manage Conntrack-related sysctls of the host.
		cfgSysctlManage: true,

		// Run a pprof endpoint during operation. (live profiling)
		cfgPProfEnabled:  false,
		cfgPProfEndpoint: "localhost:6060",
	}
)

func init() {
	// Initialize Viper with configuration defaults.
	for k, v := range cfgDefaults {
		viper.SetDefault(k, v)
	}
}

// initRegisterSinks initializes a list of sinks according to their types
// and registers them to the given pipeline.
func initRegisterSinks(cl []types.SinkConfig, pipe *pipeline.Pipeline) error {

	for _, cfg := range cl {
		// Create and initialize a new sink based on the SinkConfig.
		sink, err := sinks.New(cfg)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("creating sink '%s'", cfg.Name))
		}

		// Register created sink with pipeline.
		if err := pipe.RegisterSink(sink); err != nil {
			return errors.Wrap(err, fmt.Sprintf("registering sink '%s' to pipeline", cfg.Name))
		}
	}

	return nil
}
