package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/ti-mo/conntracct/internal/config"
	"github.com/ti-mo/conntracct/internal/pipeline"
	"github.com/ti-mo/conntracct/internal/sinks"
)

var (
	// Key names in configuration file.
	cfgAPIEnabled    = "api_enabled"
	cfgAPIEndpoint   = "api_endpoint"
	cfgSysctlManage  = "sysctl_manage"
	cfgPProfEnabled  = "pprof_enabled"
	cfgPProfEndpoint = "pprof_endpoint"

	// Sink config defaults are set in internal/config.
	cfgSinks = "sinks"

	// Probe config defaults are set in internal/config.
	cfgProbe = "probe"

	// Default application configuration.
	cfgDefaults = map[string]interface{}{
		// HTTP API endpoint.
		cfgAPIEnabled:  true,
		cfgAPIEndpoint: "localhost:8000",

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
func initRegisterSinks(cl []config.SinkConfig, pipe *pipeline.Pipeline) error {
	for _, cfg := range cl {
		// Create and initialize a new sink based on the SinkConfig.
		sink, err := sinks.New(cfg)
		if err != nil {
			return fmt.Errorf("creating sink %s: %w", cfg.Name, err)
		}
		log.Debugf("Created %s sink %s", cfg.Type, cfg.Name)

		// Register created sink with pipeline.
		if err := pipe.RegisterSink(sink); err != nil {
			return fmt.Errorf("registering sink %s: %w", cfg.Name, err)
		}
		log.Debugf("Registered %s sink %s", cfg.Type, cfg.Name)
	}

	return nil
}
