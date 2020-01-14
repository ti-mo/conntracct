package cmd

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ti-mo/conntracct/internal/apiserver"
	"github.com/ti-mo/conntracct/internal/config"
	"github.com/ti-mo/conntracct/internal/pipeline"
	"github.com/ti-mo/conntracct/internal/pprof"
)

// runCmd represents the run command.
var runCmd = &cobra.Command{
	Use:          "run",
	Short:        "Listen for conntrack events and send them to configured sinks.",
	RunE:         run,
	SilenceUsage: true, // Don't show usage when RunE returns error.
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func run(cmd *cobra.Command, args []string) error {

	log.Infoln("Starting", versionStr)

	if viper.GetBool(cfgPProfEnabled) {
		pprof.ListenAndServe(viper.GetString(cfgPProfEndpoint))
	}

	pcfg, scfg, err := getProbeSinkConfig()
	if err != nil {
		return err
	}

	pipe := pipeline.New()

	if err := initRegisterSinks(scfg, pipe); err != nil {
		return errors.Wrap(err, "initialize and register sinks")
	}

	// Initialize and start accounting pipeline.
	if err := pipe.Init(pcfg); err != nil {
		return errors.Wrap(err, "initialize pipeline")
	}

	if err := pipe.Start(); err != nil {
		return errors.Wrap(err, "start pipeline")
	}

	// Initialize and run the API server if enabled.
	if viper.GetBool(cfgAPIEnabled) {
		if err := apiserver.Init(pipe); err != nil {
			return err
		}

		if err := apiserver.Run(viper.GetString(cfgAPIEndpoint)); err != nil {
			return err
		}
	}

	defer func() {
		if err := pipe.Stop(); err != nil {
			log.Fatalf("Failure stopping pipeline: %v", err)
		}
	}()

	if err := config.Init(); err != nil {
		return errors.Wrap(err, "apply system configuration")
	}

	// Wait for program to be interrupted.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	log.Info("Exiting with signal ", <-sig)

	return nil
}

// getProbeSinkConfig parses the probe and sink configurations from Viper.
func getProbeSinkConfig() (*config.ProbeConfig, []config.SinkConfig, error) {

	// Get probe configuration from Viper.
	pcfg, err := config.DecodeProbeConfigMap(viper.GetStringMap(cfgProbe))
	if err != nil {
		return nil, nil, err
	}
	log.Debug("Read probe configuration: ", pcfg)

	// Fill ProbeConfig with defaults.
	pcfg.Default(config.DefaultProbeConfig)
	log.Info("Using probe configuration: ", pcfg)

	// Get sink configuration from Viper.
	scfg, err := config.DecodeSinkConfigMap(viper.GetStringMap(cfgSinks))
	if err != nil {
		return nil, nil, err
	}
	log.Debugf("Read sink configuration: %+v", scfg)

	if len(scfg) == 0 {
		scfg = config.DefaultSinkConfig
	}
	// Log as debug, these often contain credentials.
	log.Debugf("Using sink configuration: %+v", scfg)

	return pcfg, scfg, nil
}
