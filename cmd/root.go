package cmd

import (
	"fmt"
	"os"
	"path"
	"runtime/debug"

	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("No BuildInfo found in binary")
	}

	rev := findSetting(bi, "vcs.revision")
	if findSetting(bi, "vcs.modified") == "true" {
		rev += " (dev)"
	}
	time := findSetting(bi, "vcs.time")
	goos := findSetting(bi, "GOOS")
	goarch := findSetting(bi, "GOARCH")

	buildInfo = fmt.Sprintf("%s built on %s with %s for %s/%s", rev, time, bi.GoVersion, goos, goarch)
}

func findSetting(bi *debug.BuildInfo, key string) string {
	for _, s := range bi.Settings {
		if s.Key != key {
			continue
		}
		return s.Value
	}
	return ""
}

var (
	appName   = "conntracct"
	buildInfo string

	cfgFile string
	dbg     bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   appName,
	Short: "A real-time Conntrack accounting exporter.",
	Long: `Conntracct is a tool for extracting network flow information from Linux hosts.
It hooks into Conntrack's accounting (acct) subsystem using eBPF to receive
low-overhead updates to connection packet counters.`,
	PersistentPreRun: rootPreRun,
}

// versionCmd represents the version command.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the application's version and build info.",
	Run:   printVersion,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "",
		"config file (default conntracct.yml in $HOME/.config/ or /etc/conntracct/)")
	rootCmd.PersistentFlags().BoolVarP(&dbg, "debug", "d", false, "enable debug logging")

	rootCmd.AddCommand(versionCmd)
}

// initConfig sets up Viper with config search paths and an env prefix.
func initConfig() {

	if cfgFile != "" {
		// Use given config file directly.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search directories for config file.
		viper.AddConfigPath(path.Join(home, ".config")) // $HOME/.config/
		viper.AddConfigPath("/etc/" + appName)          // /etc/conntracct/

		viper.SetConfigName(appName) // conntracct.{yml,toml,json,...}
	}

	viper.SetEnvPrefix("ct")

	// Automatically pull in known env variables.
	viper.AutomaticEnv()

	// If a config file is found, read it in and return.
	if err := viper.ReadInConfig(); err == nil {
		log.Infof("Using config file: %s", viper.ConfigFileUsed())
		return
	}
}

// rootPreRun runs after all commands have been initialized and config
// flags have been bound.
func rootPreRun(*cobra.Command, []string) {
	// Enable debug logging if debug flag enabled.
	if dbg {
		log.SetLevel(log.DebugLevel)
	}
}

// printVersion prints the app's build info to stdout.
func printVersion(cmd *cobra.Command, args []string) {
	fmt.Println(buildInfo)
}
