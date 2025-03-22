package clickhouse

import (
	"os"

	"github.com/ClickHouse/clickhouse-go/v2"
	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/internal/config"
)

// sinkDefaults sets default values on a SinkConfig structure.
func sinkDefaults(sc *config.SinkConfig) {

	if sc.Address == "" {
		sc.Address = "localhost:9000"
	}

	if sc.Database == "" {
		h, err := os.Hostname()
		if err != nil {
			panic(err)
		}
		sc.Database = "conntracct-" + h
	}

	if sc.BatchSize == 0 {
		sc.BatchSize = 2048
	}
}

// clientOptions extracts values from a SinkConfig to configure
// an clickhouse client.
func clientOptions(sc config.SinkConfig) *clickhouse.Options {

	// Initialize opts with a list of cluster addresses.
	opts := &clickhouse.Options{
		Addr: []string{sc.Address}, // Address of the ClickHouse server
		Auth: clickhouse.Auth{
			Database: sc.Database,
			Username: sc.Username,
			Password: sc.Password,
		},
	}

	log.WithField("sink", sc.Name).Debugf("Using clickhouse at address '%s'", sc.Address)
	log.WithField("sink", sc.Name).Debugf("Using clickhouse with database '%s'", sc.Database)

	// Set up basic authentication if configured.
	if sc.Username != "" && sc.Password != "" {
		log.WithField("sink", sc.Name).Debug("Configured clickhouse connection with authentication")
	}

	return opts
}
