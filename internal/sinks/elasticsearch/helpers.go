package elasticsearch

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/ti-mo/conntracct/internal/config"

	elastic "github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"
)

// sinkDefaults sets default values on a SinkConfig structure.
func sinkDefaults(sc *config.SinkConfig) {

	if sc.Address == "" {
		sc.Address = "http://localhost:9200"
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

	if sc.Shards == 0 {
		sc.Shards = 3
	}
}

// clientOptions extracts values from a SinkConfig to configure
// an elastic client.
func clientOptions(sc config.SinkConfig) []elastic.ClientOptionFunc {

	// Initialize opts with a list of cluster addresses.
	opts := []elastic.ClientOptionFunc{
		elastic.SetURL(strings.Split(sc.Address, ",")...),
		// Disable node discovery by default, this interferes with
		// connecting to ES clusters over the internet.
		elastic.SetSniff(false),
	}

	log.WithField("sink", sc.Name).Debugf("Using elasticsearch at address '%s'", sc.Address)

	// Set up basic authentication if configured.
	if sc.Username != "" && sc.Password != "" {
		opts = append(opts, elastic.SetBasicAuth(sc.Username, sc.Password))
		log.WithField("sink", sc.Name).Debug("Configured elasticsearch client with basic authentication")
	}

	return opts
}

// mustJSONEscape escapes a string to be safely sent in a json field.
func mustJSONEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}

	// Marshal output comes enclosed in double quotes, strip them.
	s := string(b)
	return s[1 : len(s)-1]
}
