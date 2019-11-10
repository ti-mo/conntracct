package elasticsearch

import (
	"strings"

	"github.com/ti-mo/conntracct/internal/sinks/types"

	elastic "github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"
)

func configureElastic(sc types.SinkConfig) []elastic.ClientOptionFunc {

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
