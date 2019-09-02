package elasticsearch

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	es7 "github.com/elastic/go-elasticsearch/v7"

	"github.com/ti-mo/conntracct/internal/sinks/types"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// ElasticSink is an accounting sink implementing an elasticsearch client.
// It is only intended for flow archival (completed/destroyed flows).
type ElasticSink struct {

	// Sink had Init() called on it successfully.
	init bool

	// Sink's configuration object.
	config types.SinkConfig

	// elastic driver client handle.
	client *es7.Client

	// Sink stats.
	stats types.SinkStats
}

// New returns a new ElasticSearch accounting sink.
func New() ElasticSink {
	return ElasticSink{}
}

// Init initializes the ElasticSearch accounting sink.
func (s *ElasticSink) Init(sc types.SinkConfig) error {

	if sc.Name == "" {
		return errEmptySinkName
	}
	if sc.Address == "" {
		sc.Address = "http://localhost:9200"
	}

	ec := es7.Config{
		Addresses: strings.Split(sc.Address, ","),
		Username:  sc.Username,
		Password:  sc.Password,
		CloudID:   sc.CloudID,
		APIKey:    sc.APIKey,
	}

	// Try to open a connection to the database with the latest ES client.
	client, err := es7.NewClient(ec)
	if err != nil {
		return err
	}

	// Obtain information about the cluster.
	ir, err := client.Info()
	if err != nil {
		return err
	}

	// Check and parse cluster info response.
	info, err := parseInfo(ir)
	if err != nil {
		return err
	}

	log.WithField("sink", sc.Name).Debugf("Connected to ElasticSearch cluster '%s' version %s with ES client version %s",
		info.ClusterName, info.ServerVersion, info.ClientVersion)

	// Create index mapping.

	s.config = sc
	s.client = client

	// Start workers.

	// Mark the sink as initialized.
	s.init = true

	return nil
}

// Push an accounting event into the buffer of the ElasticSearch accounting sink.
func (s *ElasticSink) Push(e bpf.Event) {
	fmt.Println("ES received event:", e)
}

// IsInit returns true if the ElasticSearch accounting sink was successfully initialized.
func (s *ElasticSink) IsInit() bool {
	return s.init
}

// Name returns the ElasticSearch sink's name.
func (s *ElasticSink) Name() string {
	return s.config.Name
}

// Stats returns the ElasticSearch accounting sink's statistics structure.
func (s *ElasticSink) Stats() types.SinkStats {
	return s.stats.Get()
}

// WantUpdate always returns false, it is not interested in update events.
func (s *ElasticSink) WantUpdate() bool {
	return false
}

// WantDestroy always returns true, it is only interested in destroy events.
func (s *ElasticSink) WantDestroy() bool {
	return true
}

// TODO(timo): Install index mapping before rollover at midnight.
