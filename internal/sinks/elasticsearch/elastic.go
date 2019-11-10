package elasticsearch

import (
	"strings"
	"sync"

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

	// Channel the send workers receive batches on.
	sendChan chan batch

	// Data point batch.
	batchMu sync.Mutex
	batch   batch

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
	if sc.BatchSize == 0 {
		sc.BatchSize = 2048
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

	log.WithField("sink", sc.Name).
		Debugf("Connected to ElasticSearch cluster '%s' version %s using client version %s",
			info.ClusterName, info.ServerVersion, info.ClientVersion)

	s.config = sc
	s.client = client

	// Start workers.
	s.sendChan = make(chan batch, 64)

	// Mark the sink as initialized.
	s.init = true

	return nil
}

// PushUpdate pushes an update event into the buffer of the ElasticSearch accounting sink.
func (s *ElasticSink) PushUpdate(e bpf.Event) {
	// Wrap the BPF event in a structure to be inserted into the database.
	ee := event{
		Data:      &e,
		EventType: "update",
	}

	s.addBatchEvent(&ee)
}

// PushDestroy pushes a destroy event into the buffer of the ElasticSearch accounting sink.
func (s *ElasticSink) PushDestroy(e bpf.Event) {
	// Wrap the BPF event in a structure to be inserted into the database.
	ee := event{
		Data:      &e,
		EventType: "destroy",
	}

	s.addBatchEvent(&ee)
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

// WantUpdate returns true if the elastic sink is configured to accept update events.
// TODO(timo): Add this to SinkConfig.
func (s *ElasticSink) WantUpdate() bool {
	return true
}

// WantDestroy returns true if the elastic sink is configured to accept update events.
// TODO(timo): Add this to SinkConfig.
func (s *ElasticSink) WantDestroy() bool {
	return true
}

// TODO(timo): Create index mapping and roll over at midnight.
