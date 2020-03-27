package stdout

import (
	"bufio"
	"os"

	"github.com/ti-mo/conntracct/pkg/bpf"

	"github.com/ti-mo/conntracct/internal/config"
	"github.com/ti-mo/conntracct/internal/sinks/types"
)

// StdOut is an accounting sink writing to standard output/error.
type StdOut struct {

	// Sink had Init() called on it successfully.
	init bool

	// Sink's configuration object.
	config config.SinkConfig

	// Sink stats.
	stats types.SinkStats

	// Buffered event channels. BatchLength configuration parameter
	// is used as the buffer sizes of these channels.
	updates  chan bpf.Event
	destroys chan bpf.Event

	// Stdout/err writer.
	writer *bufio.Writer
}

// New returns a new StdOut.
func New() StdOut {
	return StdOut{}
}

// Init initializes the StdOut sink.
func (s *StdOut) Init(sc config.SinkConfig) error {

	// Validate / sanitize input.
	if sc.Name == "" {
		return errEmptySinkName
	}
	if sc.BatchSize == 0 {
		sc.BatchSize = 2048
	}

	switch sc.Type {
	case types.StdOut:
		// Initialize stdout writer.
		s.writer = bufio.NewWriter(os.Stdout)
	case types.StdErr:
		// Initialize stderr writer.
		s.writer = bufio.NewWriter(os.Stderr)
	default:
		return errInvalidSinkType
	}

	s.updates = make(chan bpf.Event, sc.BatchSize)
	s.destroys = make(chan bpf.Event, sc.BatchSize)
	s.config = sc

	go s.outWorker()

	// Mark the sink as initialized.
	s.init = true

	return nil
}

// PushUpdate pushes an update event into the buffer of the StdOut accounting sink.
func (s *StdOut) PushUpdate(e bpf.Event) {
	// Non-blocking send on event channel.
	select {
	case s.updates <- e:
		s.stats.IncrUpdateEventsPushed()
	default:
		s.stats.IncrUpdateEventsDropped()
	}
}

// PushDestroy pushes a destroy event into the buffer of the StdOut accounting sink.
func (s *StdOut) PushDestroy(e bpf.Event) {
	// Non-blocking send on event channel.
	select {
	case s.destroys <- e:
		s.stats.IncrDestroyEventsPushed()
	default:
		s.stats.IncrDestroyEventsDropped()
	}
}

// Name gets the name of the StdOut.
func (s *StdOut) Name() string {
	return s.config.Name
}

// IsInit checks if the StdOut was successfully initialized.
func (s *StdOut) IsInit() bool {
	return s.init
}

// WantUpdate always returns true.
func (s *StdOut) WantUpdate() bool {
	return true
}

// WantDestroy always returns true, StdOut receives destroy events. (flow totals)
func (s *StdOut) WantDestroy() bool {
	return true
}

// Stats returns the StdOut's statistics structure.
func (s *StdOut) Stats() types.SinkStats {
	return s.stats.Get()
}
