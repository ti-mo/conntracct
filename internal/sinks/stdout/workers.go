package stdout

import (
	log "github.com/sirupsen/logrus"

	"github.com/ti-mo/conntracct/pkg/bpf"
)

// outWorker receives events from the sink's event channel
// and prints them to stdout/stderr.
func (s *StdOut) outWorker() {

	for {
		var e bpf.Event

		select {
		case e = <-s.updates:
			_, _ = s.writer.WriteString("Update: ")
		case e = <-s.destroys:
			_, _ = s.writer.WriteString("Destroy: ")
		}

		if _, err := s.writer.WriteString(e.String() + "\n"); err != nil {
			s.stats.IncrBatchDropped()
			log.Errorf("StdOut sink '%s': error writing: %s", s.config.Name, err)
			continue
		}

		if err := s.writer.Flush(); err != nil {
			s.stats.IncrBatchDropped()
			log.Errorf("StdOut sink '%s': error flushing writer: %s", s.config.Name, err)
			continue
		}

		// Increase 'batches' sent counter.
		s.stats.IncrBatchSent()
	}
}
