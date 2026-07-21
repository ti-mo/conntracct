package dummy

import (
	"github.com/ti-mo/conntracct/pkg/bpf"

	"github.com/ti-mo/conntracct/internal/config"
	"github.com/ti-mo/conntracct/internal/sinks/types"
)

// Dummy is an accounting sink that does nothing. At all.
type Dummy struct {

	// Sink had Init() called on it successfully.
	init bool

	// Sink's configuration object.
	config config.SinkConfig

	stats types.SinkStats
}

// New returns a new Dummy.
func New() Dummy {
	return Dummy{}
}

// Init initializes the Dummy sink.
func (d *Dummy) Init(sc config.SinkConfig) error {
	d.config = sc
	d.init = true
	return nil
}

// Push sends an event into the abyss.
func (d *Dummy) Push(e bpf.Event) {
	if e.Type == bpf.Destroy {
		d.stats.IncrDestroyEventsPushed()
		d.stats.IncrDestroyEventsDropped()
		return
	}
	d.stats.IncrUpdateEventsPushed()
	d.stats.IncrUpdateEventsDropped()
}

// Name gets the name of the Dummy.
func (d *Dummy) Name() string {
	return d.config.Name
}

// IsInit checks if the Dummy was successfully initialized.
func (d *Dummy) IsInit() bool {
	return d.init
}

// WantNew always returns true.
func (d *Dummy) WantNew() bool {
	return true
}

// WantUpdate always returns true.
func (d *Dummy) WantUpdate() bool {
	return true
}

// WantDestroy always returns true, Dummy receives destroy events. (flow totals)
func (d *Dummy) WantDestroy() bool {
	return true
}

// Stats returns the Dummy's statistics structure.
func (d *Dummy) Stats() types.SinkStats {
	return d.stats.Get()
}
