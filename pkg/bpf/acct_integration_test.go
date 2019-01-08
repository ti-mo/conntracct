// +build integration

package bpf

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var acctProbe *AcctProbe

func TestMain(m *testing.M) {

	var err error

	cfg := AcctConfig{
		CooldownMillis: 20, // One update every 20 milliseconds after startup burst.
	}

	// Create and start the AcctProbe.
	acctProbe, err = NewAcctProbe(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := acctProbe.Start(); err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func TestAcctProbe(t *testing.T) {

	// Create and register consumer.
	in, out := make(chan AcctEvent, 2048), make(chan AcctEvent)
	ac := NewAcctConsumer(t.Name(), in)
	require.NoError(t, acctProbe.RegisterConsumer(ac))

	// Create UDP client.

	stop := make(chan bool)
	go filterSrcPort(in, out, stop, 25376)

	// Validation logic.

	stop <- true
}

// filterSrcPort is a filter worker that filters an AcctEvent chan based on the
// source port of its events.
func filterSrcPort(in, out chan AcctEvent, stop chan bool, srcPort uint16) {
	for {
		select {
		case ev := <-in:
			// Filter messages based on the given source port.
			if ev.SrcPort == srcPort {
				out <- ev
			}
		case <-stop:
			close(in)
			close(out)
			break
		}
	}
}
