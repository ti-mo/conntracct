package boottime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	window = 10 * time.Millisecond
)

func TestEstimate(t *testing.T) {
	// Estimate the boot time.
	e := Estimate()

	// Boot time should be before now.
	assert.True(t, e.Before(time.Now()))

	// Add the current monotonic clock to the estimated boot time.
	aboutNow := e.Add(time.Duration(nanotime()))

	// Check if the timestamp is within an offset from time.Now().
	testWindow(t, aboutNow, window)
}

func TestAbsolute(t *testing.T) {
	// Convert nanotime to an absolute timestamp and assert it falls within the window.
	testWindow(t, time.Unix(0, Absolute(nanotime())), window)
}

// testWindow tests if ts falls between time.Now() plus and minus w.
func testWindow(t *testing.T, ts time.Time, w time.Duration) {

	now := time.Now()
	past := now.Add(-w)
	future := now.Add(w)

	// Timestamp should not be longer ago than the window size.
	assert.True(t, ts.After(past))
	// It should not be farther into the future than the window size.
	assert.True(t, ts.Before(future))
}
