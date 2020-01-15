package boottime

import (
	"runtime"
	"sync/atomic"
	"time"
	_ "unsafe" // required for go:linkname
)

const (
	// Amount of times to call nanotime() + time.Now().
	rounds = 10

	// Seconds between polling cycles.
	interval = 2
)

var nanos int64

func init() {
	// Ensure a valid timestamp has been estimated on init.
	storeNanos(estimate())

	// Start the background worker.
	go worker()
}

//go:noescape
//go:linkname nanotime runtime.nanotime
// https://github.com/golang/go/issues/24595
func nanotime() int64

// Estimate attempts to estimate the absolute genesis time stamp
// of the system's monotonic clock with a nanosecond resolution. This time
// stamp can be used as an offset to calculate absolute time stamps of kernel
// events when only the monotonic clock (ktime) is known.
//
// Performs multiple rounds of direct calls to runtime.nanotime()
// and time.Now() as close to each other as possible, and subtracts
// the nanotime from the time.Now() value. Each round, the result is
// 'voted' on, to increase the confidence in the origin timestamp.
func Estimate() time.Time {
	return time.Unix(0, estimate())
}

// Absolute converts a relative nanosecond-resolution timestamp t to
// an absolute timestamp. An example of a relative timestamp is a timestamp
// obtained from eBPF's ktime_get_ns.
func Absolute(t int64) int64 {
	return getNanos() + t
}

// estimate spawns a locked OS thread to call nanotime() and time.Now()
// in a tight loop. On each sample, the nanotime is subtracted from the absolute
// timestamp, and the resulting value is voted on.
func estimate() int64 {
	t := make(map[int64]uint8)
	var b int64

	// Lock the goroutine to an OS thread so it doesn't
	// get de-scheduled. We want the nanotime() and time.Now()
	// calls to occur as close to each other as possible.
	runtime.LockOSThread()
	for i := 0; i < rounds; i++ {

		// Get relative and absolute timestamps.
		ns := nanotime()
		now := time.Now()

		// Approximate the boot time.
		b = now.Add(-time.Duration(ns)).UnixNano()

		// Vote on the obtained boot time.
		t[b]++
	}
	runtime.UnlockOSThread()

	var out int64
	var max uint8

	// Find the most voted-on Time entry in the map.
	for ts, n := range t {
		if n > max {
			// Bump the maximum result.
			max = n
			// Hold on to the key.
			out = ts
		}
	}

	return out
}

// storeNanos atomically stores t in the package-global timestamp.
func storeNanos(t int64) {
	atomic.StoreInt64(&nanos, t)
}

// getNanos atomically loads the package-global timestamp.
func getNanos() int64 {
	return atomic.LoadInt64(&nanos)
}

// worker updates the package-global timestamp every interval seconds.
func worker() {
	t := time.NewTicker(interval * time.Second)
	defer t.Stop()

	for {
		<-t.C
		storeNanos(estimate())
	}
}
