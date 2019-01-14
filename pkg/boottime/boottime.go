package boottime

import (
	"runtime"
	"time"
	_ "unsafe" // required for go:linkname
)

// Amount of times to call nanotime() + time.Now().
const rounds = 15

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
// and time.Now() as close to each other as possible, and substracts
// the nanotime from the time.Now() value. Each round, the result is
// 'voted' on, to increase the confidence in the origin timestamp.
func Estimate() time.Time {

	t := make(map[time.Time]uint8)

	// Lock the goroutine to an OS thread so it doesn't
	// get de-scheduled. We want the nanotime() and time.Now()
	// calls to occur as close to each other as possible.
	runtime.LockOSThread()
	for i := 0; i < rounds; i++ {
		ns := nanotime()
		now := time.Now()
		bootTime := now.Add(-time.Duration(ns))
		t[bootTime]++ // vote on the obtained bootTime
	}
	runtime.UnlockOSThread()

	var out time.Time
	var max uint8

	// Find the most voted-on Time entry in the map.
	for ts, n := range t {
		if n > max {
			out = ts
			max = n
		}
	}

	return out
}
