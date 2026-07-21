package bpf

import "sync/atomic"

// ProbeStats holds various statistics and information about the BPF probe.
type ProbeStats struct {
	// total amount of events received from kernel
	RingbufEventsTotal uint64 `json:"ringbuf_events_total"`
	// total amount of bytes read from the BPF ring buffer
	RingbufBytesTotal uint64 `json:"ringbuf_bytes_total"`
}

func (s *ProbeStats) incrRingbufEventsTotal() {
	atomic.AddUint64(&s.RingbufEventsTotal, 1)
	atomic.AddUint64(&s.RingbufBytesTotal, uint64(eventLength))
}

// Get returns a copy of the Stats structure created using atomic loads.
// The values can be inconsistent with each other, as they are written and
// read concurrently without locks.
func (s *ProbeStats) Get() ProbeStats {
	return ProbeStats{
		RingbufEventsTotal: atomic.LoadUint64(&s.RingbufEventsTotal),
		RingbufBytesTotal:  atomic.LoadUint64(&s.RingbufBytesTotal),
	}
}
