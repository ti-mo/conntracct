package elasticsearch

import (
	"os"
	"time"

	"github.com/ti-mo/conntracct/internal/sinks/helpers"
	"github.com/ti-mo/conntracct/pkg/boottime"
	"github.com/ti-mo/conntracct/pkg/bpf"
)

// event wraps a bpf.Event in an ES-specific structure.
// This structure is used to generate the JSON document
// sent to elasticsearch.
type event struct {
	// State of the flow, eg. 'established' or 'finished'.
	State string `json:"flow_state"`

	// Hostname of the machine sending the event.
	Hostname string `json:"hostname"`

	// Embedded Event struct, to be included on
	// the root level of the marshaled json.
	*bpf.Event

	// Calculated fields.
	PacketsTotal uint64 `json:"packets_total"`
	BytesTotal   uint64 `json:"bytes_total"`
	ProtoName    string `json:"proto_name"`
}

// transformEvent applies transformations on an event before
// pushing it to elasticsearch.
func (s *ElasticSink) transformEvent(e *event) {

	// TODO(timo): Allow the user to override the hostname.
	e.Hostname, _ = os.Hostname()

	// Apply boot time offset to the (relative) event timestamp, convert to milliseconds.
	// Nanosecond-resolution unix timestamps cannot be ingested by elastic.
	// https://github.com/elastic/elasticsearch/issues/43917
	e.Timestamp = uint64(boottime.Absolute(int64(e.Timestamp)) / int64(time.Millisecond))

	// Flows' start timestamps are only generated when the kernel marks them
	// as 'CONFIRMED'. The first event will come with a zero start timestamp.
	// For elastic, use the event's timestamp as an approximate start time
	// since later events will upsert the actual start timestamp anyway.
	// Under normal conditions, this should only be a couple microseconds off.
	if e.Start == 0 {
		e.Start = e.Timestamp
	} else {
		// Convert the flow start timestamp to milliseconds.
		e.Start = e.Start / uint64(time.Millisecond)
	}

	// Calculated fields.
	e.PacketsTotal = e.PacketsOrig + e.PacketsRet
	e.BytesTotal = e.BytesOrig + e.BytesRet
	e.ProtoName = helpers.ProtoIntStr(e.Proto)
}
