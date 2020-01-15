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
	// Type of event, eg. 'update' or 'destroy'.
	EventType string `json:"event_type"`

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

	// Convert the flow start timestamp to milliseconds.
	// Nanosecond-resolution unix timestamps cannot be ingested by elastic.
	// https://github.com/elastic/elasticsearch/issues/43917
	e.Start = e.Start / uint64(time.Millisecond)

	// Apply boot time offset to the (relative) event timestamp, convert to milliseconds.
	e.Timestamp = uint64(boottime.Absolute(int64(e.Timestamp)) / int64(time.Millisecond))

	// Calculated fields.
	e.PacketsTotal = e.PacketsOrig + e.PacketsRet
	e.BytesTotal = e.BytesOrig + e.BytesRet
	e.ProtoName = helpers.ProtoIntStr(e.Proto)
}
