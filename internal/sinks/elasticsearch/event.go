package elasticsearch

import "github.com/ti-mo/conntracct/pkg/bpf"

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
}
