package elasticsearch

import "github.com/ti-mo/conntracct/pkg/bpf"

// event wraps a bpf.Event in an ES-specific structure.
// This structure is used to generate the JSON document
// sent to elasticsearch.
type event struct {
	// Data of the event.
	Data *bpf.Event `json:"data"`

	// Type of event, eg. 'update' or 'destroy'.
	EventType string `json:"event_type"`
}
