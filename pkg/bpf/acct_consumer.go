package bpf

// ConsumerMode defines whether the consumer
// receives updates, destroys, or both.
type ConsumerMode uint8

// Kind of events the consumer subscribes to.
const (
	ConsumerUpdate  ConsumerMode = 1
	ConsumerDestroy ConsumerMode = 2
	ConsumerAll     ConsumerMode = (ConsumerUpdate | ConsumerDestroy)
)

// An AcctConsumer is a consumer of accounting events.
type AcctConsumer struct {
	name string

	events chan AcctEvent
	lost   uint64

	mode ConsumerMode // bitfield for which events to subscribe to
}

// NewAcctConsumer returns a new AcctConsumer.
func NewAcctConsumer(name string, events chan AcctEvent, mode ConsumerMode) *AcctConsumer {

	if mode == 0 {
		mode = ConsumerAll
	}

	ac := AcctConsumer{
		name:   name,
		events: events,
		mode:   mode,
	}

	return &ac
}

// WantUpdate returns whether or not this consumer wants to receive update events.
func (ac *AcctConsumer) WantUpdate() bool {
	return (ac.mode & ConsumerUpdate) > 0
}

// WantDestroy returns whether or not this consumer wants to receive destroy events.
func (ac *AcctConsumer) WantDestroy() bool {
	return (ac.mode & ConsumerDestroy) > 0
}

// Close closes the AcctConsumer's event channel.
func (ac *AcctConsumer) Close() {
	close(ac.events)
}

// RegisterConsumer registers an AcctConsumer in an AcctProbe.
func (ap *AcctProbe) RegisterConsumer(ac *AcctConsumer) error {

	if ac == nil {
		return errConsumerNil
	}

	ap.consumerMu.Lock()
	defer ap.consumerMu.Unlock()

	for _, c := range ap.consumers {
		if c.name == ac.name {
			return errDupConsumer
		}
	}

	// Append the consumer to the probe's list of consumers.
	ap.consumers = append(ap.consumers, ac)

	return nil
}

// RemoveConsumer removes an AcctConsumer from the AcctProbe's consumer list.
func (ap *AcctProbe) RemoveConsumer(ac *AcctConsumer) error {

	if ac == nil {
		return errConsumerNil
	}

	ap.consumerMu.Lock()
	defer ap.consumerMu.Unlock()

	for i, c := range ap.consumers {
		if c.name == ac.name {
			// From https://github.com/golang/go/wiki/SliceTricks
			// Avoid memory leaks since we're dealing with a slice of pointers.

			// Swap the last element of the slice into the element we want to delete.
			ap.consumers[i] = ap.consumers[len(ap.consumers)-1]
			// Zero the last element of the slice.
			ap.consumers[len(ap.consumers)-1] = nil
			// Shrink the slice by one element.
			ap.consumers = ap.consumers[:len(ap.consumers)-1]

			return nil
		}
	}

	return errNoConsumer
}

// GetConsumer looks up and returns an AcctConsumer registered in an AcctProbe
// based on its name. Returns nil if consumer does not exist in probe.
func (ap *AcctProbe) GetConsumer(name string) *AcctConsumer {

	ap.consumerMu.RLock()
	defer ap.consumerMu.RUnlock()

	for _, c := range ap.consumers {
		if c.name == name {
			return c
		}
	}

	return nil
}
