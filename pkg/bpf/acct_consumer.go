package bpf

// An AcctConsumer is a consumer of accounting events.
type AcctConsumer struct {
	name string

	events chan AcctEvent
	lost   uint64
}

// Close closes the AcctConsumer's event channel.
func (ac *AcctConsumer) Close() {
	close(ac.events)
}

// NewAcctConsumer returns a new AcctConsumer.
func NewAcctConsumer(name string, events chan AcctEvent) *AcctConsumer {

	ac := AcctConsumer{
		name:   name,
		events: events,
	}

	return &ac
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
