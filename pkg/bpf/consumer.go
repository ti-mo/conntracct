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

// A Consumer of accounting events.
type Consumer struct {
	name   string
	events chan Event

	// Kinds of events the consumer wants to receive. (update, destroy, all)
	mode ConsumerMode

	stats *ConsumerStats
}

// NewConsumer returns a new Consumer.
func NewConsumer(name string, events chan Event, mode ConsumerMode) *Consumer {

	if mode == 0 {
		mode = ConsumerAll
	}

	ac := Consumer{
		name:   name,
		events: events,
		mode:   mode,
		stats:  &ConsumerStats{},
	}

	return &ac
}

// Name returns the consumer's name.
func (ac *Consumer) Name() string {
	return ac.name
}

// Events returns the consumer's Event channel.
func (ac *Consumer) Events() <-chan Event {
	return ac.events
}

// Stats returns a reference to the Consumer's ConsumerStats structure.
// This structure is updated using sync/atomic. Use the ConsumerStats' Get()
// methods to obtain a copy created using atomic loads.
func (ac *Consumer) Stats() *ConsumerStats {
	return ac.stats
}

// WantUpdate returns whether or not this consumer wants to receive update events.
func (ac *Consumer) WantUpdate() bool {
	return (ac.mode & ConsumerUpdate) > 0
}

// WantDestroy returns whether or not this consumer wants to receive destroy events.
func (ac *Consumer) WantDestroy() bool {
	return (ac.mode & ConsumerDestroy) > 0
}

// RegisterConsumer registers an Consumer in an Probe.
func (ap *Probe) RegisterConsumer(ac *Consumer) error {

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

// RemoveConsumer removes an Consumer from the Probe's consumer list.
func (ap *Probe) RemoveConsumer(ac *Consumer) error {

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

			close(c.events)

			return nil
		}
	}

	return errNoConsumer
}

// GetConsumer looks up and returns an Consumer registered in an Probe
// based on its name. Returns nil if consumer does not exist in probe.
func (ap *Probe) GetConsumer(name string) *Consumer {

	ap.consumerMu.RLock()
	defer ap.consumerMu.RUnlock()

	for _, c := range ap.consumers {
		if c.name == name {
			return c
		}
	}

	return nil
}
