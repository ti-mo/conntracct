package bpf

import "errors"

var (
	errProbeStarted    = errors.New("probe already running")
	errProbeNotStarted = errors.New("probe is not running")

	errDupConsumer = errors.New("a Consumer with the same name is already registered")
	errNoConsumer  = errors.New("could not find the Consumer to delete")

	errConsumerNil = errors.New("given Consumer is nil")
)
