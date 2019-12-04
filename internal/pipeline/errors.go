package pipeline

import "errors"

var (
	errAcctNotInitialized = errors.New("accounting not yet initialized")
	errSinkNotInit        = errors.New("sink must be initialized before registering with pipeline")
	errProbeConfig        = errors.New("received nil probe configuration")
)
