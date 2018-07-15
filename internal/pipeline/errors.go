package pipeline

import "errors"

var (
	errAcctAlreadyInitialized = errors.New("accounting already initialized")
	errSinkNotInit            = errors.New("sink must be initialized before registering with pipeline")
)
