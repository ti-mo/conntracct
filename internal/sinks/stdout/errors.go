package stdout

import "errors"

var (
	errEmptySinkName    = errors.New("empty sink name")
	errEmptySinkAddress = errors.New("empty sink address")
	errInvalidSinkType  = errors.New("invalid sink type")
)
