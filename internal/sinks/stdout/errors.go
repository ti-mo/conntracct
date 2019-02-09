package stdout

import "errors"

var (
	errEmptySinkName   = errors.New("empty sink name")
	errInvalidSinkType = errors.New("invalid sink type")
)
