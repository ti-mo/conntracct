package influxdb

import "errors"

var (
	errEmptySinkName     = errors.New("empty sink name")
	errEmptySinkAddress  = errors.New("empty sink address")
	errEmptySinkDatabase = errors.New("sink requires a database name")
	errInvalidSinkType   = errors.New("invalid sink type")
)
