package influxdb

import "errors"

var (
	errSinkName = errors.New("sink name is empty")
	errSinkMode = errors.New("sink mode is zero")
)
