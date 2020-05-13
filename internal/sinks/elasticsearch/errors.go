package elasticsearch

import "errors"

var (
	errEmptySinkName = errors.New("empty sink name")
	errIndexTemplate = errors.New("error installing index template")
	errScript        = errors.New("error installing stored script")
)
