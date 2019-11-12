package elasticsearch

import "errors"

var (
	errEmptySinkName = errors.New("empty sink name")
	errIndexTemplate = errors.New("index template not installed successfully")
)
