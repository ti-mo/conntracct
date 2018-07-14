package apiserver

import "errors"

var (
	errNotInit = errors.New("apiserver package not initialized, call Init() first")
	errNoPipe  = errors.New("ceci n'est pas une pipe")
)
