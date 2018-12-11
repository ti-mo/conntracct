package bpf

import "errors"

const (
	errFmtSplitKprobe = "expected string of format 'k(ret)probe/<kernel-symbol>': %s"
	errFmtSymNotFound = "kernel symbol '%s' not found"
)

var (
	errNotInRange = errors.New("range check did not match any version")
)
