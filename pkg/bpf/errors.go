package bpf

import "errors"

const (
	errFmtSplitKprobe = "expected string of format 'k(ret)probe/<kernel-symbol>': %s"
	errFmtSymNotFound = "kernel symbol '%s' not found"
)

var (
	errNotInRange     = errors.New("range check did not match any version")
	errProbeStarted   = errors.New("AcctProbe has already been started")
	errPerfChanClosed = errors.New("perfChan was closed, perfWorker stopping")
	errLostChanClosed = errors.New("lostChan was closed, lostWorker stopping")
	errDupConsumer    = errors.New("an AcctConsumer with the same name is already registered")
	errNoConsumer     = errors.New("could not find the AcctConsumer to delete")

	errSysctlGet = "error getting sysctl"
	errSysctlSet = "error setting sysctl"
)
