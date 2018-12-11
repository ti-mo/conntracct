package bpf

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// KernelRelease returns the release name of the running kernel.
func KernelRelease() (string, error) {

	uname := unix.Utsname{}
	if err := unix.Uname(&uname); err != nil {
		return "", err
	}

	// Convert [65]byte to a string.
	release := string(uname.Release[:bytes.IndexByte(uname.Release[:], 0)])

	return release, nil
}
