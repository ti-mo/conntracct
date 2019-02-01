package config

import "github.com/ti-mo/conntracct/pkg/bpf"

// Init sets up the host to make conntracct function correctly.
func Init() error {
	return bpf.Sysctls(true)
}
