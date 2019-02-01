package config

import "gitlab.com/0ptr/conntracct/pkg/bpf"

// Init sets up the host to make conntracct function correctly.
func Init() error {
	return bpf.Sysctls(true)
}
