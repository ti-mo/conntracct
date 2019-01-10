package config

import "gitlab.com/0ptr/conntracct/pkg/bpf"

// Init sets up the host to make conntracct function correctly.
func Init() error {

	if err := bpf.Sysctls(true); err != nil {
		return err
	}

	return nil
}
