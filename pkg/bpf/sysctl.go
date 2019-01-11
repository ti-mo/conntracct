package bpf

import "gitlab.com/0ptr/conntracct/internal/sysctl"

// Sysctls applies a list of sysctls on the machine.
// When verbose is true, logs any changes made to stdout.
func Sysctls(verbose bool) error {

	sysctls := map[string]string{
		"net.netfilter.nf_conntrack_acct": "1",
	}

	return sysctl.Apply(sysctls, verbose)
}
