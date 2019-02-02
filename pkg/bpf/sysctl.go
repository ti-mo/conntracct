package bpf

import "github.com/ti-mo/conntracct/internal/sysctl"

// Sysctls applies a list of sysctls on the machine.
// When verbose is true, logs any changes made to stdout.
func Sysctls(verbose bool) error {

	sysctls := map[string]string{

		// Enable the accounting subsystem of the conntrack
		// kernel module.
		"net.netfilter.nf_conntrack_acct": "1",

		// Enable timestamps of flow start in events.
		// This is required for calculating the total
		// flow time.
		"net.netfilter.nf_conntrack_timestamp": "1",
	}

	return sysctl.Apply(sysctls, verbose)
}
