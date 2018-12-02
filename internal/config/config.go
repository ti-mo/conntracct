package config

// Init sets up the host to make conntracct function:
// - apply sysctls
// - ...
func Init() error {

	sysctls := map[string]string{
		"net.netfilter.nf_conntrack_acct": "1",
	}

	if err := applySysctl(sysctls); err != nil {
		return err
	}

	return nil
}
