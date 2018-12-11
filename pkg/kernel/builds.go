package kernel

// Builds is a list of Kernels that can be built against.
var Builds = map[string]Kernel{
	"4.9.142": Kernel{
		Version: "4.9.142",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.142.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
	"4.14.85": {
		Version: "4.14.85",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.85.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
}

var params = map[string]Params{
	"MarkNFTNat": Params{
		"CONFIG_NETFILTER":          "y",
		"CONFIG_NETFILTER_ADVANCED": "y",

		"CONFIG_NF_CONNTRACK":      "m",
		"CONFIG_NF_CONNTRACK_MARK": "y",

		"CONFIG_NF_NAT":    "m",
		"CONFIG_NF_TABLES": "m",
		"CONFIG_NFT_NAT":   "m",
	},
}

var kprobes = map[string]Probes{
	// These probes are enabled in the sequence listed here.
	// List functions that insert records into a map last to prevent stale records in BPF maps.
	"acct_v1": Probes{
		"kprobe/nf_conntrack_free",
		"kretprobe/__nf_ct_refresh_acct",
		"kprobe/__nf_ct_refresh_acct",
	},
}
