package kernel

// Builds is a list of Kernels that can be built against. We try to stick to one version
// per minor release. (eg 4.9.x)
//
// Whenever a breaking change is made to any of the structures the bpf program references,
// this map needs to be updated with the version it's introduced in.
var Builds = map[string]Kernel{
	// 4.9 used by Debian Stretch.
	"4.9.0": {
		Version: "4.9.0",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
	// `nat_bysource` in struct nf_conn was changed from a struct rhlist_head
	// to a struct hlist_node.
	"4.9.63": {
		Version: "4.9.63",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.63.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
	// 4.17 saw a breaking change in netns struct layout. Not a long-term kernel.
	"4.17.0": {
		Version: "4.17.9",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.17.9.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
	// In 5.3, `u16 cpu` and `u32 timeout` got swapped in struct nf_conn.
	"5.3.0": {
		Version: "5.3.14",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.3.14.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
	// In 5.5.0, `struct rcu_head rcu` was removed from `struct nf_ct_ext`.
	"5.5.0": {
		Version: "5.5.10",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.5.10.tar.xz",
		Params:  params["MarkNFTNat"],
		Probes:  kprobes["acct_v1"],
	},
}

var params = map[string]Params{
	"MarkNFTNat": {
		"CONFIG_NETFILTER":          "y",
		"CONFIG_NETFILTER_ADVANCED": "y",

		"CONFIG_NF_CONNTRACK":      "m",
		"CONFIG_NF_CONNTRACK_MARK": "y",

		// Changes alignment of the ct extensions enum for timestamp.
		"CONFIG_NF_NAT":                 "m",
		"CONFIG_NF_CONNTRACK_EVENTS":    "y",
		"CONFIG_NF_CONNTRACK_TIMESTAMP": "y",

		"CONFIG_NF_TABLES": "m",
		"CONFIG_NFT_NAT":   "m",

		// Disabling SMP makes some structs smaller by removing some
		// synchronization primitives.
		"CONFIG_SMP": "y",
	},
}

var kprobes = map[string]Probes{
	// These probes are enabled in the sequence listed here.
	// List functions that insert records into a map last to prevent stale records in BPF maps.
	"acct_v1": {
		{
			Kind: "kprobe",
			Name: "destroy_conntrack",
		},
		{
			Kind: "kretprobe",
			Name: "__nf_ct_refresh_acct",
		},
		{
			Kind: "kprobe",
			Name: "__nf_ct_refresh_acct",
		},
		{
			Kind: "kprobe",
			Name: "__nf_conntrack_hash_insert",
		},
	},
}
