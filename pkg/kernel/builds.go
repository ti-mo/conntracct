package kernel

// Builds is a list of Kernels that can be built against.
var Builds = []Kernel{
	{
		Version: "4.9.142",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.142.tar.xz",
		Params:  params["MarkNFTNat"],
	},
	{
		Version: "4.14.85",
		URL:     "https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.14.85.tar.xz",
		Params:  params["MarkNFTNat"],
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
