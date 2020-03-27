module github.com/ti-mo/conntracct

go 1.12

replace github.com/cilium/ebpf => github.com/ti-mo/ebpf v0.0.0-20200331133758-a258b0c67078

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/cilium/ebpf v0.0.0-20200319110858-a7172c01168f
	github.com/google/nftables v0.0.0-20191115091743-3ba45f5d7848
	github.com/gorilla/mux v1.7.0
	github.com/influxdata/influxdb v1.7.4
	github.com/influxdata/platform v0.0.0-20190117200541-d500d3cf5589 // indirect
	github.com/jsimonetti/rtnetlink v0.0.0-20191203001355-5d027701a5b7
	github.com/lorenzosaino/go-sysctl v0.1.0
	github.com/magefile/mage v1.8.0
	github.com/mdlayher/netlink v0.0.0-20191009155606-de872b0d824b
	github.com/mitchellh/go-homedir v1.0.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/olivere/elastic/v7 v7.0.9
	github.com/pkg/errors v0.8.1
	github.com/rakyll/statik v0.1.6
	github.com/sirupsen/logrus v1.4.0
	github.com/spf13/cobra v0.0.3
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.2.2
	github.com/ti-mo/kconfig v0.0.0-20181208153747-0708bf82969f
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df
	golang.org/x/sync v0.0.0-20190227155943-e225da77a7e6
	golang.org/x/sys v0.0.0-20200124204421-9fbb57f87de9
	lukechampine.com/blake3 v0.4.0
)
