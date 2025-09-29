module github.com/ti-mo/conntracct

go 1.25

replace github.com/cilium/ebpf => github.com/ti-mo/ebpf v0.0.0-20200331133758-a258b0c67078

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/cilium/ebpf v0.0.0-20200319110858-a7172c01168f
	github.com/google/nftables v0.0.0-20191115091743-3ba45f5d7848
	github.com/gorilla/mux v1.7.0
	github.com/influxdata/influxdb v1.7.4
	github.com/jsimonetti/rtnetlink v0.0.0-20191203001355-5d027701a5b7
	github.com/lorenzosaino/go-sysctl v0.1.0
	github.com/magefile/mage v1.15.0
	github.com/mdlayher/netlink v0.0.0-20191009155606-de872b0d824b
	github.com/mitchellh/go-homedir v1.1.0
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

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/influxdata/platform v0.0.0-20190117200541-d500d3cf5589 // indirect
	github.com/koneu/natend v0.0.0-20150829182554-ec0926ea948d // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.1 // indirect
	github.com/magiconair/properties v1.8.0 // indirect
	github.com/mailru/easyjson v0.0.0-20190626092158-b2ccc519800e // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.1.2 // indirect
	github.com/spf13/cast v1.3.0 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.3 // indirect
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 // indirect
	golang.org/x/net v0.0.0-20191028085509-fe3aa8a45271 // indirect
	golang.org/x/text v0.3.2 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
	gopkg.in/yaml.v2 v2.2.2 // indirect
)

tool github.com/magefile/mage
