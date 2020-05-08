# conntracct

Conntracct is a tool for extracting network flow information from Linux hosts,
firewalls, gateways, container or virtualization hosts, even mid- to high-end
embedded devices.

It does not capture or analyze packets in any way, but hooks into Conntrack's
accounting subsystem using eBPF with minimal overhead.

---

## Overview

Conntracct contains a metrics pipeline that supports shipping packet/byte
counters for individial network flows to backends like InfluxDB and
ElasticSearch, where they can be queried and visualized in real time.

## Compatibility

The following major distributions are supported:

- Debian
    - Stretch
    - Buster
- Ubuntu
    - Xenial (with Hardware Enablement kernel)
    - Bionic
- Fedora
- Arch Linux

The minimum required kernel version is 4.9. For distributions with rolling
releases, breakage is expected as the kernel's internal data structures evolve
over time. Please create an issue if you encounter any issues running the
project on rolling distributions.

## Roadmap

The major challenges of targeting amd64 Linux machines are mostly solved.
This is a small list of features that are planned to

- [x] Compile C-based eBPF probe against multiple kernel versions concurrently
- [x] InfluxDB sink driver for real-time flow metrics
- [x] StdOut/Err sink driver for testing and debugging
- [x] Elasticsearch sink for archival of finished flows
- [x] Automated cross-distro test runner
- [ ] Community-provided Grafana dashboards for InfluxDB and Elastic back-ends
- [ ] Prometheus endpoint for monitoring pipeline internals
- [ ] `conntracct test` subcommand to ship eBPF test suite with the binary
- [ ] ARMv7 (aarch64) support (Odroid XU3/4+, RPi 3+, etc.)
- [ ] Easy build procedure for targeting a single custom kernel
- [x] Pure-go eBPF implementation without Cgo (https://github.com/cilium/ebpf)

## Installing

Get the latest binary from Releases. Conntracct needs the following
capabilities:

When using the BPF probe for real-time accounting events:

- `cap_sys_admin` for calling bpf()
- `cap_sys_resource` for calling `setrlimit()` for ring buffer memory
- `cap_ipc_lock` for locking memory for the ring buffer (seems no longer required by newer gobpf versions)
- `cap_dac_override` for opening /sys/kernel/debug/tracing/*

When letting Conntracct manage sysctl:
- `cap_net_admin` for managing `sysctl net.netfilter.nf_conntrack_{acct,timestamp}`

## Configuring

While the configuration layout will definitely undergo changes in the near
future, up-to-date examples can always be found in
[`configs/`](https://github.com/ti-mo/conntracct/blob/master/configs/).
Viper is used for configuration, so TOML and JSON can also be used.

Default configuration search paths are (valid extensions are `yml`, `toml`, `json`):
- `$HOME/.config/conntracct.yml`
- `/etc/conntracct/conntracct.yml`

Explicitly specify a config file with the global `-c`/`--config` flag.

### iptables / nftables

In order to make sure your host track outgoing connections, `iptables` or
`nftables` need to be configured to do so. Keep in mind that all NAT'ed flows
are automatically tracked by `conntrack`, this cannot be disabled (NAT relies
on it). For example, if you're running Docker on your machine, traffic to and
from your containers will likely already be tracked, depending on your network
configuration.

Track all outgoing IPv4 and IPv6 connections with:
```
sudo ip6tables -t filter -A OUTPUT -m conntrack --ctstate related,established -j ACCEPT
sudo iptables -t filter -A OUTPUT -m conntrack --ctstate related,established -j ACCEPT
```

## Building

Conntracct uses [Mage](https://magefile.org) for building.

`mage build`

All BPF probes are pre-built using Clang 7.0 and are bundled using `statik`.
This means the binary can be built from source with just the Go toolchain,
and all probes are available to be used by just importing the `pkg/bpf`
package, even from other projects.

### Building BPF probes

All bpf-related tasks are in their own `bpf:` Mage namespace.

`mage bpf:build`

This will fetch, extract and configure all versions of Linux targeted by
the build package to build probes against. This is performed in isolation in
`$HOME/.cache/conntracct` and will not touch your installed OS kernel.

## Developing

Conntracct comes with a Docker-based development environment, available using

`mage dev`

This will launch a docker-compose stack, build the binary and run `modd` for
live reloading on save.

`go get github.com/cortesi/modd/cmd/modd`

## Acknowledgements

This project would not have been possible without WeaveWorks'
[tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf). While I didn't
take the approach of offset scanning, the ideas around packaging bytecode into
the package with `statik` and the overall implementation of the tracer program
were instrumental as an example for this project. Thanks, guys!

## Getting Involved

As always, pull requests and feedback are greatly appreciated.
Don't hesitate to get in touch through any of the following channels:

- #networking on Gophers Slack
- File [an issue](https://github.com/ti-mo/conntracct/issues/new)
- [E-mail me](mailto:timo@incline.eu) if you'd like to sponsor a new feature
