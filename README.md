# conntracct

Conntracct is a tool for extracting network flow information from Linux hosts,
firewalls, gateways, container or virtualization hosts, even mid- to high-end
embedded devices.

It does not capture or analyze packets in any way, but hooks into Conntrack's
accounting subsystem using eBPF with minimal overhead.

---

## Overview

Conntracct  metrics pipeline that supports shipping packet/byte
counters for individial network flows to backends like InfluxDB and
ElasticSearch, where they can be queried and visualized in real time.

## Compatibility

Linux v5.5 or later with a BTF-enabled kernel should work.

## Installing

Get the latest binary from
[Releases](https://github.com/ti-mo/conntracct/releases). Conntracct needs the
following capabilities:

- `cap_sys_admin` for attaching to kernel symbols
- `cap_net_admin` for managing sysctl `net.netfilter.nf_conntrack_{acct,timestamp}`

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

Conntracct uses [Task](https://taskfile.dev) for building.

Run `go tool task` to display all available tasks.

## Developing

Conntracct comes with a [vai](https://github.com/sgtdi/vai) configuration for
fast and easy local iteration.

Run `go tool vai` to build the binary, lint, run the tests, and run the app in
hot-reload mode.

## Acknowledgements

This project would not have been possible without WeaveWorks'
[tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf). While this is now
commonplace with tools like bpf2go, the ideas around packaging bytecode into the
package with `statik` and the overall implementation of the tracer program were
instrumental as an example for this project at the time. Thank you and so long,
WeaveWorks!

## Getting Involved

As always, pull requests and feedback are greatly appreciated.
Don't hesitate to get in touch through any of the following channels:

- #networking on Gophers Slack
- File [an issue](https://github.com/ti-mo/conntracct/issues/new)
- [E-mail me](mailto:timo@incline.eu) if you'd like to sponsor a new feature
