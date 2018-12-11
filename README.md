# conntracct

Low-overhead, real-time network flow exporter based on conntrack, without packet captures.

---

## Installing

Get the latest binary from Releases. Conntracct does not need to run as root,
but it needs the following capabilities:

When using the BPF probe for real-time accounting events:

- `cap_sys_admin` for calling bpf()
- `cap_ipc_lock` for locking memory for the ring buffer
- `cap_dac_override` for opening /sys/kernel/debug/tracing/*

When letting Conntracct manage sysctl:
- `cap_net_admin` for managing `sysctl net.netfilter.nf_conntrack_acct`

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
`/tmp/conntrack/kernels` and will not touch your installed OS kernel.

## Developing

Conntracct comes with a Docker-based development environment, available using

`mage dev`

This will launch a docker-compose stack, build the binary and run `modd` for
live reloading on save.

`go get github.com/cortesi/modd/cmd/modd`
