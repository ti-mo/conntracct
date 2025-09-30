package bpf

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-I /usr/src/linux/include" acct ../../bpf/acct.c
