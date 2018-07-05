#include <linux/kconfig.h>
#include "bpf_helpers.h"

#define KBUILD_MODNAME "empty" // Required for including printk.h
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>

struct acct_event_t {
  u32 cid;
  u64 ts;
  u64 packets_orig;
  u64 bytes_orig;
  u64 packets_ret;
  u64 bytes_ret;
  union nf_inet_addr srcaddr;
  union nf_inet_addr dstaddr;
};

struct bpf_map_def SEC("maps/acct_events") acct_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/lastupd") lastupd = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/currct") currct = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};


SEC("kprobe/__nf_ct_refresh_acct")
int kprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  u32 pid = bpf_get_current_pid_tgid();

	// stash the conntrack pointer for lookup on return
	bpf_map_update_elem(&currct, &pid, &ct, BPF_ANY);

	return 0;
}

SEC("kretprobe/__nf_ct_refresh_acct")
int kretprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  u32 pid = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();

  // Look up the conntrack structure stashed by the kprobe
  struct nf_conn **ctp;
  ctp = bpf_map_lookup_elem(&currct, &pid);

	if (ctp == 0)
		return 0;

  // Dereference and delete from the stash table
  struct nf_conn *ct = *ctp;
  bpf_map_delete_elem(&currct, &pid);

  // Check if accounting extension is enabled and
  // initialized for this connection. Important because
  // acct codepath is called for unix socket usage as well.
  // Also, the acct extension memory is uninitialized if the acct
  // sysctl is disabled.
  struct nf_ct_ext *ct_ext;
  bpf_probe_read(&ct_ext, sizeof(ct_ext), &ct->ext);
  if (!ct_ext)
    return 0;

  u8 ct_acct_offset;
  bpf_probe_read(&ct_acct_offset, sizeof(ct_acct_offset), &ct_ext->offset[NF_CT_EXT_ACCT]);
  if (!ct_acct_offset)
    return 0;

  struct acct_event_t data = {
    .cid = (u32)ct,
    .ts = ts,
  };

  u64 *last;
  last = bpf_map_lookup_elem(&lastupd, &ct);

  if (!!last && (data.ts - *last) < (1 * 1000000000))
    return 0;

  // Obtain reference to accounting conntrack extension
  struct nf_conn_acct *acct_ext = ((void *)ct_ext + ct_acct_offset);
  if (!acct_ext)
    return 0;

  struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
  struct nf_conn_counter ctr[IP_CT_DIR_MAX];

  bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);
  bpf_probe_read(&ctr, sizeof(ctr), &acct_ext->counter);

  data.srcaddr = tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
  data.dstaddr = tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;

  data.packets_orig = ctr[IP_CT_DIR_ORIGINAL].packets.counter;
  data.bytes_orig = ctr[IP_CT_DIR_ORIGINAL].bytes.counter;

  data.packets_ret = ctr[IP_CT_DIR_REPLY].packets.counter;
  data.bytes_ret = ctr[IP_CT_DIR_REPLY].bytes.counter;

  // Submit event to userspace
  bpf_perf_event_output(ctx, &acct_events, CUR_CPU_IDENTIFIER, &data, sizeof(data));

  // Save last timestamp we posted the conntrack
  bpf_map_update_elem(&lastupd, &ct, &data.ts, BPF_ANY);

  return 0;
}

SEC("kprobe/nf_conntrack_free")
int kprobe__nf_conntrack_free(struct pt_regs *ctx) {

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

  // Remove last-updated entry for connection
  bpf_map_delete_elem(&lastupd, &ct);

  return 0;
}

char _license[] SEC("license") = "GPL";

// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;
