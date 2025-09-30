/* This is auto-generated file. See bpf_doc.py for details. */

#ifndef __bpf_fastcall
#if __has_attribute(bpf_fastcall)
#define __bpf_fastcall __attribute__((bpf_fastcall))
#else
#define __bpf_fastcall
#endif
#endif

/*
 * bpf_map_lookup_elem
 *
 * 	Perform a lookup in *map* for an entry associated to *key*.
 *
 * Returns
 * 	Map value associated to *key*, or **NULL** if no entry was
 * 	found.
 */
static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/*
 * bpf_map_update_elem
 *
 * 	Add or update the value of the entry associated to *key* in
 * 	*map* with *value*. *flags* is one of:
 *
 * 	**BPF_NOEXIST**
 * 		The entry for *key* must not exist in the map.
 * 	**BPF_EXIST**
 * 		The entry for *key* must already exist in the map.
 * 	**BPF_ANY**
 * 		No condition on the existence of the entry for *key*.
 *
 * 	Flag value **BPF_NOEXIST** cannot be used for maps of types
 * 	**BPF_MAP_TYPE_ARRAY** or **BPF_MAP_TYPE_PERCPU_ARRAY**  (all
 * 	elements always exist), the helper would return an error.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (* const bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;

/*
 * bpf_map_delete_elem
 *
 * 	Delete entry with *key* from *map*.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (* const bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

/*
 * bpf_probe_read
 *
 * 	For tracing programs, safely attempt to read *size* bytes from
 * 	kernel space address *unsafe_ptr* and store the data in *dst*.
 *
 * 	Generally, use **bpf_probe_read_user**\ () or
 * 	**bpf_probe_read_kernel**\ () instead.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (* const bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;

/*
 * bpf_ktime_get_ns
 *
 * 	Return the time elapsed since system boot, in nanoseconds.
 * 	Does not include time the system was suspended.
 * 	See: **clock_gettime**\ (**CLOCK_MONOTONIC**)
 *
 * Returns
 * 	Current *ktime*.
 */
static __u64 (* const bpf_ktime_get_ns)(void) = (void *) 5;

/*
 * bpf_trace_printk
 *
 * 	This helper is a "printk()-like" facility for debugging. It
 * 	prints a message defined by format *fmt* (of size *fmt_size*)
 * 	to file *\/sys/kernel/tracing/trace* from TraceFS, if
 * 	available. It can take up to three additional **u64**
 * 	arguments (as an eBPF helpers, the total number of arguments is
 * 	limited to five).
 *
 * 	Each time the helper is called, it appends a line to the trace.
 * 	Lines are discarded while *\/sys/kernel/tracing/trace* is
 * 	open, use *\/sys/kernel/tracing/trace_pipe* to avoid this.
 * 	The format of the trace is customizable, and the exact output
 * 	one will get depends on the options set in
 * 	*\/sys/kernel/tracing/trace_options* (see also the
 * 	*README* file under the same directory). However, it usually
 * 	defaults to something like:
 *
 * 	::
 *
 * 		telnet-470   [001] .N.. 419421.045894: 0x00000001: <formatted msg>
 *
 * 	In the above:
 *
 * 		* ``telnet`` is the name of the current task.
 * 		* ``470`` is the PID of the current task.
 * 		* ``001`` is the CPU number on which the task is
 * 		  running.
 * 		* In ``.N..``, each character refers to a set of
 * 		  options (whether irqs are enabled, scheduling
 * 		  options, whether hard/softirqs are running, level of
 * 		  preempt_disabled respectively). **N** means that
 * 		  **TIF_NEED_RESCHED** and **PREEMPT_NEED_RESCHED**
 * 		  are set.
 * 		* ``419421.045894`` is a timestamp.
 * 		* ``0x00000001`` is a fake value used by BPF for the
 * 		  instruction pointer register.
 * 		* ``<formatted msg>`` is the message formatted with
 * 		  *fmt*.
 *
 * 	The conversion specifiers supported by *fmt* are similar, but
 * 	more limited than for printk(). They are **%d**, **%i**,
 * 	**%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**,
 * 	**%lli**, **%llu**, **%llx**, **%p**, **%s**. No modifier (size
 * 	of field, padding with zeroes, etc.) is available, and the
 * 	helper will return **-EINVAL** (but print nothing) if it
 * 	encounters an unknown specifier.
 *
 * 	Also, note that **bpf_trace_printk**\ () is slow, and should
 * 	only be used for debugging purposes. For this reason, a notice
 * 	block (spanning several lines) is printed to kernel logs and
 * 	states that the helper should not be used "for production use"
 * 	the first time this helper is used (or more precisely, when
 * 	**trace_printk**\ () buffers are allocated). For passing values
 * 	to user space, perf events should be preferred.
 *
 * Returns
 * 	The number of bytes written to the buffer, or a negative error
 * 	in case of failure.
 */
static long (* const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;

/*
 * bpf_get_current_pid_tgid
 *
 * 	Get the current pid and tgid.
 *
 * Returns
 * 	A 64-bit integer containing the current tgid and pid, and
 * 	created as such:
 * 	*current_task*\ **->tgid << 32 \|**
 * 	*current_task*\ **->pid**.
 */
static __u64 (* const bpf_get_current_pid_tgid)(void) = (void *) 14;

/*
 * bpf_perf_event_output
 *
 * 	Write raw *data* blob into a special BPF perf event held by
 * 	*map* of type **BPF_MAP_TYPE_PERF_EVENT_ARRAY**. This perf
 * 	event must have the following attributes: **PERF_SAMPLE_RAW**
 * 	as **sample_type**, **PERF_TYPE_SOFTWARE** as **type**, and
 * 	**PERF_COUNT_SW_BPF_OUTPUT** as **config**.
 *
 * 	The *flags* are used to indicate the index in *map* for which
 * 	the value must be put, masked with **BPF_F_INDEX_MASK**.
 * 	Alternatively, *flags* can be set to **BPF_F_CURRENT_CPU**
 * 	to indicate that the index of the current CPU core should be
 * 	used.
 *
 * 	The value to write, of *size*, is passed through eBPF stack and
 * 	pointed by *data*.
 *
 * 	The context of the program *ctx* needs also be passed to the
 * 	helper.
 *
 * 	On user space, a program willing to read the values needs to
 * 	call **perf_event_open**\ () on the perf event (either for
 * 	one or for all CPUs) and to store the file descriptor into the
 * 	*map*. This must be done before the eBPF program can send data
 * 	into it. An example is available in file
 * 	*samples/bpf/trace_output_user.c* in the Linux kernel source
 * 	tree (the eBPF program counterpart is in
 * 	*samples/bpf/trace_output.bpf.c*).
 *
 * 	**bpf_perf_event_output**\ () achieves better performance
 * 	than **bpf_trace_printk**\ () for sharing data with user
 * 	space, and is much better suitable for streaming data from eBPF
 * 	programs.
 *
 * 	Note that this helper is not restricted to tracing use cases
 * 	and can be used with programs attached to TC or XDP as well,
 * 	where it allows for passing data to user space listeners. Data
 * 	can be:
 *
 * 	* Only custom structs,
 * 	* Only the packet payload, or
 * 	* A combination of both.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (* const bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
