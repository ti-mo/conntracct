We have our hashing algorithm:
https://github.com/minio/blake2b-simd

Maps with concurrent access:
https://github.com/orcaman/concurrent-map

Use buffered channels wherever possible:
https://gist.github.com/atotto/9342938

Worker queue design:
http://nesv.github.io/golang/2014/02/25/worker-queues-in-go.html
http://marcio.io/2015/07/handling-1-million-requests-per-minute-with-golang/

Only DESTROY events carry accounting info. We will need a second Netlink socket to send accounting queries for every flow. How scalable is this?

Features we require out of mdlayher/netlink:

- NetFilter Netlink (nfnetlink) functionality and parsing, primarily ConnTrack
  * Old compat NF_NETLINK (NEW/UPDATE/DESTROY) consts from 'libnfnetlink/linux_nfnetlink_compat.h' - why do they still exist?
  * Macros like NFCT_ALL_CT_GROUPS
  * Queries for connection states (searches, accounting info, etc.)
  * Calls to invalidate sessions
- A function to easily read and modify the buffer size of the Netlink socket
- A leaner conn.Receive() call devoid of any logic or multipart detection
  * Perhaps a blocking conn.Stream() that takes a `chan` if the user just wants to receive?
  * Parsing logic that can be invoked inside any context (eg. reading messages from a `chan` for parallel processing)


## Processing Pipeline

### Ingest

1. Pick from Netlink Queue into channel
2. Parse Netlink messages into structs
3. Run a fast hash function over the original direction quad
4. Look up hash in a thread-safe hash map
5. Conditionally commit/apply the message to the map (only roll-forward)

```
 ----------------
| Netlink Socket |
 ----------------
       |
       | Ordered
       |
     -----
Netlink Workers (n-scalable)
  - Run Netlink parsing here (not Conntrack parsing)
  - Output of this block of workers is considered unordered
     -----
       |
       | Unordered messages
       | Buffered channel (high contention)
       | M:M channel
       |
     -----
Conntrack Workers (n-scalable)
  - Extract Conntrack attributes
  - Run a quad hash
     -----
       |
       | Unordered Messages
       | Buffered channel
       | M:1 channel
       |
     -----
Commit Workers (single or n-scalable)
  - Look up the Conntrack message hash in the state table
  - Check if the message could advance the connection state
  - Commit the transaction
  - Log any out-of-order transactions
     -----
```

Scaling out commit workers might incur a significant performance penalty
on map accesses. This needs to be benchmarked using concurrent-map.

Conntrack garbage collector
---
https://patchwork.ozlabs.org/patch/680336

Conntracks that are timed out will NOT be immediately evicted from the kernel cache, and DESTROY events will not be sent in time.
Cleanup is done by gc_worker() in the kernel. DESTROY events are sent when the garbage collector reaps expired flows.

It is possible for a flow not to be evicted when the timer expires. If communication resumes (eg. UDP)
between a flow expiring and the garbage collect running, the ID will be re-used and the counters reset.
DESTROY and NEW events will be generated back-to-back, but when processing the event pipeline asynchronously,
it's possible for these messages to be processed out-of-order. We will have to mix and match (and make sense of)
events and polling messages to reach the right conclusion.

- If counters reset from polling an ID, expect a DESTROY on that ID, but obey the counters from the poll.
  * Copy the 'old' flow to an archival table instead of moving it to preserve its accounting info and starting timestamp
  * Do not archive/evict the freshly-reset flow when the DESTROY comes in. (eg. set ExpectDestroy flag on flow)
  * Expect a NEW event (eg. set ExpectNew) on the new flow and overwrite its timestamp with the one from the new event
- Connection tuple info will never change, this only happens when re-using same ports/addresses.
