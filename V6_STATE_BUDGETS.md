# Argos Sniffer v6 — bounded state and byte budgets

This inventory describes current production owners. It is a contract input, not
permission to integrate staging parsers. Sizes are native LP64 values and are
pinned by `tests/test_state_capacity.c` and `tests/test_core_budget.c`; ARM64 CI
must compile the same assertions. Packet-derived storage is fixed-capacity and
prepared only at startup when its feature needs it. No owner may allocate or
retry allocation in packet processing.

## Retained packet-derived state

| Owner | Capacity / probes | Lifetime and saturation | Retained bytes |
|---|---:|---|---:|
| TCP application generation/DONE | 1,024 / 4 | 60 s; oldest entry in the four-slot collision window is replaced. Initial SYN resets both directions. Incomplete inspection completes after 8 payload packets. | 57,344 inline |
| UDP class suppression | 256 / 2 | Fixed 5 s epoch; suppressed hits do not extend it; oldest entry in the two-slot collision window is replaced. | 14,336 inline |
| SYN/SYN-ACK correlation | 1,024 / 8 | 120 s; expired/free slot first, otherwise oldest in the eight-slot window. Clock rollback invalidates the old epoch. | 65,536 enabled heap |
| DNS request correlation | 1,024 / 8 | 5 s; expired/free slot first, otherwise oldest in the eight-slot window. Full tuple, TXID, qtype and qname hash identify an entry. | 212,992 enabled heap |
| Emission dedup | 2,048 / 8 | Caller TTL; fixed or sliding policy. Free/matching slot first, otherwise oldest in the eight-slot window. Stores only hash/time/valid. | 49,152 enabled heap |
| IPv4 address owner | 256 / 4 | 180 s; stale/free/matching slot first, otherwise oldest in four-slot window. | 8,192 enabled heap |
| IPv6 address owner | 128 / 4 | 180 s; stale/free/matching slot first, otherwise oldest in four-slot window. | 5,120 enabled heap |
| QUIC success suppression | 64 direct slots | 15 s; a colliding key replaces the direct slot. | included in 1,576-byte QUIC owner |
| QUIC Initial scratch | one reusable workspace | Prepared when TLS/QUIC is enabled; never retained across owners and never allocated per packet. | 81,919 enabled heap |
| QUIC heavy reassembly (`-W`) | 64 sessions | 5 s; completed/stale session is cleared. If all sessions are live, a new DCID is dropped rather than evicting active evidence. Each session retains at most 8,192 CRYPTO bytes plus a 1,024-byte presence bitmap. | 593,408 opt-in heap |

`argos_runtime_state_t` is 71,704 bytes inline (application table, UDP table and
three dynamic-owner handles). `argos_network_state_t` is 6,336 bytes inline and
`argos_quic_state_t` is 1,576 bytes inline. With every current optional owner,
both IP families and heavy QUIC enabled, the listed dynamic allocations total
1,016,319 bytes and these three inline owners total 79,616 bytes: 1,095,935 bytes
combined. This excludes capture/kernel buffers, executable mappings, libc and
transient parser stack. It is a maximum configuration inventory, not a claim
that all features are enabled by default.

DNS is the only generic correlation owner above that retains a textual value:
each 208-byte entry contains a bounded 128-byte domain field. QUIC heavy retains
only its bounded CRYPTO prefix/presence map. No owner retains packet pointers or
unbounded payload.

## Capture, startup and transient budgets

| Component | Bound | Ownership / hot-path rule |
|---|---:|---|
| Capture state | 400 bytes; max 8 interfaces | Lifecycle owner; interface entries are 48 bytes each. |
| Capture packet result | 32 bytes | Metadata only; points to no retained frame. |
| Receive frame buffer | 65,535 bytes | One caller-owned reusable packet-loop buffer. |
| Epoll result batch | max 16 events | Caller-owned reusable packet-loop array. |
| Kernel receive buffer request | 2 MiB per AF_PACKET socket | Kernel-owned request; effective allocation is OS-controlled and not included in user-space totals. |
| Runtime config | 20 bytes | Startup/control state; no packet-derived evidence. |
| Dispatch plan | 48 bytes | Startup-derived fixed protocol/feature masks and L2/L3/L4 route flags; no packet-derived evidence or retained payload. |
| Classic BPF builder | 2,052 bytes; max 256 instructions | Startup stack only; attached filter is kernel-owned. |
| Address filter program | 2,312 bytes each; max 64 RPN tokens | Three compile-once programs exist in main; evaluation uses a bounded 64-integer stack and no string lookup/allocation. |
| Telemetry event | 1,024 bytes | Per-call stack buffer; truncates to the existing bound. |
| Sensor OBS envelope | 1,280 bytes | Per-call stack buffer only in sensor mode. No telemetry queue exists. Datagram sinks are nonblocking; stdout policy remains a C8 contract. |

TLS, enterprise, L2, identity and the remaining network protocol parsers do not
own retained flow tables in current production. Their result structures and
parser scratch are bounded automatic storage. Stack/compiler frame budgets stay
under the permanent native/ARM64 size and build gates and must be remeasured when
an engine adds significant scratch.

## Verified semantics and remaining byte work

Permanent fixtures cover capacity/collision replacement for TCP application,
UDP suppression, SYN, DNS, dedup and IPv4/IPv6 address owners; QUIC full-table
drop, expiry/reuse and successful-completion DCID reuse; fixed/sliding epochs,
clock rollback and application SYN generation reset. Static assertions turn ABI
growth into an explicit review instead of silent RAM drift.

This inventory freezes existing owner capacity and lifecycle facts only. It does
not fill planned protocol-matrix values by assumption. Before any staged protocol
is runtime-ready, its exact `max_packets`, `max_bytes`, `state_bytes`, timeout,
completion/drop and privacy assertions must be source-verified under C5/C10.
Unrated output may bypass emission dedup only; it never removes inspection or
retained-state safety ceilings.
