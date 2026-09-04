# v6 core contracts — source audit and freeze gates

Audit baseline: `0b704b8e2d0288702cc91b86c2f66914fa6eaaab` (`version-6`).
Capture production commit: `aacdf45d867e13a1b382661bace53aa905fe1331` (PR #6).
Transport API production commit: `136d772e17a02421624a9942cf7e2ba73e6cccb4` (PR #8).
Runtime transport adoption: `181e1ec8c63971fcb915e938eac8257c7c3cb321` (PR #9).
This is an **interim audit, not integration approval**.
The protocol integration matrix remains the master blueprint. Its planned fields
are not evidence of runtime reachability or collector compatibility.

## Current source facts and remaining freeze gates

Transport API addition: `argos_packet_transport()` returns borrowed bounded offsets,
TCP/UDP ports only when applicable, and rejects malformed lengths/nonfirst fragments.
`tests/test_transport.c` checks equivalence with the existing main-loop predicates.
Runtime adoption uses `argos_packet_transport_normalized(view, protocol, out)`
after successful normalization and IP/nonfirst-fragment guards. The protocol
argument is the matching TCP/UDP dispatch constant, enabling inline specialization.
The defensive API shares this parser and remains available for other callers.
TCP option bounds use the returned header length; UDP relevance/owner checks stay
before length validation. No AH handling, output or state ownership changes.
The debug packet dump and earlier router-exception header peeks remain separate;
this step replaces the TCP/UDP protocol-dispatch payload calculations only.

PR #9 gates: core 33843014442, L2 33843014466, staging 33843014452 PASS.
Native full text 155521 (-44), stub 142780 (+344), BSS unchanged (80304/80296).
No transport helper call remains in native/ARM64 full/stub optimized builds.
The focused local mixed transport benchmark measured ~1.00x enabled/~0.89x disabled
versus legacy predicates; it is not an end-to-end capture performance guarantee.
Fixtures cover IPv4 options/IPv6 extension, Ethernet/VLAN/QinQ/PPPoE/raw/cooked,
unaligned frames, truncation and padding exclusion. ARM64 fixtures compile only.

| Order | Contract | Verified source fact | Required before freeze |
|---|---|---|---|
| 1 | Capture / normalization | Capture extraction owns AF_PACKET setup/receive/stats/close. `argos_packet.h` owns borrowed frame and TCP/UDP dispatch payload bounds. | Direction/ownership context, no-port dispatch/AH semantics, ancillary metadata and failure-path coverage; debug-dump/header-peek reconciliation. |
| 2 | Bounded state / lifecycle | `argos_flow_state.h` owns application DONE, UDP suppression and SYN/DNS/dedup lifecycle; network and QUIC retain separate state. | Eliminate packet-time allocation, explicit prepare/destroy contracts, partial-init cleanup, byte budgets, clock behavior and cache-eviction semantics. |
| 3 | Config / enable bitmap | `argos_runtime_config_t` contains enterprise mode, identity mode and WireGuard port; main still owns legacy booleans. | One protocol bit, shared membership tables, explicit profile contents and precedence, separate enable and unrated masks; startup-only compilation. |
| 4 | Cheap dispatch / gating | Main gates TCP/UDP with legacy categories; BPF uses category booleans and port lists. | Per-protocol gates before parser/state access, BPF/userspace equivalence, disabled-protocol call counters, non-port IPv4/IPv6 and native-L2 reachability. |
| 5 | Suppression / dedup | TCP DONE is directional, reset on initial SYN; UDP class suppression and emitted-record dedup have distinct keys/TTLs. | Do not conflate unrated output with unlimited inspection. Prove completion packet emits before DONE; test collision/expiry/bulk-tail and byte ceilings. |
| 6 | JIT / scheduling / feed state | No JIT/feed-state API exists in the audited source. Main schedules QUIC GC and capture statistics by wall clock. | Define demand activation outside packet processing, bounded maintenance quotas and immutable per-packet configuration epoch. No runtime code generation or new tracker is implied. |
| 7 | Observation / output / JSONL | Engines return protocol-specific results; main assembles legacy strings. `argos_telemetry.h` formats a 1024-byte event and optional 1280-byte OBS wrapper. JSONL is not implemented. | Separate borrowed packet lifetime from owned bounded evidence, field/privacy/escaping limits, newline/truncation semantics, stream backpressure policy, collector compatibility. |
| 8 | Telemetry ownership | Datagram sends belong to `argos_telemetry.h`; CLI in main creates/closes its descriptors. Datagrams are nonblocking; stdout uses `fwrite`. | Sink lifecycle behind telemetry API; explicit stdout blocking/drop behavior and counters; engines never own transports or queues. |
| 9 | Helper/API cleanup | TLS and enterprise port helpers are shared by parsers and BPF; raw identity is separate. | Fold only after config/dispatch boundaries settle; avoid making BPF depend on protocol implementations. Remove duplicate parsing, not just file names. |
| 10 | Regression matrix | Standalone parser tests plus native/ARM64 builds exist. | Add end-to-end capture→normalize→dispatch→observation coverage, allocation trap, saturation/expiry tests, output golden corpus and hardware acceptance. |

None of the ten complete contracts is frozen by this audit. Existing legacy wire
behavior and privacy requirements remain compatibility constraints throughout.
The capture extraction passed its combined-tree gate: native full/stub, ARM64
full/stub, all standalone tests, capture sanitizers and staging isolation/sanitizers.
It does not certify all packet paths. Main shrank from 119724 to 110856 bytes;
optimized native text grew by 104 bytes. The BSS decrease of 416 bytes is mainly
capture state moving to stack, not an equivalent total-memory saving. These are
size measurements, not proof of zero runtime performance overhead.

## Concrete blockers, not hypothetical architecture work

### Allocation and lifecycle

- `argos_dedup_should_suppress_at` allocates its table on first emitted evidence.
- `argos_network_owner4_note` / `argos_network_owner6_note` can allocate ownership
  tables through their ensure helpers while processing ARP/NDP.
- QUIC stateless and stateful decrypt allocate scratch buffers per call;
  `quic_heavy_ensure_table` allocates its table on first use.
- Consequently **no malloc in the packet hot path is not currently satisfied**.
  Moving only dedup allocation would not close this contract.
- Preserve disabled-mode footprint by allocating enabled subsystem capacity at
  startup/explicit activation, before capture processing. If future JIT activation
  is required, request activation and return; prepare resources at a lifecycle
  boundary, never retry allocations for every packet. This is a design target,
  not current implementation.
- SYN state is a module-static pointer, and runtime destruction is currently
  single-use. Multi-instance ownership, repeated destroy and partial initialization
  require tests before declaring the lifecycle API reusable.

### Packet reachability

- The audited baseline rejected the STP `42 42 03` LLC prefix. PR #7 repairs this
  using the existing canonical parsers: normalization retains LLC and bounds
  `packet_end` by declared 802.3 length; main passes that bound to STP/RSTP/MSTP.
  `test_stp_path` failed before repair and now exercises BPF→normalization→parser
  for native/VLAN/QinQ, truncated declarations and padding exclusion. This closes
  this specific reachability defect, not the whole packet-view contract.
- IPv6 AH is traversed as an extension by `argos_packet_ipv6_l4`; its own header
  offset is not retained for a future AH engine. ESP/AH remain on hold.
- PTP EtherType `0x88f7` is not admitted by the main non-IP allowlist or native
  untagged BPF path. UDP 319/320 is not wired either. Both must reach one parser.
- Thread has no raw IEEE 802.15.4 capture contract and remains on hold.
- Packet fields contain original frame offsets, not owned payload. Never retain
  these pointers in observation/state after the receive buffer is reused.

### Completion and rate semantics

- TCP application table: 1024 slots, four probes, 60-second idle window,
  eight payload-packet budget. This is not a protocol-specific byte budget or a
  permanent per-flow guarantee under eviction.
- UDP suppression: 256 slots, two probes, five-second fixed epoch; suppressed
  hits do not extend the epoch. Used for WireGuard transport-data class 4 only.
- Emission dedup: 2048 slots/eight probes; ordinary records use sliding TTL;
  ARP/NDP/RA use fixed refresh floors. Uppercase/verbose affects output dedup,
  not TCP safety limits or UDP bulk suppression.
- TLS ServerHello parsing is repeated by the completion helper after emission.
  Replace this with a completion result from the same parser invocation during
  the dispatcher/observation work; do not add another enrichment parser pass.

### CLI decisions required

- Keep `--identity[=hash|raw]` exclusively as the existing privacy mode. The group
  named `identity` needs a disambiguated selector (for example a qualified group
  selector); the help mock-up cannot silently redefine this existing option.
- Preserve `--sensor` deployment semantics separately from profile `sensor`.
- Profile membership and legacy compatibility precedence are not yet specified
  exactly. No profile should silently activate staged parsers or raw identity.
- Generate thematic help and enable masks from the same source. Base help needs
  an agreed line budget; the long illustrative mock-up is not a size acceptance
  test. Do not add `--help-protocols`.

### Observation and streaming

- `ENT|`, `TLS|`, `DOT|`, `TLSSRV|`, `IDENT|` and OBS remain current wire facts;
  proposed `TLS-CLIENT`, `TLS-SERVER`, `TLS-CERT` are not runtime vectors.
- Existing truncation may remove the trailing newline. This is incompatible
  with claiming an already-frozen JSONL/streaming contract.
- A nonblocking UDP socket does not make stdout nonblocking. Define bounded
  stream delivery/partial-write/backpressure behavior before claiming bounded
  output latency. Never solve it with an unbounded queue.
- Collector code/deployment acceptance is not established in this repository.
  `collector_mapping` must remain unverified until an actual compatibility fixture
  and collector owner/version are supplied or inspected.

## Preliminary integration readiness (not the final post-freeze review)

1. **Immediately runtime-ready staging parsers: none.** Core gates remain open.
2. LLDP-MED/LACP/STP require reconciliation with the canonical L2 engine. STP
   normalization was repaired in PR #7; keep exactly one runtime parser per protocol.
3. TLS client/server enrichment must become fields of the existing parse result,
   not a second ClientHello/ServerHello parse. ATS1 remains the current server
   fingerprint. JA4S choice, ordering and naming are not frozen.
4. Synthetic enrichment fixtures verify presence extraction, not real TLS 1.3
   visibility. Add realistic flights distinguishing offers from negotiated facts,
   encrypted handshake metadata and HRR. Certificate framing tests are not proof
   that TLS 1.3 certificates are passively visible without decryption.
5. Certificate/X.509 need positive complete leaf fixtures, field bounds/privacy,
   realistic visibility, normalized observation ownership and collector mapping.
6. Fast-complete staging is policy input only; reconcile with existing DONE state.
   Flow-shape remains experimental; no new flow tracker is authorized.
7. Other isolated protocols need the full per-row matrix audit, wrapper/result
   adaptation, budget and collector fixtures. Standalone tests are not approval.
8. Explicit holds remain Thread, ESP/AH; PTP is blocked on dual-path reachability.

After core freeze, use the master matrix's integration order: overlapping L2
reconciliation → RIP/PTP (subject to reachability) → exporters → application
control → media → enterprise storage/directory → industrial → IoT → VPN.
TLS enrichment is a separate bounded step after the TLS/public-observation freeze.
No dependency is waived by a protocol's position in that sequence.

## Missing acceptance tests before final readiness review

- Frame fixtures for STP/RSTP/MSTP, native+UDP PTP, IPv4/IPv6 AH/ESP, fragments,
  VLAN/QinQ/PPPoE, raw/cooked/unsupported links and ancillary VLAN/timestamp data.
- Allocator interception after startup including successful/failing QUIC decrypt,
  first ARP/NDP evidence and first deduplicated emission; zero allocations required.
- Partial initialization, repeated shutdown, allocation failure, table saturation,
  tuple reuse, clock rollback and expiry; explicit per-protocol packet/byte budgets.
- Disabled-engine counters proving no payload parsing or state lookup; startup
  masks/help equivalence and BPF-versus-userspace reachability for every enabled bit.
- Completion packet retained; bulk tail cannot add evidence; unrated output does
  not remove parser budgets; identity-bearing later handshake not skipped early.
- Legacy golden output, JSON escaping/control-byte corpus, long-field truncation,
  final newline, partial writes/EAGAIN, slow/closed stdout and sink fan-out policy.
- Realistic TLS visibility/privacy and fingerprint stability/discrimination;
  collector mapping/version fixtures, sanitized PCAPs and actual OpenWrt/SPAN runs.

The final readiness review must answer all eight requested questions using
verified source/API and test evidence. Do not mark this interim audit as that exit gate.
