# v6 core contracts — source audit and freeze gates

Audit baseline: `0b704b8e2d0288702cc91b86c2f66914fa6eaaab` (`version-6`).
Capture production commit: `aacdf45d867e13a1b382661bace53aa905fe1331` (PR #6).
Transport API production commit: `136d772e17a02421624a9942cf7e2ba73e6cccb4` (PR #8).
Runtime transport adoption: `181e1ec8c63971fcb915e938eac8257c7c3cb321` (PR #9).
Capture metadata/lifecycle hardening: `c2c06dfaa9813472143e28662514b1e73393b2db` (PR #10).
Legacy VLAN/OBS context and network API preparation: `223720c9a3a42800e9bc84fba9cf7bea4bbf73c0` (PR #11).
Runtime network policy adoption: `0d5d783a014fa6f3b07e04d2579542c5e047dd05` (PR #12).
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
PR #9 replaced only TCP/UDP dispatch payload calculations. PR #15 below also
adopts normalized inspector input and bounds the network-owned router exception.

PR #9 gates: core 33843014442, L2 33843014466, staging 33843014452 PASS.
Native full text 155521 (-44), stub 142780 (+344), BSS unchanged (80304/80296).
No transport helper call remains in native/ARM64 full/stub optimized builds.
The focused local mixed transport benchmark measured ~1.00x enabled/~0.89x disabled
versus legacy predicates; it is not an end-to-end capture performance guarantee.
Fixtures cover IPv4 options/IPv6 extension, Ethernet/VLAN/QinQ/PPPoE/raw/cooked,
unaligned frames, truncation and padding exclusion. ARM64 fixtures compile only.

| Order | Contract | Verified source fact | Required before freeze |
|---|---|---|---|
| 1 | Capture / normalization | Capture owns AF_PACKET lifecycle/metadata. Packet owner supplies bounded frame/transport/inspector input including PPPoE/LLC (PR #16); network owner supplies source-side/routed classification and router admission (PR #12/#15). | Complete frame-to-observation coverage, no-port dispatch/AH semantics, lossless VLAN schema decision. |
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

### Runtime network context — PR #12

Baseline `b44ad2866979aec430c88e18004e79ca1918d3cb`. Runtime adoption preserves
filter/router/raw-identity/device selection and cheap TCP/UDP owner-cache gating.
Source/destination policy lives in the network API, not borrowed packet storage.
Routing classification merges repeated learned-prefix scans into one bounded scan;
a later direct prefix overrides an earlier routed candidate. Destination membership
is skipped when source-side evidence already admits the packet. No state/heap additions.

132600 IPv4/IPv6 endpoint/interface/capacity equivalence cases use test-only baseline
routing predicates; reject/reset and unchanged-state checks included. Core 33863897098,
L2 33863897107 and staging 33863896952 passed on candidate
`1a2c908dc287a0a5122934e46cf8db4e3377fc25`: strict standalone/native full+stub,
ASan/UBSan, ARM64 full+stub/fixture compilation and revised size gate.
Native full text 156441 versus 155629 (+812 bytes, ~0.52%); stub 143936 (+796);
BSS unchanged 80304/80296. User accepted the measured tradeoff after alternatives
were evaluated; the full-text cap is exactly 156441 with no additional headroom.
Focused 0/32/64-prefix benchmark on the original source candidate had CI ratios
0.60–0.83; code is unchanged by the approved gate revision. This is not capture
throughput or hardware acceptance. ARM64 fixtures compile only. Full core freeze
and staging integration remain blocked by the remaining contracts below.

Repository hygiene: user deleted the obsolete merged PR #1–13 branches.
Exact remote check at `b5c707b813be667d21f3a40740d0a7f469e3adc6` found only
`main` and `version-6`. Temporary gates still need retirement after final use;
re-read exact heads/open PRs before deletion and keep merged PR recovery references.

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

Link boundary PR #14 from `b5c707b8…`: the live AF_PACKET/SOCK_RAW owner
maps Ethernet/IEEE802 to Ethernet; NONE/PPP/TUNNEL/TUNNEL6/SIT/IPGRE to raw IP;
all other hardware types to unsupported. `any` resolves each packet's hardware
type/index; a fixed interface retains its configured type/index. It never creates
SLL headers or returns LINK_COOKED. Raw IP keeps absent MACs in the packet view;
main creates surrogate identities later. No new capture type or BPF fallback.

The compatibility SLL v1 decoder incorrectly tested the high byte of its BE16
address length. A red→green fixture verifies length 6 now copies the complete MAC;
all other lengths leave MAC absent, without truncating longer addresses into a
false six-byte identity. Format reference: [libpcap sll.h](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h),
blob `b13a8cbc2a024d788deca7825aacfcc09ec523ed`. Tests exhaust the 16-bit address
length and hardware-type fields, raw/SLL IPv4/IPv6, alignment/truncation/reset,
unsupported/per-packet rejection and fixed versus per-packet receive selection.
SLL2 and cooked live input are not added. Native full/stub text/BSS are unchanged.
Merged as `5c88814f68f778aba66234508c5c5c0873a805f1`; core 33865643412,
L2 33865643350 and staging 33865643383 PASS. Native strict/full/stub and sanitizers
ran; ARM64 builds/fixtures compiled only. Full C1 is not frozen.

Header-peek PR #15 from `cd4c370a…`: the inspector now consumes the successful
normalized view rather than reparsing IP. Shared TCP header-length framing lives
in `argos_packet.h`; fragment admission remains a separate dispatch policy.
Actual-printer golden tests preserve nonfirst IPv4 diagnostics, short-header
fallbacks, invalid UDP declared-length output, and IPv6 base next-header display.
22,719 output cases compare everything except the live timestamp; the golden
fixture was also executed against the pre-change printer before refactoring.

`argos_network_router_exception(protocol, l4, available, source_side)` owns the
cheap DNS-source/forwarded-SYNACK admission policy, without packet/state storage
or new packet-header dependencies. Main passes declared IP bounds behind existing
Ethernet/router/is_ip gates. 2,027,520 cases compare the old aligned-header
predicates: the sole changed admission is UDP source 53 with fewer than eight
declared IP payload bytes, formerly read from capture padding. Such input already
fails the later transport gate. Malformed TCP doff, UDP lengths and nonfirst IPv4
remain subject to their existing later dispatch checks, not extra early parsing.
No BPF, telemetry grammar, privacy, state or staging integration change.

Main shrinks 1491 source bytes. Local native full text 156281 (−160), stub 143740
(−196); BSS 80304/80296 unchanged. New helpers inline in optimized full/stub builds.
Merged as `5940804b3b9b942705f69b2ce7da09c6716e1f82`; core 33866793091,
L2 33866793047 and staging 33866793903 PASS. Native strict/full/stub and sanitizers
ran; ARM64 full/stub and fixtures compiled only. The focused transport benchmark
binary is byte-identical to baseline (SHA256 recorded in the merge commit), so
its observed timing variation is not changed test code. No full capture-throughput
or core-freeze claim.
PPPoE/legacy LLC PR #16 (`18b215571e6ba6065ff660d03b551607c26f3edd`): normalization bounds all existing
LLC/SNAP discriminators by the 802.3 declaration and inner IP by PPPoE payload
length. The existing enterprise L2 consumer uses normalized `packet_end`, so
padding cannot supply discovery TLVs. No new parser, state, BPF or wire schema.
Length semantics follow [RFC 2516 section 4](https://www.rfc-editor.org/rfc/rfc2516.html#section-4):
PPPoE length includes the PPP protocol field but not its six-byte envelope.
This step intentionally retains legacy version/type/code/session-ID acceptance;
it is length framing, not complete PPPoE semantic validation or discovery support.
The new fixture fails on the baseline and passes 3,444,174 boundary cases after
repair, plus canonical CDP/FDP/EDP padding-evidence checks. Existing malformed
positive PPPoE/CDP test frames now carry valid declared lengths. Full/stub text
156217/143676 (−64 each), BSS unchanged. Core 33869462769, L2 33869462741 and
staging 33869462750 PASS: strict native matrix/full/stub, ASan/UBSan/LSan and
ARM64 full/stub/fixture compilation (not execution). Lossless VLAN output and
full frame-to-observation coverage remain open. No throughput claim.

Runtime network context: `argos_network_context4/6` and an eight-byte
`argos_network_packet_context_t` express source-side selection and source-routed
evidence. This is not capture-socket direction. Equivalence fixtures cover both
directions, configured/learned prefixes and unknown interfaces. Main now calls
these functions after normalization; later owner-cache checks remain behind the
existing TCP/UDP relevance gates. No packet pointers are retained. No core-freeze claim.

`argos_telemetry_capture_context` owns the current legacy VLAN projection and
copies interface provenance into bounded sink storage, only in sensor mode.
It preserves equal-VID coalescing, two-VID truncation, VID-zero/absent ambiguity,
and the configured capture name (including `any`), without a schema change.
250 golden combinations plus reset/copy-lifetime fixtures protect existing OBS
output. Lossless VLAN presence, equal nested tags and actual per-packet interface
provenance remain explicit future decisions, not silently corrected here.

PR #11: core 33845034267, L2 33845034214, staging 33845034207 PASS.
Native full text 155629 (unchanged), stub 143140 (-20); BSS unchanged 80304/80296.
The existing text cap was not relaxed. Strict native standalone tests and
ASan/UBSan passed, including network and telemetry fixtures. ARM64 full/stub and
fixtures compiled; no ARM64 fixture execution or end-to-end throughput claim.
PR #11 left main's network predicates unchanged; PR #12 adopts the network API
while preserving policy outcomes, owner-cache gating and identity selection.

PR #10: core 33843660310, L2 33843660206, staging 33843660244 PASS.
Native full text 155629 (+108), stub 143160 (+380); BSS unchanged 80304/80296.
Size cap was not relaxed. These are correctness bounds/cleanup changes, not
an end-to-end throughput benchmark. Native fixtures and sanitizers ran; ARM64
full/stub and the capture contract fixture were compiled, not hardware-executed.

- Capture receive accepts only complete ancillary records within returned control
  bytes; aligned stack storage, timestamp length checked, valid prefixes retained
  under MSG_CTRUNC. VLAN validity remains independent of VID (including VID 0).
- Capture close is repeat-safe after any open attempt; allocation failure releases
  epoll immediately. A zero-interface return still requires close, as main already
  does. Open must not be called on a live owner; arbitrary zeroed state is not an
  initialized capture owner. Global runtime/sink failure cleanup is still open.
- `test_capture_contract` mocks syscall failures without raw-socket privileges;
  it checks EINTR/EAGAIN, clamping, per-packet versus fixed link/index, malformed
  ancillary extents, partial startup and repeated close. `test_capture` also checks
  a real kernel timestamp via a local datagram socket, not AF_PACKET hardware.
  These tests do not freeze direction/ownership or VLAN observation semantics.

- The audited baseline rejected the STP `42 42 03` LLC prefix. PR #7 repairs this
  using the existing canonical parsers: normalization retains LLC and bounds
  `packet_end` by declared 802.3 length; main passes that bound to STP/RSTP/MSTP.
  `test_stp_path` failed before repair and now exercises BPF→normalization→parser
  for native/VLAN/QinQ, truncated declarations and padding exclusion. This closes
  this specific reachability defect, not the whole packet-view contract.
- IPv6 AH is traversed as an extension by `argos_packet_ipv6_l4`; its own header
  offset is not retained for a future AH engine. ESP/AH remain on hold.
- `tests/test_packet_fragments.c` adds decode→transport boundary coverage:
  all IPv4/IPv6 fragment-field bits, first/nonfirst/atomic behavior, partial TCP/UDP,
  declared-length/capture truncation and padding, unaligned raw/Ethernet frames,
  extension length fields and mixed chains. The existing eight-iteration traversal
  accepts at most seven extensions before a terminal header; eight are rejected.
  AH length follows the existing formula, not full RFC validation; checksums,
  reserved bits and extension ordering are not validated by these fixtures.
  PR #13 merged as `986fb010089c5d38289e312994ce40ea9dc10145` after core
  33864797588, L2 33864797374 and staging 33864797402 PASS. Native strict/full/stub
  and ASan/UBSan ran; ARM64 full/stub and fixtures compiled, not executed.
  This test-only step does not change runtime policy or certify BPF/output
  reachability, reassembly, AH ownership or the full C1 contract.
- PTP EtherType `0x88f7` is not admitted by the main non-IP allowlist or native
  untagged BPF path. UDP 319/320 is not wired either. Both must reach one parser.
- Thread has no raw IEEE 802.15.4 capture contract and remains on hold.
- Packet fields contain original frame offsets, not owned payload. Never retain
  these pointers in observation/state after the receive buffer is reused.

### Non-port/AH/PTP design checkpoint (no runtime API freeze)

Exact baseline: `5af8df48ed46b159acb9ef2f014ef6d614e704a2`.
`tests/test_nonport_contract.c` characterizes existing code; it does not implement
a replacement dispatcher. Source under `src/` remains unchanged by this step.

| Layer | Verified current behavior | Required change before integration |
|---|---|---|
| Capture | Only fixed Ethernet without live userspace filter attaches vector BPF; raw/`any` do not. Attach/build failure warns and continues without it. | Test configuration capacity and explicit failure behavior; never run a partial filter. |
| BPF | Buildable legacy masks admit untagged IPv4 non-port protocols 2/89/112 only under enterprise. IPv6 is conservative under ipv6; VLAN/QinQ/PPPoE are unconditional fallbacks. | Compile enabled IP-protocol gates, retaining safe fallbacks and disabled userspace rejection. |
| AH | IPv4 keeps protocol 51/header offset. IPv6 walks AH and keeps terminal protocol/offset only; repeated AH headers lose both offsets. AH→59 rejects the whole view. | Preserve separate bounded AH framing without overwriting terminal transport or rewalking extensions in engines. |
| ESP | Terminal protocol 50 yields a bounded non-port transport slice, but no runtime engine receives it. | Enable gate before fixed-header extraction; no payload/decryption/tunnel recursion. |
| PTP | Normalizer can expose native 88f7 or bounded UDP payload. Main native allowlist excludes 88f7 and has no PTP call. UDP 319/320 have no dedicated relevance/BPF entry. | One bit and one parser reached by native and UDP adapters after contracts settle. |

**New priority blocker — BPF capacity:** exhaustive 10-boolean configuration
fixtures find 212/1024 builds fail at the existing 256-instruction limit with
WireGuard port zero. All categories enabled plus WireGuard 51820 also fails
(e.g. `-a --enterprise`, not `-a` alone). On the applicable fixed-Ethernet capture
path this prevents prefilter attachment; packets still undergo userspace gates.
No memory overrun was observed: builder bounds reject the partial program.
Fix compact admission generation and test all masks/custom ports before adding
new protocol gates. Evaluate shared return targets/deduplicated checks first;
any necessary capacity/stack increase requires measured review, not a silent cap
change. Kernel verifier/attach and fault-policy tests remain required. The current
fixture deliberately labels this a KNOWN GAP; change its expectations when fixed.

**Proposed API direction, not implemented:** packet normalization owns framing;
preserve `ip_protocol/l4_offset` terminal semantics for existing consumers. Prefer
an optional caller-owned first-AH offset/length sidecar populated during the same
bounded IPv6 walk (IPv4 uses the existing header offset). No packet-wide list,
payload copy, allocation, protocol result fields or new per-flow tracker. Compare
this against two inline packet-view fields before selecting the final API; measure
stack/ABI/text and disabled-path specialization on native/ARM64. A null/disabled
request must not add engine calls or state lookups. No extra traversal per engine.

The future first-AH contract must explicitly state first-only coverage for
repeated AH, no recursive tunnel inspection, no ports on AH/ESP slices, and no
usable output on decode failure. Do not recover AH evidence from AH→59 or a later
malformed extension by using a partially initialized view. Such evidence would
need a separately reviewed partial-success API. Reject nonfirst fragments; only
complete bounded headers on admitted first/atomic fragments can supply metadata,
never authentication verification or reassembly.

AH framing length follows [RFC 4302 §2.2](https://www.rfc-editor.org/rfc/rfc4302.html#section-2.2).
The legacy IPv6 walker accepts an eight-byte AH, whereas the isolated parser
requires at least twelve; neither currently enforces IPv6's eight-byte alignment.
The proposed evidence adapter must validate those bounds without silently changing
legacy terminal dispatch. Neither SPI/sequence extraction nor a valid length
proves AH integrity. No ICV/key material may become observation storage.

PTP adapters should supply the same bounded message slice to the existing parser:
native `[l3_offset,packet_end)` or UDP's declared payload. Use one protocol enable
bit before parser/state access. A WireGuard custom port of 319 or an unrelated
enabled port can incidentally admit the tuple today; this is not PTP integration.
PTP common-header metadata is not full message-specific validity, and its staging
result's clock/sequence/correction fields are not frozen fingerprint inputs.

Fixtures cover buildable-mask non-port admission, explicit bounded failure masks,
raw/Ethernet/VLAN/QinQ/PPPoE/SLL compatibility, alignment/truncation/padding,
AH length fields/mixed chain/header loss/fragments and one isolated PTP parser
across native/UDP4/UDP6. BPF interpreter checks use complete frames only; its
out-of-range load behavior is not the kernel's immediate-drop behavior. This is
not an AF_PACKET throughput test, kernel verifier test or end-to-end emission test.
Merged as PR #17, `2ac259284e5481d65ba852d943a000d2b24bfd32`. Core 33874404696,
L2 33874404652 and staging 33874404676 PASS: strict standalone/native full/stub,
ASan/UBSan/LSan, ARM64 full/stub/fixture compilation and unchanged size budgets.
241,362 characterization checks passed; known BPF failures are not repaired or
waived. Native full/stub binaries are byte-identical to PR #16 (hashes in merge
commit); ARM64 fixtures compiled, not executed. ESP/AH/PTP remain runtime-isolated.

### Completion and rate semantics (remaining work)

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
