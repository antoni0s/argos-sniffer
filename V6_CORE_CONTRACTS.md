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
| 2 | Bounded state / lifecycle | `argos_flow_state.h` owns application DONE, UDP suppression and SYN/DNS/dedup lifecycle; network and QUIC retain separate explicit owners. Their enabled capacity is prepared before capture and packet calls do not allocate (PR #22–24). Current capacities, native/ARM64 byte sizes, clock/expiry, saturation/eviction and tuple reuse are pinned in `V6_STATE_BUDGETS.md` (PR #27). | Existing production retained-state ownership is frozen. Every future/staged engine still requires exact packet/byte/state ceilings and completion/drop semantics under C5/C10 before integration. |
| 3 | Config / enable bitmap | `argos_config.h` defines 101 stable protocol IDs/groups (PR #28), production-only enabled/unrated masks (PR #29), exact legacy bundles/features (PR #30), production-filtered no-rate targets (PR #31), exact production-only profiles (PR #32), argv-order selector compilation (PR #33), generated help (PR #34), and compile-once runtime adoption for existing legacy options (PR #35). | Expose qualified selectors only with fine-grained C4 dispatch; preserve legacy equivalence. |
| 4 | Cheap dispatch / gating | A fixed 48-byte plan owns canonical protocol/features plus bounded L2/L3/L4 route demand. Native-L2 and non-port network callers consume individual bits before parser work; ARP/NDP owner allocation follows enabled-family demand. | Adopt remaining TCP/UDP callers, canonical BPF/userspace equivalence and full no-port IPv4/IPv6 reachability. |
| 5 | Suppression / dedup | TCP DONE is directional, reset on initial SYN; UDP class suppression and emitted-record dedup have distinct keys/TTLs. | Do not conflate unrated output with unlimited inspection. Prove completion packet emits before DONE; test collision/expiry/bulk-tail and byte ceilings. |
| 6 | JIT / scheduling / feed state | No JIT/feed-state API exists in the audited source. Main schedules QUIC GC and capture statistics by wall clock. | Define demand activation outside packet processing, bounded maintenance quotas and immutable per-packet configuration epoch. No runtime code generation or new tracker is implied. |
| 7 | Observation / output / JSONL | Engines return protocol-specific results; main assembles legacy strings. `argos_telemetry.h` formats a 1024-byte event and optional 1280-byte OBS wrapper. JSONL is not implemented. | Separate borrowed packet lifetime from owned bounded evidence, field/privacy/escaping limits, newline/truncation semantics, stream backpressure policy, collector compatibility. |
| 8 | Telemetry ownership | Datagram sends belong to `argos_telemetry.h`; CLI in main creates/closes its descriptors. Datagrams are nonblocking; stdout uses `fwrite`. | Sink lifecycle behind telemetry API; explicit stdout blocking/drop behavior and counters; engines never own transports or queues. |
| 9 | Helper/API cleanup | TLS and enterprise port helpers are shared by parsers and BPF; raw identity is separate. | Fold only after config/dispatch boundaries settle; avoid making BPF depend on protocol implementations. Remove duplicate parsing, not just file names. |
| 10 | Regression matrix | Standalone parser tests plus native/ARM64 builds exist. | Add end-to-end capture→normalize→dispatch→observation coverage, allocation trap, saturation/expiry tests, output golden corpus and hardware acceptance. |

The current-production retained-state ownership sub-contract (C2) is frozen; the
other complete contracts are not frozen by this audit. Existing legacy wire
behavior and privacy requirements remain compatibility constraints throughout.
The capture extraction passed its combined-tree gate: native full/stub, ARM64
full/stub, all standalone tests, capture sanitizers and staging isolation/sanitizers.
It does not certify all packet paths. Main shrank from 119724 to 110856 bytes;
optimized native text grew by 104 bytes. The BSS decrease of 416 bytes is mainly
capture state moving to stack, not an equivalent total-memory saving. These are
size measurements, not proof of zero runtime performance overhead.

### Canonical config catalog — PR #28, `b19811f08b8154579ff0185a395be8ee43c361d7`

`argos_config.h` owns one stable ID for each of the 101 canonical protocols, a
two-word/16-byte fixed bitmap, six super-groups, 28 groups and 103 memberships.
NFS and NTLM intentionally belong to two groups but each has one ID/bit. The six
profile names are reserved without inventing their contents. Startup-only exact
lowercase/UPPERCASE lookup distinguishes normal/unrated protocol selections and
rejects mixed case. Group, super-group and profile-name lookup is lowercase exact.

Current implementation status is explicit metadata, not an activation: overlapping
production/staging TLS enrichment and LLDP-MED/STP/LACP are marked as both; Thread,
ESP and AH retain HOLD. No staged parser is reachable from the catalog. The main
loop, legacy CLI booleans, BPF, help, wire output and allocation behavior are unchanged.
Because the catalog is not yet consumed by production, optimized full/stub text,
data and BSS remain 157560/144886, 1408 and 80360/78760 respectively.

`tests/check_config_catalog.py` fails if the backlog taxonomy and source catalog
drift. `tests/test_config_catalog.c` verifies all IDs, group/super-group counts,
duplicate membership, edge bits, exact case parsing, reserved profiles and status
holds. Core 33947311065, L2 33947311048 and staging 33947311059 PASS, including
strict full/stub, ASan/UBSan/LSan and ARM64 compilation. Profile contents,
legacy-category mapping, precedence and runtime consumption remain open C3/C4 work.

### Config selection state — PR #29, `6bc9b4dd1a63f67b3737a42b47da69756d90d8f8`

`argos_protocol_selection_t` owns fixed enabled and unrated protocol masks (32 bytes
total). Every requested mask is intersected with current production status, so staging-only
and HOLD entries cannot become active. Overlapping lowercase/uppercase selections use
startup argument order: the most recent selection changes only those protocols' rate mode.
The no-rate-limit primitive can unrate already-enabled protocols but cannot enable a parser.
Inspection/state safety budgets are independent of output rate mode.

The catalog test pins selection size, production filtering, last-overlap precedence,
group overlap and empty-selection behavior. Main, BPF, legacy CLI booleans, packet loop,
wire output and allocations remain unchanged; native full/stub text stays
157560/144886 and BSS 80360/78760. Core 33947638500, L2 33947638504 and staging
33947638519 PASS, including strict full/stub, sanitizer and ARM64 compile coverage.
Profile contents, legacy-category mapping, non-protocol controls and runtime adoption
remain open; no staging parser became reachable.

### Legacy selection ownership — PR #30, `01cb582dc39aa6ed0a72e8e258b4e20a72bb3b59`

The eight historical short telemetry categories, their default subset and `-a/-A`
bundle now have exact startup-only canonical masks. SYN fingerprinting, IPv6 handling,
extended metrics, stateful QUIC and sensor deployment are typed feature controls rather
than false protocol bits. Only SYN has a legacy rate mode. The legacy TLS category maps
to TLS/DoT/QUIC; L2 maps to LLDP/ARP/NDP/RA; multicast discovery maps to
mDNS/SSDP/UPnP/WSD. The all shorthand retains current behavior and excludes enterprise.

The current `--enterprise` compatibility gate is characterized as 50 production protocol
semantics spanning network, application, enterprise, industrial, IoT and VPN. It is
deliberately distinct from the canonical enterprise super-group; the shared CLI spelling
must be resolved before runtime adoption. Tests pin bundle sizes, paired semantics,
production filtering, default/all exclusions and rate precedence. No main/BPF/packet-path
consumer changed, so native full/stub text and BSS remain 157560/144886 and 80360/78760.
Core 33948114721, L2 33948114726 and staging 33948114731 PASS. Profile policy,
CLI conflict resolution and runtime wiring remain open; no staging parser is active.

### Rate-target compilation — PR #31, `da957069e07f833dd0450dec0ea6fa04c3a2d619`

`--no-rate-limit` target names now compile once into fixed protocol masks for exact
lowercase `all`, super-group or group names. Masks are filtered to current production
status, so staging/HOLD entries cannot be selected. Applying a target intersects it
with the already-enabled mask: it changes emission policy only and cannot activate a
parser or relax inspection/state budgets. Individual protocols retain the uppercase
selection convention rather than becoming rate-target names.

Tests pin target kind, case rejection, production filtering, invalid-target no-op and
identity/enterprise/all scope. Main, CLI, BPF and packet processing do not consume the
API yet; native full/stub text and BSS remain 157560/144886 and 80360/78760. Core
33948366691, L2 33948366700 and staging 33948366715 PASS. Runtime CLI/help
adoption remains open; no staging parser is active.

### Production profile and CLI namespace policy — PR #32, `4d9585fb0f1580ada1de39d5dfa4ab47dda8fd3f`

The six profiles now have exact production-filtered masks: core 7, standard 16,
full 67, home 36, enterprise 50 and sensor 67 protocols. Core and standard preserve
the existing default and `-a` bundles; enterprise preserves the current broad
50-protocol compatibility bundle instead of silently redefining it as the canonical
enterprise super-group. Stateful QUIC, sensor deployment and observed-identity modes
remain separate explicit controls. No profile can activate staging/HOLD protocols.

The namespace policy keeps `--enterprise`/`--enterprise-verbose` as v6 compatibility
options, uses `--profile enterprise` for the profile and `--super-group enterprise`
for the canonical super-group. Likewise `--group identity` selects identity protocols,
while `--identity[=hash|raw]` retains its privacy-mode meaning; `--profile sensor` does
not imply `--sensor` deployment mode. Tests pin exact counts, membership boundaries,
production filtering and invalid-name rejection. Main, BPF and packet processing remain
unchanged; full/stub text and BSS remain 157560/144886 and 80360/78760. Core
33961234603, L2 33961234596 and staging 33961234609 PASS. Startup CLI/help compilation
and runtime dispatcher adoption remain open; no staged parser became reachable.

### Startup selector compiler — PR #33, `2d0e41d1ad089d3cd94b6bd913b26b1d379babd4`

`argos_cli_selection_t` compiles profile, super-group, group, protocol, legacy and
no-rate selectors in argument order into fixed protocol/feature masks. A later profile
replaces the protocol/profile-feature base; explicit feature controls remain orthogonal
and survive that replacement. Later additive selectors extend the base, protocol case
retains last-overlap rate precedence, and no-rate targets affect only bits already active
at that point. Feature-only options do not suppress the historical default. Invalid and
staging/HOLD protocol names leave state unchanged; `group=identity` is distinct from the
observed-identity privacy mode.

This remains a startup contract API: main, getopt, BPF and packet processing do not consume
it yet. Tests pin size, profile replacement, explicit-feature preservation, defaults,
identity disambiguation, case/rate order and invalid no-op behavior. All 73 local strict
standalone tests passed; full/stub text and BSS remain 157560/144886 and 80360/78760.
Core 33961749975, L2 33961749932 and staging 33961750077 PASS, including sanitizers
and ARM64 compilation. Thematic help and controlled runtime CLI adoption remain open.

### Generated bounded help — PR #34, `b9b62ca7ebb5a724b513a425f467568d8361e464`

`argos_help.h` owns base, six canonical super-group/profile screens and focused
capture/output/rate/identity/performance topics. Membership and staging markers come
from the config catalogs and profile masks; the former 102-line main help literal was
deleted. Base help is 29 lines/1140 bytes and the generic `--help-protocols` path is a
bounded error. A preflight scan handles help/version before getopt or any Argos state,
capture, BPF or sink setup, independent of argument order.

Generated bounded-width help adds 6214 bytes full text and 2424 bytes data; full/stub
are 163774/152580 text, 3832 data and unchanged 80360/78760 BSS. This startup-only
cost prevents duplicate membership truth and does not enter packet processing. All 74
local strict tests passed; core 33962384705, L2 33962384687 and staging 33962384695
PASS with sanitizer and ARM64 compile gates. Runtime selector/dispatcher adoption and
executing-ARM64 byte-parity remain open; no staged parser became reachable.

### Canonical legacy runtime adoption — PR #35, `f630a19708d4e5ca2a49aa1f8dd53d965bcf8f9f`

Existing legacy category, default, all and enterprise options now compile into
`argos_cli_selection_t` and project once before capture into the unchanged coarse runtime
gates. IPv6, extended-metrics and stateful-QUIC parsing features project from the same owner;
sensor deployment is recorded there while its established deployment boolean remains direct.
Argument-order rate precedence and historical defaults remain exact. A permanent
source invariant rejects any selection-state access after `argos_capture_open`, so packet
processing performs no catalog scan or CLI-string work.

Qualified profile/super-group/group/protocol selectors are deliberately not exposed yet:
the current coarse enterprise gate could activate parsers outside a requested fine-grained
mask. They require the C4 per-engine dispatcher and disabled-engine call-counter tests first.
Full/stub text is 164710/152668, data 3832 and BSS 80360/78760; main stack remains 84944
bytes. Core 33966752299, L2 33966752376 and staging 33966752328 PASS, including
LeakSanitizer and ARM64 compilation. No staged parser became reachable.

### Fixed startup dispatch plan — PR #36, `3ed23e21067a245a010c709e41557d7d7b40b74e`

`argos_dispatch.h` owns a 48-byte startup plan containing fixed enabled/unrated masks,
feature bits and bounded L2/L3/L4 route flags. Main compiles it once after final selector
precedence and uses it for the existing legacy projection before capture. Catalogs, selector
strings and `cli_selection` remain absent after `argos_capture_open`; the fixed plan is the
only canonical config object permitted in packet processing.

`tests/test_dispatch_plan.c` exhausts every production protocol bit and uses parser/state
call counters to freeze the gate contract; staging/HOLD selection remains rejected. It also
pins legacy normal/unrated projection and representative L2/L3/L4 route demand. This does
not claim that all existing parser/state calls are already behind their individual bits;
that runtime adoption and canonical BPF projection remain the next C4 gate.

All 75 local strict standalone tests pass. Full/stub text is 165565/153555 (+855/+887 from PR #35),
data 3832 and BSS 80360/78760 unchanged. Core 33970212966, L2 33970212932 and staging
33970212929 PASS, including LeakSanitizer and ARM64 compilation. No staged parser became reachable.

### Native-L2 and non-port protocol gates — PR #37

Main now admits native-L2 frames and invokes ARP, LLDP/LLDP-MED, STP/RSTP/MSTP, LACP,
CDP/EDP/FDP/IS-IS, EAPOL and PROFINET parsers only through their individual canonical bits.
ICMPv6 distinguishes NDP from RA before calling their shared bounded parser; MLD, IGMP, OSPF
and VRRP likewise check their own bits. Each engine's unrated bit now supplies its exact dedup
mode. ARP/NDP owner tables are prepared only for enabled families, with IPv6 feature demand
still required so legacy `-L`/`-V` allocation behavior stays exact.

Catalog/selector state remains startup-only; a permanent source invariant requires each named
caller to have its canonical gate nearby. The exhaustive dispatch fixture pins every L2 wire
discriminator and enabled/unrated behavior. All 75 strict tests and full/stub builds pass;
transport ratios are 0.931 disabled and 0.914 enabled, network ratios remain 0.621–0.890,
and AH-disabled decode is 1.018 of frozen. Full/stub text is 166273/154211 (+708/+656 from
PR #36), data 3832 and BSS 80360/78760 unchanged. Core 33970823850, L2 33970823827 and
staging 33970823831 PASS, including LeakSanitizer and ARM64 compilation. BPF and remaining
TCP/UDP callers stay open; no isolated staging parser became reachable.

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

- Dedup is prepared during startup only when rate-limited output is enabled;
  absent/OOM state stays fail-open and packet calls never allocate or retry (PR #22).
- Network ownership is prepared at startup only for enabled L2 families; partial
  failure stays family-local/fail-open and ARP/NDP calls never allocate or retry (PR #23).
- QUIC owns one enabled-only startup workspace and its opt-in heavy session table;
  valid, invalid and stateful packet calls never allocate or retry (PR #24).
- TLS fingerprint hashing streams through fixed scratch and performs no allocation (PR #25).
- The audited production parsers/owners therefore satisfy **no malloc in the packet hot path**;
  complete budget/expiry/saturation coverage remains open before C2 can freeze.
- Future-dated application/SYN/dedup/network/QUIC entries fail open after clock rollback;
  DNS and UDP already used the same policy (PR #26).
- Preserve disabled-mode footprint by allocating enabled subsystem capacity at
  startup/explicit activation, before capture processing. If future JIT activation
  is required, request activation and return; prepare resources at a lifecycle
  boundary, never retry allocations for every packet. This is a design target,
  not current implementation.
- At the PR #19 baseline SYN state was module-static; repeated enable leaked old
  tables and destruction left dangling pointers. The lifecycle change below
  addresses this owner API, not every process-startup/sink cleanup path.

#### SYN/DNS lifecycle — PR #20, `8e38cde6c9702b11b1cb856c814abb6bfa38656f`

`argos_runtime_state_t` owns `syn_track` and `dns_track` independently of other
instances. Initialize to zero and never copy a live owner. Preparation/destruction
run only outside packet processing. Repeated successful enable preserves tables
and evidence without allocating. Preparation commits both tables only on success;
failure frees newly allocated scratch ownership immediately and preserves any
pre-existing table. A retry is explicit lifecycle work, never packet-time retry.
Destroy accepts NULL, frees owned SYN/DNS/dedup, and zeros the whole owner so a
restart cannot inherit fixed TCP DONE/UDP state. Borrowed entry pointers expire
at destruction. This API is not concurrent shutdown or thread synchronization.

`argos_syn_track_find` now takes the explicit owner; its caller must have gated
extended metrics and successfully prepared it. The four existing main calls
retain their `opt_syn`/`opt_ext_metrics` gates, with no new lookup guard or allocation.
SYN and DNS keys, probes, TTL and correlation behavior are unchanged. The DNS
parser/API, wire output, rate policy, CLI and staging integration are unchanged.

`test_state_lifecycle.c` intercepts allocation/free: both failure sites, immediate
rollback, preserved partial owners, retry, repeated enable/destroy, two independent
owners, fixed-state reset, first IPv4/IPv6 SYN/DNS evidence and zero allocations
during lookup/expiry. Optional SYN/DNS heap remains 65536 + 212992 bytes on native
64-bit; disabled ownership allocates neither. The owner grows one pointer while
the former global pointer disappears; total native BSS remains 80304/80296.
Main stack remains 84960 bytes; these are static measurements, not total RAM.

Alternatives measured: passing the table adds lookup argument overhead; passing
the owner allows compiler specialization. Inline preparation gives full text
156537, cold-hinted preparation 156489; explicit out-of-line startup preparation
gives 156433 (stub 143818), within unchanged full cap 156441. Versus PR #19:
+200/+124 text, no BSS increase. Native optimized SYN lookup has the same 303
instructions after relocation normalization. Core 33893211897, L2 33893211835
and staging 33893211837 PASS: strict standalone/native full+stub, ASan/UBSan/LSan,
ARM64 full+stub/lifecycle fixture compilation and unchanged size budgets.
ARM64 fixtures compile only; no new hardware performance claim.

#### Process startup cleanup — PR #21, `7e18fab414b56c73d9991974469a72c06c74d55f`

Main routes CLI/validation/state-preparation errors to shared state/sink cleanup.
After any capture-open attempt, it first closes the initialized capture owner;
early CLI errors never touch uninitialized capture storage. Normal shutdown closes
the optional netlink listener before joining the same cleanup. Existing exit codes,
packet loop, telemetry emission, BPF policy and protocol selection are unchanged.
Telemetry owns repeat-safe `argos_telemetry_close`: closes owned Unix/UDP descriptors,
invalidates them and resets enable flags; it does not close the stdout stream.
Replacement UDP options invalidate the old descriptor before fallible resolution,
preventing stale ownership/double-close. This does not make main reentrant or add
concurrent shutdown, and does not yet extract sink setup from CLI.

`test_startup_lifecycle.c` runs actual main/owners with fake syscalls/resolution,
tracked heap/descriptors and a fresh child process for each case. It covers CLI
validation after sink creation, initial/replacement sink failure, resolver failure,
both metrics allocation failures, capture epoll/list/socket/bind/registration
failures, optional netlink failures, SIGTERM shutdown, disabled metrics, repeated
sink close and owned descriptor zero. No raw socket privilege or external traffic.
The fixture is permanent in native, sanitizer and ARM64 compilation gates.
The same fixture fails against the prior main with live descriptors remaining.
Core 33894580958, L2 33894580816 and staging 33894580782 PASS, including
ASan/UBSan/LSan and ARM64 full/stub/fixture compilation (not hardware execution).
Native full/stub text is 156309/144022 (-124/+204), BSS unchanged at 80304/80296,
main stack 84944 (-16). Size budgets are unchanged; no throughput claim.

Remaining C8 work includes backpressure testing and sink setup extraction. Future
protocol inspection ceilings remain C5/C10 integration gates, not unfrozen ownership.

#### State capacity and saturation — PR #27, `ddaa7c73c81ee31245173aac3923f196afb9f918`

`V6_STATE_BUDGETS.md` is the authoritative current-production inventory. Compile-time
LP64/ARM64 assertions pin entry/table/control sizes; deterministic fixtures cover
application, UDP, SYN, DNS, dedup and IPv4/IPv6 collision saturation, plus QUIC
full-table drop, expiry reuse and completed-DCID reuse. Heavy QUIC drops new live
sessions at capacity rather than evicting active evidence. No runtime source, wire
format, state capacity or production binary size changed.

Core 33946696301, L2 33946696283 and staging 33946696275 PASS, including strict
full/stub, ASan/UBSan/LSan and ARM64 compilation. Native full/stub text remains
157560/144886 and BSS 80360/78760. The all-enabled/heavy listed owners total at
most 1,095,935 bytes excluding capture/kernel/transient stack. This freezes existing
retained-state ownership only; planned protocol `max_packets`/`max_bytes` remain
unverified C5/C10 requirements and staging integration remains blocked.

#### Dedup preparation — PR #22, `833849024c09b4064d9091bedf85f18545780801`

Baseline `6b186c4b16e80f25e65eaeb9060b85b320a54390`. Candidate
`argos_dedup_prepare` initializes the existing 2048-slot/eight-probe cache outside
packet handling. Repeated prepare preserves entries; destroy remains repeat-safe.
Main computes demand after legacy defaults/precedence: positive -f, at least one
rate-limited category/enterprise, and not live inspector (-z). -A/wholly verbose
and -f 0 do not allocate. Canonical bitmap/profile work is not implied.

Failure remains fail-open with one startup warning; packets never retry allocation.
This intentionally removes the old per-evidence allocation retry after OOM;
explicit lifecycle retry is possible outside packet processing. Enabled idle
instances now reserve 49152 bytes before first evidence, rather than lazily on it;
steady-state cache capacity, keys/hash, probes, fixed/sliding TTL and wire output
remain unchanged. PR #24 subsequently closes QUIC packet-time allocation.

`test_dedup_lifecycle` traps allocation on first/failed-cache evidence, checks repeat
prepare/destroy, independent owners, and 30000 decision/full-cache comparisons with
the frozen prior dedup algorithm, including saturation/collisions/clock rollback.
`test_startup_lifecycle` also checks actual CLI defaults, order, verbose/mixed,
enterprise, -f 0, inspector and fail-open startup policy. Existing owner tests now
prepare explicitly. These are not full capture throughput or all-owner acceptance.

Alternatives (native full text): inline 156921; bitwise demand 157033;
out-of-line prepare 157065; shared lookup 156581; cold prepare/shared lookup 156801.
Selected shared lookup retains the prior native shared-call boundary and removes
its allocator branch. Full/stub 156581/144106 (+272/+84 from baseline), unchanged
BSS 80304/80296; main stack 84960 (+16). User approved the 140-byte cap revision
156441 -> 156581, prioritizing CPU/latency and code quality over tiny text changes.
The structural benefit is removal of packet-time allocation/retry; no measured
capture-throughput gain is claimed. No staged protocol row becomes ready.
Approved candidate `4ea2a3764e664ba3b1dd56fdbe69a44e80c53c9a`: core 33896908802,
L2 33896908769 and staging 33896908794 PASS, including native full/stub,
ASan/UBSan/LSan and ARM64 full/stub/fixture compilation. The squash production
commit is the heading commit above. No ARM64 hardware execution or measured
capture-throughput claim.

#### Network ownership preparation — PR #23, `b799b791b8257e47eea8f0aa14ee2965d2efd6fd`

`argos_network_prepare_owners(state, want4, want6)` replaces packet-time ensure
calls. Main requests IPv4 only for enabled L2, IPv6 only for L2+IPv6, and neither
for live inspector/disabled L2. The families are independent: partial OOM retains
the available family and missing state remains fail-open without packet retries.
Repeated prepare preserves learned entries; destroy remains repeat-safe. Capacity,
four-probe lookup, 180-second TTL, replacement, routed classification and output
are unchanged. Enabled capacity is 8192 bytes IPv4 plus 5120 bytes IPv6.

`test_network_owner_lifecycle` traps first/failed-family evidence and checks repeat
prepare/destroy. The actual-main startup fixture verifies legacy flag precedence,
family selection, inspector bypass and partial failures. Core 33917508319, L2
33917508349 and staging 33917508313 PASS, including ASan/UBSan/LSan and ARM64
full/stub/fixture compilation. Native full/stub text is 156949/144438; BSS remains
80304/80296. No capture-throughput or ARM64 hardware-execution claim.

#### QUIC workspace ownership — PR #24, `76472e9dab2e47fcd30231c78fc653be7e7ab2e1`

`argos_quic_state_t` explicitly owns reusable packet, presence-map and ClientHello
scratch plus the bounded heavy session table. `argos_quic_prepare(state, heavy)` runs
after final CLI precedence and before capture: disabled TLS and live inspector allocate
nothing; enabled TLS reserves 81,919 bytes; TLS+`-W` additionally reserves the existing
593,408-byte/64-session table. Partial failure remains fail-open and lifecycle retry is
explicit; repeated prepare preserves state and destroy is repeat-safe. Heavy mode stays
runtime opt-in and its capacity/TTL/reassembly behavior is unchanged.

Stateless/stateful valid packets and invalid-tag packets perform no allocation or retry.
AES-GCM authenticates before CTR plaintext work, avoiding decrypt CPU on forged Initials.
The reusable byte presence map was retained to favor simple bounded operations over saving
roughly 7 KiB. `test_quic_lifecycle` covers successful stateless/stateful decrypt, tag
failure, allocation failures and repeat lifecycle with allocator traps. Core 33919266074,
L2 33919265965 and staging 33919266033 PASS, including ASan/UBSan/LSan and ARM64
full/stub/fixture compilation. Native full/stub text is 157024/144438; BSS is
80360/80296 (+75/+0 text and +56/+0 BSS from PR #23). This is a structural CPU/latency
benefit; no measured capture-throughput or ARM64 hardware-execution claim.

#### TLS fingerprint streaming — PR #25, `fe2d8ca55622540c5377fe0c664de2e673d6ed16`

The JA4-like MD5 helper now processes complete 64-byte input blocks directly and
uses only a bounded 128-byte final-padding buffer. It removes the former 8 KiB
whole-message copy/zero buffer and conditional packet-time `calloc/free`; output
remains byte-compatible. A shared compression boundary avoids duplicated code.
Standard vectors plus 55/56/63/64/65-byte padding boundaries and 2047/4095-byte
production input bounds are permanent fixtures; the adoption check rejects allocator
or large-buffer reintroduction. The MD5 stack frame is 352 bytes versus 8480.

Core 33920067953, L2 33920067902 and staging 33920068034 PASS, including all strict
fixtures, ASan/UBSan/LSan and ARM64 full/stub/fixture compilation. Native full/stub
text is 157384/144790 (+360/+352); BSS is unchanged at 80360/80296 and no persistent
RAM was added. Direct block processing avoids the former whole-input memory work;
this is structural evidence, not a measured capture-throughput claim.

#### Clock rollback and QUIC success ownership — PR #26, `a32c4011733c60e90024027d5f854c227e4481f1`

Application DONE, SYN correlation, emitted-record dedup, IPv4/IPv6 ownership,
QUIC reassembly and QUIC success suppression now invalidate future-dated entries
when wall time moves backward. This matches the existing DNS/UDP fail-open policy
and prevents stale suppression/ownership from surviving until the clock catches up.
Existing TTL boundaries, keys, probes, capacities and normal monotonic behavior are
unchanged. The existing 64-slot direct-mapped QUIC success cache moved from main into
`argos_quic_state_t`; collisions still replace one slot and destroy clears it.

Deterministic fixtures cover rollback, TTL boundaries, collision and destroy behavior;
the dedup oracle retains 30000 exact monotonic legacy-equivalence cases. Core
33921014158, L2 33921014199 and staging 33921014217 PASS, including ASan/UBSan/LSan
and ARM64 full/stub/fixture compilation. Native full/stub text is 157560/144886
(+176/+96); full BSS stays 80360 and stub BSS falls 80296→78760 because the unrelated
global cache is absent in stub mode. No new state, allocation, probe or throughput claim.

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
  initialized capture owner. PR #21 above covers process startup state/sink cleanup;
  packet-time allocation is closed by PR #22–24; full budget/expiry/saturation coverage remains open.
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

**PR #17 baseline blocker — BPF capacity:** exhaustive 10-boolean configuration
fixtures find 212/1024 builds fail at the existing 256-instruction limit with
WireGuard port zero. All categories enabled plus WireGuard 51820 also fails
(e.g. `-a --enterprise`, not `-a` alone). On the applicable fixed-Ethernet capture
path this prevents prefilter attachment; packets still undergo userspace gates.
No memory overrun was observed: builder bounds reject the partial program.
Resolved by PR #18 below; fixtures now require every legacy mask to build.
New protocol gates still require separate reachability/ownership review.

BPF repair merged as PR #18, `a366b60e3a32447a1a951048ef43315bd355f45b`: four port lists
use one shared ACCEPT return, with startup-only bounded jump fixups in the existing
instruction array. No heap/fixup array, capacity increase or per-packet C change.
All 1024 masks × seven representative WireGuard ports fit: maximum 185 versus
287 intended legacy instructions. The test-only frozen legacy generator has 512
slots solely to compare intended policy for configurations that previously failed;
production remains capped at 256. 7,239,680 frame comparisons preserve exact
ACCEPT/DROP and executed-instruction counts, including empty TCP ACK/control,
STUN/TURN exceptions, source/destination ports, non-port IP and encapsulation.
This restores prefiltering where overflow formerly forced unfiltered capture;
it does not claim the formerly failing configuration had a working kernel filter.

`tests/test_bpf_capacity.c` exercises actual kernel verifier/attach and filtering
on local datagram sockets for all 1024 masks with default WireGuard, including
truncation and a rejected invalid jump. It is not AF_PACKET/hardware throughput.
The shared test interpreter now rejects out-of-range loads immediately, matching
the kernel rather than supplying a zero value and continuing. Canary tests protect
the fixed instruction capacity. Capture mocks verify attachment selection,
invalid-config and syscall failures, warning/continue compatibility and repeat-safe
close. Build failure returns a deterministic errno and never attaches partial
instructions; the existing warn-and-continue capture policy is unchanged.
Native full/stub text 156233/143694 (+16/+18); BSS 80304/80296 unchanged.
GCC stack-use reports unchanged attach 2688, capture-open 208, main 84960 bytes;
these are static frame reports, not total-memory or throughput measurements.
Core 33890379876, L2 33890379859 and staging 33890379875 PASS: strict standalone,
native full/stub, ASan/UBSan/LSan, ARM64 full/stub and fixture compilation, unchanged
size budgets. ARM64 fixtures compile only; hardware acceptance remains open.

**First-AH API — PR #19, `775ffbbb772d79fea87cc5e6436eabe1c6c4554f`:** packet normalization owns
framing via `argos_packet_decode_with_ah(..., argos_packet_ah_view_t *out)`.
`out` is optional caller-owned offset/length populated in the same bounded IPv6
walk; IPv4 uses its existing L4 offset. Packet decode success and AH presence are
separate: a successful packet can have empty AH evidence. NULL preserves legacy
decode. `ip_protocol/l4_offset` terminal semantics and the main caller are unchanged.
No packet-wide list, payload copy, allocation, protocol result fields, state lookup
or new per-flow tracker. Offsets borrow the capture buffer and expire with it.
The sidecar must not overlap the packet view or capture buffer.

First-only coverage is explicit: an invalid first AH cannot be replaced by a
valid later AH. No recursive tunnel inspection or invented ports. Output is
cleared on every request and remains empty on decode failure, including AH→59,
later malformed extensions and depth exhaustion. Partial-success evidence needs
a separate reviewed API. Nonfirst fragments never supply AH evidence; only
complete bounded headers on admitted first/atomic fragments can supply framing,
never authentication verification or reassembly.

AH framing length follows [RFC 4302 §2.2](https://www.rfc-editor.org/rfc/rfc4302.html#section-2.2).
The legacy IPv6 walker accepts an eight-byte AH, whereas the isolated parser
requires at least twelve; neither currently enforces IPv6's eight-byte alignment.
The new evidence adapter validates those bounds without changing legacy terminal
dispatch. Neither SPI/sequence extraction nor a valid length
proves AH integrity. No ICV/key material may become observation storage.

`tests/test_packet_ah.c` compares every tested decode/view with a test-only frozen
PR #18 decoder: 17,884,886 checks across six link wrappers, both alignments and IP
versions, all AH lengths/capture truncations, declared bounds/padding, repeated/mixed
chains, first/nonfirst/atomic fragments, absent/disabled/null/failure paths. Main
does not call the new API; staging AH remains isolated and still needs adaptation
to version-validated framing. This is not non-port BPF/dispatch integration.

Local native full/stub text 156233/143694, BSS 80304/80296 and main stack 84960
remain unchanged. Packet view remains 88 bytes; optional sidecar 8 bytes versus
96 bytes for an inline-field alternative. `bench_packet_ah.c` uses the same API
for the inline alternative (not another parser). Initial compiler sharing caused
a disabled-path slowdown; explicit internal inlining and independent NULL entry
specialization removed it. Repeated local disabled/frozen ratios are near 1.0;
benchmark timings are diagnostic, not a noisy wall-clock CI threshold. Native
production disassembly differs only by an equivalent comparison direction, not
extra AH instructions. Core 33891626373, L2 33891626349 and staging 33891626357
PASS: strict standalone/native full+stub, ASan/UBSan/LSan, ARM64 full+stub and
fixture/benchmark compilation, unchanged size budgets. CI disabled/frozen decoder
ratio 0.999 (8.113/8.122 ns); optional enabled 14.689 ns, inline alternative
14.758 ns. ARM64 fixtures/benchmark compile only; real ARM64 performance and
capture/hardware throughput remain separate release gates. This framing API is
delivered, but the full packet contract and integration-readiness review remain open.

PTP adapters should supply the same bounded message slice to the existing parser:
native `[l3_offset,packet_end)` or UDP's declared payload. Use one protocol enable
bit before parser/state access. A WireGuard custom port of 319 or an unrelated
enabled port can incidentally admit the tuple today; this is not PTP integration.
PTP common-header metadata is not full message-specific validity, and its staging
result's clock/sequence/correction fields are not frozen fingerprint inputs.

Current fixtures cover all-mask non-port admission and bounded builder failure,
raw/Ethernet/VLAN/QinQ/PPPoE/SLL compatibility, alignment/truncation/padding,
AH length fields/mixed chain/header loss/fragments and one isolated PTP parser
across native/UDP4/UDP6. PR #18 repairs interpreter out-of-range loads and adds
kernel verifier/filter checks; neither step is AF_PACKET throughput or end-to-end emission coverage.
Merged as PR #17, `2ac259284e5481d65ba852d943a000d2b24bfd32`. Core 33874404696,
L2 33874404652 and staging 33874404676 PASS: strict standalone/native full/stub,
ASan/UBSan/LSan, ARM64 full/stub/fixture compilation and unchanged size budgets.
At PR #17, 241,362 characterization checks passed; BPF failures were characterized,
not waived (subsequently repaired in PR #18). Its native full/stub binaries were byte-identical to PR #16 (hashes in merge
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

All staged protocols in the master matrix are intended for v6 runtime integration. This review
chooses the safe order, canonical owner and required adaptations; it is not a later decision about
whether those protocols will be included. HOLD dependencies must be closed before their rows ship.

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
No dependency is waived by a protocol's position in that sequence, and no staged protocol may be
silently omitted from v6 because its integration requires adaptation.

## Missing acceptance tests before final readiness review

- Frame fixtures for STP/RSTP/MSTP, native+UDP PTP, IPv4/IPv6 AH/ESP, fragments,
  VLAN/QinQ/PPPoE, raw/cooked/unsupported links and ancillary VLAN/timestamp data.
- Allocator interception after startup covers successful/failing QUIC decrypt and
  dedup/ARP/NDP first/failed evidence with zero packet-time allocations (PR #22–24).
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
