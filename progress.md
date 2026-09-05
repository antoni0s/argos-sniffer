# Argos Sniffer v6 — progress

Branch: `version-6`. Verified checkpoint: `cc526e5e8fae89b61d0d052758101122024073a6` (PR #53).
**Now:** RTP/RTCP trigger, owner and privacy audit on `v6-rtp-canonical-integration`; dynamic-port admission must be frozen before parser wiring.
The application-control milestone (LPD, HTTP proxy, Telnet, VNC and WinRM) is merged.
**Not yet:** full core freeze or all staging runtime integration. Isolation is temporary: every staged
protocol listed for v6 must be integrated before the v6 release after its readiness gates pass.

## Done — high-level history

- [x] WinRM native HTTP/HTTPS observation, exact TCP 5985/5986 gates,
  credential/body exclusion, generated help and staging cleanup — PR #53.
  Core 33992514050, network 33992514060, L2 33992514107 and staging 33992514174 PASS.

- [x] VNC/RFB 3.3/3.7/3.8 cross-direction handshake, native privacy-safe
  signatures, optional bounded context, generated help and staging cleanup — PR #52.
  Core 33991432852, network 33991432814, L2 33991432837 and staging 33991432821 PASS.

- [x] Telnet native negotiation, independent TCP/SYN gates, generated help and
  staging cleanup; agreed product name restored — PR #51.
  Core 33987508144, network 33987508102, L2 33987508097 and staging 33987508060 PASS.

- [x] HTTP proxy integrated with native output, independent shared-port/SYN gates,
  bounded privacy-safe headers, web/application help and staging cleanup — PR #50.
  Core 33985969924, network 33985969976, L2 33985969932 and staging 33985969984 PASS.

- [x] LPD runtime integration with native output, printing/application help,
  inspect-once bounds, staging cleanup and frozen BPF oracle — PR #49.
  Core 33984221086, network 33984221081, L2 33984221082 and staging 33984221091 PASS.
- [x] Management exporters integrated with native vectors and staging cleanup — PR #48;
  core 33982645819, network 33982645829, staging 33982645897 and L2 33982645803 PASS.
- [x] TLS/QUIC consolidation and enterprise/L2 fingerprint foundations.
- [x] Observed identity, hash/raw modes and RDP/NTLM privacy hardening.
- [x] Discovery, compile-once filters and network/prefix/netlink extraction.
- [x] TCP DONE/UDP suppression/dedup modules and SYN/DNS lifecycle facade.
- [x] Capture lifecycle extraction and permanent native/ARM64 gates — PR #6.
- [x] 37 protocol + five enrichment/policy staging modules kept isolated; fixture/isolation gates.
- [x] STP/RSTP/MSTP normalization repair — PR #7.
- [x] Core audit, master matrix and persistent progress/update instructions.
- [x] Bounded transport API and TCP/UDP runtime adoption; equivalence/frame/sanitizer/native/ARM64 gates — PR #8–9.
- [x] Capture ancillary bounds, startup failure cleanup and repeat-safe close — PR #10.
- [x] Sink-owned legacy VLAN/OBS context — PR #11.
- [x] Runtime network policy ownership and single-scan routing; reviewed size tradeoff and all gates — PR #12.
- [x] IPv4/IPv6 fragment and extension-chain decode→transport boundary matrix; permanent sanitizer/ARM64 gates — PR #13.
- [x] User removed obsolete merged branches; exact remote check retained only main/version-6 before the next gate.
- [x] Live link-type/receive ownership matrix and SLL address identity bounds; red→green/permanent gates — PR #14.
- [x] Normalized inspector/shared TCP framing and network-owned bounded router admission; golden/equivalence gates — PR #15.
- [x] PPPoE/LLC declared-length bounds and canonical discovery padding exclusion; exhaustive fixtures/permanent gates — PR #16.
- [x] Non-port/AH/PTP source characterization, bounded fixtures and ownership design; existing BPF capacity blocker identified — PR #17.
- [x] BPF capacity repair without cap/stack increase; policy equivalence, kernel attach/filter/failure tests and permanent gates — PR #18.
- [x] Optional first-AH framing ownership, unchanged terminal decode/view and disabled cost; frozen equivalence/sanitizer/native/ARM64 gates — PR #19.
- [x] Instance-owned SYN/DNS, transactional preparation and repeat-safe reset/destroy; failure/allocation traps and permanent gates — PR #20.
- [x] Process startup failures unwind state/capture/sinks; telemetry-owned repeat-safe close and actual-main fault gates — PR #21.
- [x] Enabled-only dedup preparation removes allocation/retry from packet handling; lifecycle/equivalence gates — PR #22.
- [x] Enabled-family network ownership preparation removes ARP/NDP allocation/retry from packet handling — PR #23.
- [x] Enabled-only QUIC workspace/session preparation removes packet allocations and rejects forged tags before decrypt work — PR #24.
- [x] Streaming fixed-stack TLS fingerprint hashing removes the last audited parser allocation and ~8 KiB MD5 stack — PR #25.
- [x] State clock rollback fails open consistently; QUIC success suppression moved into its explicit owner — PR #26.
- [x] Current production owner capacities, byte costs, saturation/eviction and tuple reuse are pinned and inventoried — PR #27.
- [x] Canonical 101-protocol IDs, fixed bitmap and 6-super-group/28-group membership catalog — PR #28.
- [x] Production-only enabled/unrated masks, last-overlap precedence and safe no-rate-limit semantics — PR #29.
- [x] Exact legacy short/default/all/enterprise bundles and separate non-protocol feature controls — PR #30.
- [x] Production-only compile-once no-rate-limit targets for all/super-group/group — PR #31.
- [x] Exact production-only profile masks and CLI namespace/compatibility policy — PR #32.
- [x] Startup selector compiler contract with explicit-feature/profile precedence — PR #33.
- [x] Generated bounded help owner and pre-runtime help/version paths — PR #34.
- [x] Existing legacy CLI/default/all/enterprise/features compile through canonical masks once before capture; coarse runtime behavior remains equivalent and selection state cannot enter packet processing — PR #35.
- [x] Fixed 48-byte startup dispatch plan derives bounded L2/L3/L4 route demand from canonical masks; exhaustive bit/call-counter fixtures keep disabled protocols outside parser/state work — PR #36.
- [x] Native-L2 and non-port network callers use individual canonical bits before parser work; ARP/NDP owner allocation and per-engine rate mode follow the fixed plan — PR #37. BPF and port-driven callers remain open.
- [x] Canonical dispatch routes project once into classic BPF with independent L2/L3 admission,
  frozen legacy decisions and conservative encapsulation fallbacks — PR #39.
- [x] Exact enabled-engine TCP/UDP ports replace coarse BPF families; frozen legacy matrix,
  lower verifier length/work and independent shared-port aliases — PR #41.
- [x] Qualified profile/super-group/group/protocol/no-rate selectors compile once before capture;
  source-truth audit keeps no-op LLMNR staged and mandatory for v6 — PR #42.
- [x] Fixed native/UDP PTP and ESP/AH no-port readiness routes with staging/HOLD isolation — PR #43.

## How to update — mandatory

- Preserve the agreed product title `argos-sniffer v6.0`, subtitle
  `Passive network fingerprinting & telemetry engine`, executable `argos-sniffer`;
  keep the development build explicit. Review naming with progress/help/cleanup.

- Exact-check remote HEAD; read affected source and all documents in `AGENTS.md`.
- Work in dependency order below. Mark only the active item **NOW**.
- Tick only delivered, verified scope: fixtures/malformed/truncation → sanitizers →
  native full/stub + ARM64 → production → cleanup. Record actual evidence, not assumed tests.
- Source length is not a correctness/performance budget. If important architecture work exceeds
  compiled-size limits, test reasonable alternatives and present benefit, measured text/RAM/runtime
  costs and a recommendation. Small justified code-size growth is accepted when it improves
  CPU/latency, boundedness or ownership; report and revise the guard with evidence instead of
  escalating every few bytes. Significant RAM/hot-path costs still require review. Never trade
  runtime quality for cosmetic byte savings; distinguish measured speedups from structural benefits.
- On completion, move/summarize the item in **Done**: one short outcome + PR/commit.
  Remove transient logs, failed attempts and repeated implementation notes from this file;
  preserve evidence in Git/PR/tests and unresolved requirements in open tasks.
- A consolidation is not complete while an obsolete implementation/header remains. After
  canonical adoption and full gates, delete superseded source/staging files and temporary tests;
  first move every unique fixture/assertion into the permanent canonical test suite. Verify no
  include, build, workflow or documentation reference remains. Never keep duplicate parsers.
- Split partial tasks; do not tick an entire group until every named requirement is satisfied.
  Carry residual work forward explicitly, then proceed to the next dependency-safe task.
- Reconcile all four backlogs/matrix plus the core audit after each step. Every new
  requirement must join a named open item here; no silent removal, forgotten holds or
  promotion of planned values to facts. When source specs change, review their diff.
- Before handoff, update **Now / Next / Blocked**, actual production checkpoint and pending PRs.
  Do not invent the containing commit's SHA. Reopen regressions. No automatic background work implied.

## Core work — in dependency order

### C1. Packet / capture / normalization

- [ ] Lossless VLAN presence/equal-tag/overflow policy needs schema approval.
- [ ] No-port IPv4/IPv6 dispatch/BPF and first-AH API adoption after canonical enable bits (C3/C4);
  PTP dual-path integration is complete; ESP/AH remain HOLD pending runtime adapters and AH sidecar
  ownership. Thread stays HOLD until raw
  IEEE802.15.4/6LoWPAN capture is defined. C1 remains open across those dependencies.
- [ ] Freeze packet/capture only after complete frame-to-observation reachability coverage.

### C2. Bounded state / lifecycle

- [x] Remove packet-time QUIC scratch/state allocations; prepare only enabled capacity outside
  packet handling; heavy QUIC remains opt-in/default cheap.
- [x] Existing production retained-state capacities, expiry/rollback, collision/eviction/saturation,
  tuple reuse and native/ARM64 byte budgets are frozen in `V6_STATE_BUDGETS.md`.
  Per-protocol inspection ceilings remain explicitly under C5/C10; no unbounded retained payload.

### C3. Config / bitmap / help

- [x] Single protocol IDs and shared SUPER GROUP → GROUP → PROTOCOL catalog; profile names are
  reserved. All 101 canonical protocols use a fixed 16-byte bitmap; NFS/NTLM multi-membership
  resolves to one bit and cannot duplicate parsing/emission.
- [x] Separate enabled/unrated masks; production-only activation, lowercase normal/UPPERCASE
  unrated last-overlap precedence, and no-rate-limit affecting only already-enabled protocols.
- [x] Exact legacy short-category/default/`-a`/`-A` mappings and separate controls for SYN,
  IPv6, extended metrics, stateful QUIC and sensor deployment; existing options consume them once
  before capture through the canonical selection owner.
- [x] `--no-rate-limit=<all|super-group|group>` target compilation is exact lowercase,
  production-only, runtime-exposed and can modify only already-enabled protocols.
- [x] Exact production-only profile contents and naming/conflict policy: broad compatibility
  `--enterprise`, canonical `--super-group enterprise`, and `--profile enterprise`. Sensor evidence
  profile stays separate from deployment mode; no implicit identity/heavy/staged activation.
- [x] Startup compiler API covers profile/super-group/group/protocol/legacy/no-rate order,
  `--group identity` namespace and default/explicit-feature precedence. Existing legacy options and
  qualified selectors are runtime-adopted before capture through the fine-grained C4 dispatcher.
- [x] One-screen base help (29 lines/1140 bytes); no `--help-protocols`.
  Generate `--help-profiles`, `--help-network`, `--help-application`, `--help-enterprise`,
  `--help-industrial`, `--help-iot`, `--help-vpn` from the same runtime tables.
- [x] Operational help: `--help-capture` (interfaces, -r/-R, promisc/count, sensor/filter/encapsulation);
  `--help-output` (Unix/UDP/stdout fan-out, approved grammar/JSONL/compatibility);
  `--help-rate` (actual compiled -f default, dedup/unrated);
  `--help-identity` (modes/allowed fields/prohibited secrets);
  `--help-performance` (-E/-W, defaults/allocation costs, promoted flow-shape only).
- [x] Help tests: exact per-screen/profile membership/no drift, real defaults, generated staging
  markers, bounded unknown-topic error, cheap `--version`, and zero Argos capture/state/sink setup.
- [ ] Native/ARM64 help-output byte parity on an executing ARM64 runner; release-time marker audit.

### C4. Cheap dispatch / gates

- [x] Existing legacy CLI selections project from canonical fixed masks once before capture with
  preserved defaults/rate precedence; no CLI strings or selection state enter packet processing.
- [x] Derive a fixed startup L2/L3/L4 route plan without packet-time catalog/string scans;
  exhaustive production-bit fixtures prove the protocol gate itself skips simulated parser and
  state calls. This is the control contract, not proof that every main-loop caller uses it yet.
- [x] Project canonical demand into BPF while preserving safe VLAN/QinQ/PPPoE/IPv6
  fallbacks and frozen legacy accept/drop behavior.
- [x] Adopt the plan before each current TCP/UDP production parser/state call. Shared ports
  resolve through bounded owner switches; TLS/DoT parse once but emit/rate on independent bits.
- [ ] Wire existing production engines to bitmap: network/addressing/discovery; TLS/DoT/QUIC/HTTP;
  L2/routing/redundancy; enterprise/storage/database/identity/management; industrial/IoT/VPN.
  Golden output unchanged; kernel early-drop preserved.
- [ ] Benchmark packets/sec, loop latency, text size, disabled-feature cost and AF_PACKET drops.
  Local fixed-port dispatch and text/disabled-cost evidence is complete; capture throughput,
  loop latency and AF_PACKET drop counters still require the hardware gate.

### C5. Suppression / dedup / fast-complete

- [ ] Audit all production/staged protocols for elephant exposure and unnecessary continued parsing.
  Matrix: trigger/evidence packets, completion/drop reasons, packet/byte/state ceilings, timeout,
  identity value and privacy. Include TLS/DoT/QUIC/HTTP/SMB/NTLM/RPC/NFS/RDP/SSH/databases/
  LDAP/media/exporters/industrial/VPN.
- [ ] Preserve directional DONE/SYN reset, completion packet emission, later identity evidence;
  UDP fixed epochs versus fixed/sliding emission dedup. Unrated output never removes safety budgets.
- [ ] Remove repeated TLS completion parsing; reconcile fast-complete staging with existing owner.
  Bulk-tail invariance and long-elephant benchmarks; policy debug uses aggregates, not per-flow spam.

### C6. JIT / scheduling / feed state

- [ ] Define demand activation outside packet handling, immutable config epoch, feed-state lifecycle,
  bounded GC/maintenance quotas and overload behavior. No implied runtime code generation/new tracker.

### C7. Observation / schema / JSONL / collector

- [ ] Inventory cross-protocol semantic fields and inconsistent names; canonical protocol/role/phase/
  capabilities/identity/product/fingerprint/completion, while preserving protocol-private evidence.
  Map collector needs to minimum sensor fields; observations own bounded data, not packet pointers.
- [ ] Freeze vector names (SMB2→SMB, SMB2-NTLM→NTLM, ORACLE-TNS→ORACLE, SNMPV3-USM→SNMP);
  exact required/optional fields for every candidate vector in the master matrix; ordering,
  escaping/missing values/string-list caps and per-vector privacy. No current wire cutover yet.
- [ ] JSONL/streaming: valid escaping/control-byte handling, truncation/newline guarantees,
  partial-write/EAGAIN/slow or closed stdout tests; bounded backpressure policy.
- [ ] Collector-first dual legacy/canonical acceptance, equivalent normalized inventory records,
  every-vector mapping fixture and unknown-field compatibility; sniffer legacy ENT mode without
  duplicate evidence. Verify deployed collector before cutover; one-release window, remove old
  parser only in a major schema transition.

### C8. Telemetry boundaries

- [ ] Sink setup/close API owns Unix/UDP/stdout transports; engines never own transport/queues.
  Explicit stdout blocking/drop policy, bounded buffering/counters, fan-out and feedback-loop tests.

### C9. Helper/API cleanup

- [ ] Fold tls_ports/enterprise_ports/raw_identity into justified owners after consumers settle;
  BPF must not import parsing implementations. Common types/utilities only for truly shared concepts.
- [ ] Main becomes capture→normalize→gate/dispatch→bounded engine→observation→identity/telemetry.
  Cohesive engines, no one-header-per-protocol; final packet-loop/allocation/cache/memory/privacy audit.
- [ ] For every consolidation, migrate unique fixtures, delete superseded headers/implementations
  and temporary tests, then prove no include/build/workflow/doc reference remains. Never keep
  duplicate or dead parsers; file removal is part of the same completion gate.

### C10. Acceptance and final readiness review

- [ ] Per-step native full/stub, ASan/UBSan, ARM64, malformed corpus, performance/size and isolation gates;
  end-to-end reachability, disabled-cost, allocation, lifecycle/saturation/expiry and golden output tests.
- [ ] For EVERY production or staged protocol verify: cli_bit, group_membership, super_group_membership,
  owner_file, entry_function, trigger, bpf_gate, state_owner, vector, required_fields, optional_fields,
  fingerprint_inputs, max_packets, max_bytes, state_bytes, timeout_ms, complete_when, drop_when,
  privacy_assertions, fixtures, collector_mapping. No planned owners/triggers treated as facts.
- [ ] Eight-part exit review: frozen contracts; exact source/API changes; immediately ready parsers;
  adaptations; holds; safe order; newly exact matrix entries; missing tests. No mass integration before
  this; the review controls safe order and required adaptations, not whether staged v6 protocols ship.

## After core freeze — integration order

All staged protocol engines below are committed v6 scope, not optional future ideas. Each item requires
ALL C10 row fields, CLI/help/BPF, budgets/fast-drop/privacy, collector/vector fixtures and gates;
fold/remove temporary staging headers only after canonical ownership is proven. HOLD means its named
dependency must be resolved before integration, not that the protocol is dropped from v6.

- [x] Reconcile LLDP-MED/LACP/STP fixture-by-fixture with canonical L2; one runtime parser and
  protocol-native vectors; duplicate staging headers removed.
- [x] PTP native/UDP integration; canonical network owner and obsolete staging cleanup.
- [x] RIP/RIPng: canonical `argos_network.h` owner, exact UDP 520/521 dispatch/BPF,
  native privacy-safe `RIP|...` output, permanent fixtures and staging-header removal.
- [x] Syslog/NetFlow/IPFIX/sFlow: canonical enterprise owner, native non-`ENT`
  signatures, exact TCP/UDP dispatch/BPF, bounded header-only fixtures and staging cleanup.
- [x] HTTP proxy runtime/code slice delivered as PR #50; deployed collector
  mapping remains open under C7/C10.
- [x] Telnet runtime/code slice delivered as PR #51; deployed collector mapping
  remains open under C7/C10.
- [x] VNC runtime slice merged in PR #52; deployed collector mapping remains
  open under C7/C10.
- [x] WinRM runtime slice merged in PR #53; deployed collector mapping remains
  open under C7/C10.
- [ ] LPD runtime/code acceptance is tracked by PR #49; deployed collector
  mapping remains open under C7/C10, so full protocol acceptance is not claimed.
- [ ] RTP/RTCP/RTSP/Cast/AirPlay/DLNA.
- [ ] FTP/NVMe-TCP/MongoDB/Redis/TACACS+/LDAP/LDAPS.
- [ ] KNXnet-IP/S7comm/OPC-UA/DNP3.
- [ ] Matter; Thread HOLD on capture semantics.
- [ ] OpenVPN/IKE; ESP/AH HOLD on no-port dispatch/BPF.

## Enrichment — explicit dependencies and acceptance

- [ ] After TLS/public-observation freeze: audit current coverage, reuse ClientHello/ServerHello parser;
  decide official JA4S-compatible vs Argos-native (not frozen), raw component order/GREASE rules.
  Client version/JA4/ALPN/SNI + ECH/PSK/modes/early_data/versions; server version/cipher/ext_count
  + visible ALPN/HRR/PSK/early_data/ECH/extensions. Distinguish offers from negotiated/visible facts.
- [ ] Realistic sanitized TLS1.2/1.3, HRR/ECH/resumption-PSK/0-RTT fixtures; per-direction packet/byte
  caps and exact completion; preserve JA4/privacy; text-size and hot-path benchmark before promotion.
- [ ] Certificate-lite: framing present/chain_count/leaf_len/truncated; leaf CN/issuer/self-signed hint,
  bounded SAN/count/truncation, validity, optional approved leaf hash. Decide vector ownership;
  realistic visibility/full positive DER fixtures; never retain/emit certificate chains or key blobs.
- [ ] All enrichment outputs: vector owner, required/optional field caps, deterministic fingerprint
  ordering/noise exclusion; stability under irrelevant changes and discrimination under meaningful
  changes; privacy/completion/malformed/collector fixtures; native/sanitizer/ARM64/performance gates.
  Exclude SNI/session IDs/SPIs/sequence/timestamps/random/hostnames from implementation fingerprints
  unless explicitly relationship evidence; textual certificate tuples are not cryptographic identity.
- [ ] Flow-shape EXPERIMENT only after state freeze: reuse ownership without coupled lifetimes;
  costs for 128/256/512/1024 flows and 2/4/8 samples/direction; saturation/truncation/expiry,
  deterministic direction-size fixtures, bounded counts/bytes/transitions/coarse timing.
  No payload/high-resolution traces/ML/new tracker; default OFF; benchmark enabled/disabled;
  reject if disabled cost measurable or enabled cost disproportionate. Collector owns correlation.
- [ ] Active enrichment POST-v6/default OFF: request/result contract and separate owner/process decision;
  passive confidence→wait/targeted-probe policy; narrowly scoped IPP/HTTP HEAD/UPnP/SNMP metadata
  only with external credential policy; explicit opt-in/rate/safety limits. No generic scan/cloud/
  write operations in packet path; no credentials/arbitrary bodies or silent overwrite of passive evidence.

## Release gates

- [ ] Retire temporary gates after their final use; retain `main` and active `version-6`.
  Re-check exact heads/open PRs before deletion. Final `version-6` → `main` only after release gates.
- [ ] Legacy/canonical golden corpus and sanitized real-PCAP optional/vendor-field acceptance.
- [ ] Native Linux gateway; SPAN/TAP including VLAN/QinQ/unnumbered NIC; real constrained OpenWrt ARM64.
- [ ] Long-run bounded memory/expiry and burst/drop comparison to pre-architecture baseline.
- [ ] Documentation/changelog/compatibility matrix and 6.0.0-rc1 checklist.

## Coverage / handoff

Coverage map: V6_BACKLOG phases 1–5→C1–C5/C9; phase 6→C7; phases 7–8→integration;
phase 9→release. V6_HELP_BACKLOG→C3. V6_SENSOR_ENRICHMENT_BACKLOG→C5/C7/enrichment.
V6_PROTOCOL_INTEGRATION_MATRIX→C3/C10/integration; V6_CORE_CONTRACTS→C1–C10.
Detailed protocol field tables remain authoritative specifications, not duplicate prose here.

**Next:** freeze RTP/RTCP dynamic-port admission, ownership, native field/privacy
and completion policy before wiring. Do not broaden UDP capture merely to find
RTP; prefer signaling-derived or another bounded startup/runtime gate with measured
disabled/enabled cost. Preserve progress/help/naming/cleanup.
**Blocked:** full freeze, deployed collector compatibility and hardware acceptance;
Thread, ESP/AH and TLS enrichment retain their recorded gates.
**Delivery:** VNC is integrated in the existing handshake/control owner with
progressive native VNC records and no ENT wrapper. Exact TCP 5900..5999 gates and
startup-only optional context track confirmed RFB 3.3/3.7/3.8 server/client phases,
security types 1/2, ClientInit and ServerInit. Exact sequence, eight payloads per
direction and 1,024 bytes/message bound each retained generation. Immediate
full-range retransmits do not emit; gaps/overlaps/wrong direction, unsupported or
failed security, invalid/truncated framing complete the context without output.
Challenges, auth responses, failure reasons and framebuffer data are not inspected
or retained. Server name is accepted only after the handshake and capped/sanitized.
The existing application owner grows from 57,344 to 57,352 inline bytes (one
pointer); 16,384 bytes allocate only when VNC is selected. Runtime inline becomes
71,712. No second flow table, packet-time allocation or reassembly. Allocation
failure aborts before capture; expiry/eviction/SYN reset and destroy clear context.
Catalog-derived help removes the VNC marker; full/sensor count is 76 and home stays
38. The agreed product name/subtitle remain pinned in help/version/README tests.
Measured full/stub text is 193334/181386 (+4330/+4408 from PR #51), data 3992 and
BSS 80360/78760 unchanged. Main stack is 85,024 (+16); VNC parser frame is 368.
Reviewed full-text ceiling 193400. The growth buys direction/phase/sequence and
pixel-format validation; no throughput improvement is claimed.
Focused ASan/UBSan on six VNC/state/BPF/startup paths passes (local LSan disabled
under ptrace). BPF equivalence passes 9,992,192 frozen legacy comparisons with
max instructions still 287→183 and lower aggregate interpreted work. Kernel gates
pass 1,024 legacy plus six proxy/Telnet/VNC/full combinations. The full 82-test
strict matrix and five adoption checks pass; CI LSan/ARM64 and all four PR #52
workflows pass.
**VNC cleanup:** unique staging fixtures moved to permanent test_vnc.c; obsolete
source/includes/workflow entries are deleted. Remote-branch state is tracked below.
**WinRM delivery:** the existing handshake/control owner now emits only native
`WINRM` records in the frozen field order. Plain TCP 5985 requires a complete
HTTP/1.0/1.1 request to exact `/wsman`; TCP 5986 requires a structurally valid
TLS ClientHello/ServerHello prefix and leaves encrypted inner fields unknown.
Only Content-Type and the Authorization scheme token are classified. Credential
values, username, SOAP/XML body and encrypted session data are never decoded,
copied or emitted. Exact userspace/BPF gates cover both directions and reject
dual-service endpoints in userspace. The existing directional application owner
provides eight attempts, expiry/eviction and SYN reset with zero new retained bytes,
allocation or reassembly. Permanent `test_winrm.c` replaces the deleted staging
header. The 83-test strict matrix, adoption checks and focused ASan/UBSan pass.
BPF equivalence covers 10,680,320 packets; maximum instructions remain 287→183;
kernel gates cover 1,024 legacy plus eight combined configurations. Full/stub text
is 196690/184674 (+3356/+3288 from PR #52), data 3992 and BSS 80360/78760 unchanged.
Main stack is 85,040 (+16); WinRM parser frame is 176. Reviewed full-text ceiling
is 196750. No throughput improvement is claimed; the growth buys bounded framing,
privacy classification and independent capture gating.
**WinRM CI/merge:** PR #53 merged at `cc526e5e8fae89b61d0d052758101122024073a6`;
core 33992514050, network 33992514060, L2 33992514107 and staging 33992514174 pass.
**Cleanup:** local WinRM/VNC integration branches are deleted. Remote HTTP proxy
and Telnet branches are already absent. Remote VNC/WinRM deletion is blocked by
Git HTTPS authentication; run:
`git push origin --delete v6-vnc-canonical-integration v6-winrm-canonical-integration`.
**Handoff:** application control is complete; the active milestone is realtime/media,
starting with the coupled RTP/RTCP trigger and privacy audit.
**RTP/RTCP audit:** current files are isolated staging parsers with no runtime,
dispatcher or BPF consumer. RTP parses only the fixed/CSRC prefix and does not yet
validate extension or padding framing; RTCP parses only the first common packet and
does not establish compound validity. Their negotiated/dynamic UDP ports cannot be
captured by widening the disabled-path filter to arbitrary UDP. Integration remains
gated on a bounded port-owner source (for example verified SIP/RTSP negotiation) or
an explicit configured port range with measured enabled cost; the decision must
also freeze which sequence/timestamp/SSRC fields are session evidence rather than
stable device fingerprints.
**Model:** Astra for dynamic-port/ownership freeze; Sol after the RTP/RTCP gate is
frozen and implementation becomes bounded parser/test work.
Always: bounded work/state; no hot-path malloc/regex/full DPI/full streams/secrets/bulk payloads;
disabled features effectively zero cost; protocol engines do not own telemetry transport.
