# Argos Sniffer v6 — progress

Branch: `version-6`. Verified checkpoint: `b799b791…` (PR #23).
**Now:** remove QUIC scratch/state allocation from packet handling (C2).
**Not yet:** full core freeze or staging runtime integration.

## Done — high-level history

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

## How to update — mandatory

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
  PTP native EtherType + UDP reach one engine. Thread stays HOLD until raw
  IEEE802.15.4/6LoWPAN capture is defined. C1 remains open across those dependencies.
- [ ] Freeze packet/capture only after complete frame-to-observation reachability coverage.

### C2. Bounded state / lifecycle

- [ ] Remove packet-time QUIC scratch/state allocations;
  prepare only enabled capacity outside packet handling; heavy QUIC remains opt-in/default cheap.
- [ ] **NOW:** QUIC capacity/failure policy and lifecycle tests beyond the completed
  SYN/DNS/dedup/network/process-startup cleanup;
  no extra generic tracker. First-evidence allocation traps must cover all remaining owners.
- [ ] Packet/byte/state budgets, expiry/clock rollback, collisions/eviction/saturation and tuple reuse;
  measure stack/heap/BSS/cache cost separately. No unbounded retained payload.

### C3. Config / bitmap / help

- [ ] Single protocol bits and shared PROFILE → SUPER GROUP → GROUP → PROTOCOL tables.
  Profiles: core/standard/full/home/enterprise/sensor. Super-groups:
  network/application/enterprise/industrial/iot/vpn. All canonical groups/protocols in the matrix;
  duplicate NFS/NTLM membership must not duplicate parsing/emission.
- [ ] Exact profile contents, enable/unrated masks, precedence/conflicts, legacy short-flag window;
  lowercase normal/UPPERCASE unrated; validate `--no-rate-limit=<all|super-group|group>`.
  Compile once, no per-packet string lookups.
- [ ] Resolve identity-group selector while preserving `--identity[=hash|raw]`/legacy alias;
  separate sensor profile from deployment mode; no implicit raw identity or staged protocol activation.
- [ ] One-screen base help with measured line/byte budget; no `--help-protocols`.
  Generate `--help-profiles`, `--help-network`, `--help-application`, `--help-enterprise`,
  `--help-industrial`, `--help-iot`, `--help-vpn` from the same runtime tables.
- [ ] Operational help: `--help-capture` (interfaces, -r/-R, promisc/count, sensor/filter/encapsulation);
  `--help-output` (Unix/UDP/stdout fan-out, approved grammar/JSONL/compatibility);
  `--help-rate` (actual compiled -f default, dedup/unrated);
  `--help-identity` (modes/allowed fields/prohibited secrets);
  `--help-performance` (-E/-W, defaults/allocation costs, promoted flow-shape only).
- [ ] Help tests: exact per-screen/profile membership; valid case-sensitive examples and no drift;
  real defaults; generated/removed staging * markers; bounded unknown-option error; native/ARM64
  output parity; cheap `--version`; help/version never initialize capture/BPF/state/sinks.

### C4. Cheap dispatch / gates

- [ ] Startup L2/L3/L4/BPF plans; disabled engine skips parsing AND state lookup (call-counter tests);
  safe VLAN/QinQ/PPPoE/IPv6 fallbacks; legacy selection equivalence.
- [ ] Wire existing production engines to bitmap: network/addressing/discovery; TLS/DoT/QUIC/HTTP;
  L2/routing/redundancy; enterprise/storage/database/identity/management; industrial/IoT/VPN.
  Golden output unchanged; kernel early-drop preserved.
- [ ] Benchmark packets/sec, loop latency, text size, disabled-feature cost and AF_PACKET drops.

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

### C10. Acceptance and final readiness review

- [ ] Per-step native full/stub, ASan/UBSan, ARM64, malformed corpus, performance/size and isolation gates;
  end-to-end reachability, disabled-cost, allocation, lifecycle/saturation/expiry and golden output tests.
- [ ] For EVERY production or staged protocol verify: cli_bit, group_membership, super_group_membership,
  owner_file, entry_function, trigger, bpf_gate, state_owner, vector, required_fields, optional_fields,
  fingerprint_inputs, max_packets, max_bytes, state_bytes, timeout_ms, complete_when, drop_when,
  privacy_assertions, fixtures, collector_mapping. No planned owners/triggers treated as facts.
- [ ] Eight-part exit review: frozen contracts; exact source/API changes; immediately ready parsers;
  adaptations; holds; safe order; newly exact matrix entries; missing tests. No mass integration before this.

## After core freeze — integration order

Each item requires ALL C10 row fields, CLI/help/BPF, budgets/fast-drop/privacy, collector/vector
fixtures and gates; fold/remove temporary staging headers only after canonical ownership is proven.

- [ ] Reconcile LLDP-MED/LACP/STP fixture-by-fixture with canonical L2; one runtime parser, old wire preserved.
- [ ] RIP/PTP (PTP dual-path prerequisite).
- [ ] Syslog/NetFlow/IPFIX/sFlow.
- [ ] HTTP proxy/Telnet/VNC/WinRM/LPD.
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

**Next:** QUIC scratch/state allocation outside packet handling, keeping heavy mode opt-in
and the disabled path effectively free. C1 non-port/PTP depends on C3/C4;
VLAN depends on schema approval.
**Blocked:** full freeze; collector compatibility; Thread, ESP/AH and TLS enrichment as above.
**Pending:** no open candidate; C2/C8 remain incomplete.
PR #23: core 33917508319, L2 33917508349, staging 33917508313 PASS.
Native full/stub text 156949/144438; BSS unchanged at 80304/80296.
Ownership reserves 8 KiB IPv4 plus 5 KiB IPv6 only for enabled L2 families.
ARM64 fixtures compile only; real hardware remains open. No staging runtime integration.
Always: bounded work/state; no hot-path malloc/regex/full DPI/full streams/secrets/bulk payloads;
disabled features effectively zero cost; protocol engines do not own telemetry transport.
