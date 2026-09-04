# Argos Sniffer v6 progress

Repository: `antoni0s/argos-sniffer`; delivery branch: `version-6`.
Last verified production checkpoint: `91a1d6bd52c6df02ac004c58f8d1e94505fa644d`.
Last updated: 2026-09-04. Core contracts are **not frozen**.

## Update rules — mandatory for every task/handoff

1. Fetch/exact-check current remote HEAD and reread affected source and all six
   documents named in `AGENTS.md`. This checkpoint is historical, not permission
   to assume the branch has not changed.
2. `[x]` means delivered and verified for the stated scope. `[ ]` includes pending,
   active, blocked and partially implemented tasks; state which in the text.
3. Before work, identify the active task and dependencies. On completion, update
   its box, evidence/commit or PR, tests, remaining limitations and next action.
4. A code task closes only after fixtures (including malformed/truncated input),
   relevant sanitizers, strict native full/stub and ARM64 validation, production
   promotion and staging cleanup where applicable. Record what actually ran.
5. Do not invent the hash of the commit containing this update. Reference its
   verified parent, implementation commit or PR; obtain current HEAD from Git.
6. Preserve unfinished tasks. Split partially finished items; never mark an entire
   contract frozen because an extraction subtask completed. Add newly found bugs
   at the earliest dependency-safe position and mark regressions reopened.
7. Reconcile with the detailed backlogs/matrix after each step. This is the status
   index; those documents retain every detailed acceptance criterion. Do not
   silently delete/override their requirements or planned/hold status.
8. Before handoff, record exact source/test status, uncommitted/unmerged work,
   known blockers and one concrete next step. Never claim hardware or collector
   acceptance from compiler or standalone parser results.

## Completed foundations (scope-limited, not full contract freeze)

- [x] Cohesive TLS and consolidated QUIC engines; heavy QUIC stays opt-in.
- [x] Enterprise and canonical L2 parser coverage; end-to-end gaps remain below.
- [x] Observed identity framework and RDP/NTLM privacy hardening.
- [x] Identity hash/raw modes and legacy alias.
- [x] TCP DONE state extraction and UDP suppression consolidation.
- [x] Dedup module and initial config foundation.
- [x] Discovery engine and permanent regression gate.
- [x] Compile-once bounded userspace filter engine.
- [x] Network context/prefix/netlink ownership extraction.
- [x] SYN/DNS/dedup lifecycle facade with independent keys/TTLs.
- [x] Capture lifecycle extraction — PR #6, `aacdf45d…`; cleanup `91a1d6bd…`.
  Native/ARM64 full+stub, standalone matrix and relevant sanitizers passed.
- [x] Preserve 37 isolated protocol headers and five enrichment/policy headers.
- [x] Correct synthetic TLS enrichment fixture lengths; permanent sanitizer and
  transitive runtime-isolation CI coverage — PR #6.
- [x] Exact-source interim core audit and matrix checkpoints — `91a1d6bd…`.
- [x] Add this progress index and repository instructions for future updates.

## Core delivery queue — complete before runtime staging integration

### 1. Packet / capture / normalization

- [ ] **ACTIVE:** STP/RSTP/MSTP frame→BPF→normalization→canonical-parser regression
  and repair of rejected LLC 42/42/03. Bound BPDU input by declared 802.3 length.
- [ ] Common bounded transport/payload view; no observations stored in packet view.
- [ ] Capture ancillary VLAN/timestamp, raw/cooked/unsupported and failure cleanup tests.
- [ ] Non-port IPv4/IPv6 dispatch contract, including AH header ownership.
- [ ] Native EtherType and UDP PTP reachability to one engine.
- [ ] Freeze packet/capture ownership after end-to-end evidence.

### 2. Bounded state ownership / lifecycle

- [ ] Remove packet-time dedup and network-owner allocations.
- [ ] Replace QUIC per-packet scratch allocations with bounded owned workspace.
- [ ] Prepare enabled heavy QUIC capacity outside packet processing; disabled stays cheap.
- [ ] Partial-init failure, repeated destruction and explicit state ownership tests.
- [ ] Per-protocol packet/byte/state ceilings, expiry, collision/eviction and clock policy.
- [ ] Allocation trap covering first evidence, success and malformed packets.

### 3. Config / enable bitmap

- [ ] One bit per protocol; shared PROFILE → SUPER GROUP → GROUP → PROTOCOL tables.
- [ ] Exact core/standard/full/home/enterprise/sensor profile membership.
- [ ] Enable/unrated masks and explicit precedence/legacy compatibility window.
- [ ] Resolve identity-group selector without redefining `--identity[=hash|raw]`.
- [ ] Keep sensor deployment mode separate from sensor profile.
- [ ] Compile selections once; no packet-time CLI string processing.
- [ ] Compact base help and all thematic screens in `V6_HELP_BACKLOG.md`.
- [ ] Generate help from canonical tables; no `--help-protocols`; no runtime init on help.

### 4. Cheap dispatch / protocol gating

- [ ] Startup-derived L2/L3/L4 dispatch and BPF plans.
- [ ] Gate disabled protocols before parser/state access; call-counter proof.
- [ ] Legacy selection equivalence and VLAN/QinQ/PPPoE/IPv6 fallback tests.
- [ ] Connect existing production engines to bitmap without changing wire output.
- [ ] Packet-rate, loop-latency, text-size and capture-drop comparisons.

### 5. Suppression / dedup / completion

- [ ] Explicit per-protocol complete/drop/budget policy and bulk-tail tests.
- [ ] Preserve directional DONE, SYN generation reset and completing-packet emission.
- [ ] Preserve UDP fixed epoch versus sliding/fixed emission dedup semantics.
- [ ] Unrated output must not disable parser safety limits.
- [ ] Remove duplicate TLS completion parsing; preserve later identity evidence.

### 6. JIT / scheduling / feed-state design

- [ ] Define demand activation outside packet processing, immutable config epoch.
- [ ] Bounded maintenance/GC quotas, feed-state lifecycle and overload policy.
- [ ] No new generic tracker or runtime code generation implied by JIT.

### 7. Observation / output / JSONL

- [ ] Bounded normalized evidence lifetime independent of borrowed packet buffers.
- [ ] Vector names, required/optional fields, privacy, escaping and truncation rules.
- [ ] JSONL newline/partial-write/backpressure policy and golden corpus.
- [ ] Collector accepts legacy and canonical records with equivalent mapping.
- [ ] Compatibility mode/window before canonical schema cutover; no duplicate evidence.

### 8. Telemetry ownership

- [ ] Move sink setup/close behind telemetry API; no transport ownership in engines.
- [ ] Explicit stdout blocking/drop policy, bounded buffering and sink counters.
- [ ] Fan-out, slow/closed sink, EAGAIN and feedback-loop regression tests.

### 9. Helper/API cleanup

- [ ] Reconcile tls_ports→TLS, enterprise_ports→enterprise, raw_identity→identity
  after config/dispatch settle; keep BPF independent of parsing implementations.
- [ ] Main becomes capture→normalize→gate/dispatch→engine→observation→identity/telemetry.
- [ ] Final packet-loop, allocations, cache locality, state-size and privacy audit.

### 10. Test matrix and final integration-readiness review

- [ ] Native full/stub + sanitizer + ARM64 matrix for each architecture step.
- [ ] End-to-end reachability, disabled-cost, allocation and bounded-state gates.
- [ ] Exact per-protocol matrix fields, including membership and collector mapping.
- [ ] Final eight-part review: frozen contracts; source/API changes; ready parsers;
  adaptations; holds; integration order; verified matrix entries; missing tests.

## Post-freeze integration queue — all currently blocked by core readiness

- [ ] Reconcile LLDP-MED/LACP/STP staging with canonical L2; no duplicate parsers.
- [ ] RIP/PTP control-plane integration (PTP requires both reachability paths).
- [ ] Syslog, NetFlow, IPFIX, sFlow.
- [ ] HTTP proxy, Telnet, VNC, WinRM, LPD.
- [ ] RTP, RTCP, RTSP, Cast, AirPlay, DLNA.
- [ ] FTP, NVMe/TCP, MongoDB, Redis, TACACS+, LDAP, LDAPS.
- [ ] KNXnet/IP, S7comm, OPC UA, DNP3.
- [ ] Matter; **Thread HOLD** until raw IEEE802.15.4/6LoWPAN capture is defined.
- [ ] OpenVPN/IKE; **ESP/AH HOLD** until non-port dispatch/BPF is proven.
- [ ] TLS client/server enrichment after TLS/public-observation freeze: reuse parsers,
  realistic HRR/PSK/ECH/early-data visibility tests; JA4S decision remains open.
- [ ] Certificate framing/X.509 leaf metadata: bounds/privacy/visibility and collector fixtures.
- [ ] Flow-shape design experiment only after state freeze; no new tracker now.
- [ ] Active enrichment hook remains post-v6, optional/default OFF.

## Release acceptance

- [ ] Sanitized real-PCAP and legacy/canonical golden output corpus.
- [ ] Native Linux gateway and Linux SPAN/TAP VLAN/QinQ acceptance.
- [ ] Actual OpenWrt ARM64 constrained-hardware acceptance.
- [ ] Long-run memory/expiry and burst/drop comparison to baseline.
- [ ] Documentation, changelog, compatibility matrix and 6.0.0-rc1 checklist.

## Current handoff

Next: reproduce and repair STP normalization, then update this status with PR/gates.
Known larger blockers: packet-time allocations, incomplete bitmap/dispatch,
streaming/backpressure, collector compatibility. No full core contract is frozen.
Mandatory invariant: bounded work/state; no regex/full DPI/full stream storage;
no secrets or bulk payload emission; no mass staging runtime integration.
