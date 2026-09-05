# Argos Sniffer v6 — Architecture and Integration Backlog

This is the ordered implementation backlog for the v6 engine architecture, CLI hierarchy,
telemetry schema migration and isolated protocol engines. It is intentionally ordered by
dependency and rollout safety rather than by protocol count.

## Non-negotiable acceptance rules

Every step must preserve the following unless a separately gated schema migration explicitly
states otherwise:

- bounded work and bounded memory per packet;
- no heap allocation in the packet hot path;
- no regex processing in the sniffer;
- handshake, control-plane and header metadata only;
- explicit fast-complete/fast-drop for elephant flows;
- unchanged privacy guarantees: never emit passwords, authentication blobs, tickets or keys;
- strict native full/stub and ARM64 full/stub builds;
- fixtures, malformed/truncation corpus and ASan/UBSan coverage;
- optimized text-size and capture-path performance guards;
- staged implementation before production promotion.

Observable identity may include username, principal, realm/domain, machine account,
workstation, identity class and application identity. It must never include FTP `PASS`, LDAP
bind passwords, Redis AUTH secrets, NTLM response/challenge material, Kerberos tickets/session
keys, RADIUS shared secrets, SNMP community strings, TACACS decrypted credential material or
cryptographic keys.

## Verified starting point

- The production packet path already uses cohesive TLS, QUIC, L2, enterprise, discovery,
  identity, telemetry, packet-normalization and bounded flow-state modules.
- The discovery engine and permanent regression gate are complete.
- The compile-once bounded filter engine and permanent regression gate are complete.
- The bounded network-context engine and permanent regression gate are complete; prefix refresh
  remains event-driven and enabled ownership capacity is prepared before capture.
- Bounded TCP/UDP inspection state, optional SYN/DNS metrics and telemetry dedup now have one
  lifecycle owner while retaining independent keys, probes, TTLs and allocation policies.
- Capture socket/epoll setup, bounded receive metadata and drop statistics now have a
  cohesive lifecycle owner in `argos_capture.h`; packet normalization, filters and BPF
  construction remain separate. This extraction does not freeze the full packet contract.
- Thirty-seven standalone protocol headers are present as **runtime-isolated staging parsers**.
  They are temporary implementation units that must be integrated into v6 after readiness review,
  not permission to add 37 permanent public engine boundaries.
- RTSP, LDAP BER, NVMe/TCP and Thread/6LoWPAN boundary semantics have dedicated corrections and
  fixtures.

## Non-disruptive architecture audit

The following decisions are planning constraints only. They do not authorize runtime integration
while packet/state/config/telemetry contracts are still moving.

### Cohesive owner mapping for the 37 staged parsers

The standalone staging headers are temporary implementation units. At promotion time they should
fold into cohesive owners rather than remain one public header per protocol.

| Cohesive owner | Staged parsers |
|---|---|
| `argos_l2.h` | LLDP-MED, LACP, STP |
| `argos_network.h` | RIP, PTP |
| application facade/section | HTTP proxy, Telnet, VNC, WinRM, LPD, RTP, RTCP, RTSP, Cast, AirPlay, DLNA |
| `argos_enterprise.h` | FTP, NVMe/TCP, MongoDB, Redis, TACACS+, LDAP, LDAPS, Syslog, NetFlow, IPFIX, sFlow |
| industrial facade/section | KNXnet/IP, S7comm, OPC UA, DNP3 |
| IoT facade/section | Matter, Thread/6LoWPAN |
| VPN facade/section | OpenVPN, IKE, ESP, AH |

Do not create permanent `argos_application.h`, `argos_industrial.h`, `argos_iot.h` or
`argos_vpn.h` merely to mirror CLI super-groups unless the current source audit proves those
boundaries own enough shared logic/state to justify them. CLI taxonomy and source-file ownership
are related but not required to be 1:1.

### Normalized packet contract requirements

Any final packet-view abstraction must be able to expose, without reparsing in every engine:

- raw frame pointer/length when an engine genuinely needs it;
- L2/L3/L4/payload pointers plus bounded lengths;
- EtherType;
- IP version and IP protocol;
- source/destination MAC;
- normalized source/destination IP representation;
- source/destination ports when a port-bearing transport exists;
- packet direction/ownership/routed context.

The packet view must not assume every L4 protocol is TCP or UDP. ESP (IP protocol 50) and AH
(IP protocol 51) require direct IP-protocol dispatch without ports.

PTP must allow both native Ethernet PTP and UDP transport to reach the same protocol engine without
forcing duplicate packet APIs.

Packet normalization must stay separate from observations: SNI, JA4, usernames, SMB dialects,
RADIUS identities, confidence and application labels are engine/observation data, not packet-view
fields.

### Shared-type boundary

A shared types unit, if retained, should contain only concepts genuinely used across multiple
subsystems, such as normalized IP/endpoints, direction/transport, observation identifiers and
identity class. Protocol-private structs such as QUIC crypto state, TLS ClientHello state, STP
BPDUs, RADIUS attributes or Matter headers remain private to their owners.

Generic utility code must stay limited to small protocol-neutral primitives (bounded endian reads,
bounds checks, MAC/IP comparison, monotonic time/hash helpers). Protocol parsing must not migrate
into a generic utility dumping ground.

### Special integration holds and dispatch requirements

- **Thread/6LoWPAN:** staging parser remains valid, but runtime integration is held until capture
  link-type semantics prove how raw IEEE 802.15.4/6LoWPAN input reaches the sniffer. Ordinary
  Ethernet/SPAN capture does not by itself guarantee such frames.
- **ESP/AH:** dispatcher/BPF design must support non-port IP protocols before these are connected.
- **PTP:** dispatcher must support both EtherType-based and UDP-based reachability.
- **LLDP-MED/LACP/STP:** reconcile against the canonical L2 implementation fixture-by-fixture;
  never run duplicate production parsers for the same protocol.

### Safe work while the core refactor is active

Safe, non-disruptive work includes documentation, fixtures for isolated staging parsers, parser
boundary audits, protocol-to-owner mapping, dependency matrices, vector/schema review and test
corpus preparation.

Do not perform source-level consolidation, packet-view rewrites, state-owner changes, dispatcher
integration, CLI bitmap wiring or telemetry-schema cutover without re-reading the current
`version-6` source immediately before the change.

## Ordered delivery plan

Execution status and mandatory completion/handoff rules live in `progress.md`.
Keep that index synchronized with this detailed backlog and the master matrix.

- [x] Repair STP/RSTP/MSTP LLC normalization reachability with declared-length
  bounds and native/VLAN/QinQ frame-path regression (PR #7). This does not freeze
  the whole packet/transport-view contract or promote overlapping staging parsers.

### Core-contract prerequisite queue (2026-09-04)

Finish these in dependency order before any mass protocol or TLS-enrichment
runtime integration. `V6_CORE_CONTRACTS.md` records exact-source gaps; existing
completed extraction checkboxes do not mean the full contracts are frozen.

1. Packet/capture/normalization ownership and end-to-end reachability.
2. Bounded state lifecycle, including removal of packet-time allocation.
3. Config/enable bitmap and canonical membership/precedence.
4. Cheap dispatch and protocol/BPF gates.
5. Suppression, dedup and explicit fast-complete/drop semantics.
6. JIT activation, bounded scheduling and feed-state design.
7. Normalized observation/output/JSONL streaming contract.
8. Telemetry transport and lifecycle ownership.
9. Helper/API cleanup after their consumers' contracts settle.
10. Complete regression matrix and integration-readiness exit review.

`V6_HELP_BACKLOG.md` owns help design; `V6_SENSOR_ENRICHMENT_BACKLOG.md` remains
planning/staging. `V6_PROTOCOL_INTEGRATION_MATRIX.md` is the master integration
blueprint. Preserve all special holds and all privacy rules above.

The readiness review is a sequencing and safety gate, not a scope decision. Every staged protocol
listed in Phases 7–8 is committed to the v6 release. Known HOLD items remain in scope and require
their stated capture/dispatch dependency to be resolved before promotion; removing a protocol from
v6 requires an explicit user decision.

### Phase 1 — Finish the engine architecture

- [x] Extract the compile-once userspace filter engine; retain fixed-stack inline matching.
- [x] Build `argos_network.h`: LAN prefixes, netlink refresh, routed-source classification,
  bounded IPv4/IPv6 ownership and network visibility helpers.
- [x] Consolidate bounded flow tracking, UDP suppression and dedup ownership behind a state
  subsystem without merging unrelated lifetimes or keys.
- [x] Consolidate the capture plane only where ownership is real: packet normalization,
  userspace filters and kernel BPF construction remain distinct internal sections.
- [ ] Merge compatibility-only helpers into their owning engines:
  `tls_ports -> tls`, `enterprise_ports -> enterprise`, `raw_identity -> identity`.
- [ ] Reduce `argos-sniffer.c` to capture, normalize, cheap gate, dispatch, emit and lifecycle.
- [ ] Run final packet-loop, allocation, state-size, cache locality and capture-drop audits.

### Phase 2 — Freeze the public contracts

- [ ] Publish the canonical telemetry grammar and escaping/truncation rules.
- [ ] Freeze protocol/vector names. Vector names must not encode protocol variants:
  `SMB2 -> SMB`, `SMB2-NTLM -> NTLM`, `ORACLE-TNS -> ORACLE`, `SNMPV3-USM -> SNMP`.
- [ ] Freeze the observable-identity/privacy field policy per vector.
- [x] Freeze PROFILE -> SUPER GROUP -> GROUP -> PROTOCOL membership.
- [x] Define conflict and precedence rules for profile, group and individual protocol flags.
- [x] Decide and document the v6 legacy flag/qualified-selector compatibility policy.

### Phase 3 — Configuration and help system

- [x] Add an engine-enable bitmap with one bit per protocol and derived masks for groups,
  super-groups and profiles.
- [x] Compile existing legacy CLI selections once at startup; packet processing never walks CLI
  strings or accesses selection state. Qualified selectors remain blocked on fine-grained dispatch.
- [x] Add profiles: `core`, `standard`, `full`, `home`, `enterprise`, `sensor`.
- [x] Add super-groups: `network`, `application`, `enterprise`, `industrial`, `iot`, `vpn`.
- [x] Preserve lowercase = normal/deduplicated and uppercase = unrated behavior in the
  startup selection contract and existing legacy runtime options.
- [x] Add startup-only `--no-rate-limit=<all|super-group|group>` target compilation without
  per-packet string lookups; exposing the qualified option remains blocked on fine-grained dispatch.
- [x] Keep `--help` to one screen and add thematic help screens:
  `--help-profiles`, `--help-network`, `--help-application`, `--help-enterprise`,
  `--help-industrial`, `--help-iot`, `--help-vpn`, `--help-capture`, `--help-output`,
  `--help-rate`, `--help-identity`, `--help-performance`.
- [x] Generate help membership from the same canonical tables used by the enable bitmap so help
  and runtime behavior cannot drift.

### Phase 4 — Cheap dispatcher and BPF gating

- [x] Derive a compact fixed L2/L3/L4 route plan from the enable bitmap at startup; it is
  consumed for legacy projection before capture and cannot activate staging/HOLD bits.
- [x] Native-L2 and non-port production callers (ARP, LLDP/LLDP-MED, STP family, LACP,
  CDP/EDP/FDP/IS-IS, EAPOL, PROFINET, NDP/RA, IGMP/MLD, OSPF and VRRP) check their
  individual canonical bit before parsing; ARP/NDP owner tables follow enabled-family demand.
- [x] Extend the same pre-parser/pre-state gate to every current TCP/UDP production caller;
  shared ports use bounded owner resolution and TLS/DoT retain independent output/rate bits.
- [ ] Replace temporary coarse TCP/UDP BPF port-family flags with exact enabled-engine port
  projection while preserving safe VLAN, QinQ, PPPoE and IPv6 extension-header fallbacks.
- [x] Keep heavy QUIC reassembly runtime opt-in with enabled-demand startup allocation;
  disabled/default paths remain allocation-free and packet handling never allocates.
- [x] Add dispatcher fixtures for every current TCP/UDP port owner, both directions, aliases,
  disabled routes and legacy rate projections. End-to-end per-vector reachability stays C10.
- [ ] Benchmark packets/sec, loop latency, binary text size and AF_PACKET drop counters.

### Phase 5 — Connect existing production engines to the bitmap

- [ ] Network/addressing and discovery.
- [ ] TLS, DoT, QUIC and HTTP.
- [ ] L2 discovery, routing and redundancy.
  Native-L2 plus IGMP/MLD/OSPF/VRRP are adopted; port-driven BGP/RIP/HSRP and the remaining
  production callers keep this aggregate item open.
- [ ] Enterprise/storage/database/identity/management.
- [ ] Industrial, IoT and VPN engines already present in production.
- [ ] Prove wire output remains unchanged while only enable/gating ownership changes.

### Phase 6 — Collector-first telemetry migration

- [ ] Teach the collector to accept both legacy `ENT|...|PROTO|DETAIL` and canonical
  protocol-specific vectors.
- [ ] Add normalized internal collector records so both inputs produce identical inventory
  evidence.
- [ ] Add collector fixtures for every new vector and unknown-field forward compatibility.
- [ ] Add a sniffer compatibility mode for legacy `ENT|`; do not emit duplicate evidence.
- [ ] Switch the sniffer to protocol-specific vectors only after the deployed collector accepts
  both formats.
- [ ] Observe one release compatibility window, then remove the legacy parser only in a major
  schema transition.

### Phase 7 — Reconcile overlapping staging engines

The following already overlap production implementations and must be compared fixture-by-fixture,
not connected as duplicate parsers:

- [ ] `argos_lldp_med.h` -> canonical L2 engine.
- [ ] `argos_lacp.h` -> canonical L2 engine.
- [ ] `argos_stp.h` -> canonical L2 engine.

Keep the strongest bounded parser, preserve existing wire output until Phase 6, then remove the
redundant staging header.

### Phase 8 — Integrate all isolated engines by risk/value group

Every protocol in this list must be promoted into v6. Each group gets its own staged gate, port/BPF
matrix, flow-complete policy, privacy assertions and native/ARM64 validation. The standalone files
must be folded into the appropriate cohesive engine facade during integration rather than becoming
permanent one-protocol public modules. HOLD dependencies must be solved, not used to silently omit
the protocol from the release.

1. **Low-rate network control plane**
   - [ ] RIP, PTP.
2. **Management exporters**
   - [ ] Syslog, NetFlow, IPFIX, sFlow.
3. **Application control protocols**
   - [ ] HTTP proxy, Telnet, VNC, WinRM, LPD.
4. **Realtime and media negotiation**
   - [ ] RTP, RTCP, RTSP, Cast, AirPlay, DLNA.
5. **Enterprise storage, database and directory**
   - [ ] FTP, NVMe/TCP, MongoDB, Redis, TACACS+, LDAP, LDAPS.
6. **Industrial/OT control plane**
   - [ ] KNXnet/IP, S7comm, OPC UA, DNP3.
7. **IoT/smart-home framing**
   - [ ] Matter, Thread/6LoWPAN.
8. **VPN/IPsec metadata**
   - [ ] OpenVPN, IKE, ESP, AH.

### Phase 9 — Release hardening

- [ ] Golden wire-format corpus for legacy and canonical schema modes.
- [ ] Sanitized real-PCAP acceptance for protocols with optional/vendor fields.
- [ ] Native Linux gateway acceptance.
- [ ] Linux SPAN/TAP acceptance with VLAN/QinQ and unnumbered capture NIC.
- [ ] Real OpenWrt ARM64 acceptance on constrained hardware.
- [ ] Long-run bounded-memory/state expiry test.
- [ ] Burst capture/drop comparison against the clean pre-architecture baseline.
- [ ] Documentation, changelog, compatibility matrix and `6.0.0-rc1` release checklist.

## Canonical CLI taxonomy backlog

| Super-group | Group | Protocols |
|---|---|---|
| network | addressing | dhcp, dhcpv6, arp, ndp, ra |
| network | discovery | mdns, ssdp, upnp, llmnr, wsd, nbns |
| network | l2-discovery | lldp, cdp, edp, fdp, mndp, lldp-med, stp, lacp |
| network | multicast | igmp, mld |
| network | routing | bgp, ospf, isis, rip |
| network | redundancy | vrrp, hsrp |
| network | time | ntp, ptp |
| application | name-services | dns, dot |
| application | encrypted | tls, quic |
| application | web | http, http-proxy |
| application | remote-access | rdp, ssh, telnet, vnc, winrm |
| application | realtime | stun-turn |
| application | printing | ipp, pjl, jetdirect, lpd |
| application | voice | sip, sccp, rtp, rtcp |
| application | media | rtsp, cast, airplay, dlna |
| enterprise | fileshare | smb, ntlm, nfs, ftp |
| enterprise | storage | sunrpc, nfs, iscsi, nvmeof |
| enterprise | database | mysql, postgresql, mssql, oracle, mongodb, redis |
| enterprise | identity | kerberos, ntlm, eapol, radius, tacacs |
| enterprise | directory | cldap, netlogon, ldap, ldaps |
| enterprise | management | snmp, ipmi, rmcp, asf, vmware-slp, syslog, netflow, ipfix, sflow |
| industrial | building | bacnet, knx |
| industrial | automation | modbus, profinet, ethernet-ip, cip, s7, opcua |
| industrial | utility | dnp3 |
| iot | messaging | mqtt, coap |
| iot | smart-home | matter, thread |
| vpn | modern-vpn | wireguard, openvpn |
| vpn | ipsec-suite | ike, esp, ah |

Duplicate protocol membership such as NFS and NTLM is intentional: a protocol bit may belong to
multiple groups, but enabling either group sets the same single protocol bit and must not create
duplicate parsing or telemetry.

## Canonical vector schema backlog

All proposed records follow:

```text
VECTOR|src_mac|src_ip|dst_ip|key=value key=value ...[|routed]
```

The schema-freeze phase must finalize ordering, escaping, missing values and maximum field lengths.
Candidate vectors and their required metadata are:

| Vector | Candidate fields |
|---|---|
| SMB | version, dialect, command, signing, encryption, compression, auth, capabilities |
| NTLM | transport, message, username, domain, workstation, identity_class, windows, build |
| NFS | version, procedure, procedure_id, auth, machine |
| SUNRPC | program, program_id, version, procedure, auth, machine |
| FTP | direction, command, username, response, server, tls, passive |
| ISCSI | pdu, initiator, target, session, header_digest, data_digest |
| NVMEOF | transport, pdu, pfv, hpda, cpda, header_digest, data_digest |
| MYSQL | protocol, server_version, capabilities, charset, auth_plugin, username |
| POSTGRESQL | protocol, phase, username, application, database, ssl_requested |
| MSSQL | protocol, phase, username, version, build, subbuild, encryption |
| ORACLE | transport, packet, username, program, version, service_present, host_present |
| MONGODB | opcode, request_id, response_to, command, username |
| REDIS | protocol, frame, command, username, auth_present |
| KERBEROS | request, username, realm, identity_class, etype_count, etypes, preauth_present |
| EAPOL | version, eapol_type, code, method, username, identity_class |
| RADIUS | code, identifier, username, identity_class, service, eap, nas_present, message_authenticator |
| TACACS | version, type, seq, username, flags, encrypted |
| CLDAP | operation, netlogon, message_id |
| NETLOGON | response, opcode, flags, nt_version, domain, forest, site, dc |
| LDAP | message_id, operation, username, identity_class, auth, tls_upgrade |
| LDAPS | transport, tls_version, record_type, ldap_encrypted |
| SNMP | version, pdu, sysdescr, sysobjectid, security, username, engine_hash, enterprise, auth, priv, reportable |
| RMCP | version, sequence, class |
| IPMI | version, session, payload, username, netfn, command, authenticated, encrypted |
| ASF | enterprise, type, tag |
| VMWARE-SLP | version, function, service |
| SYSLOG | format, facility, severity, version, hostname, appname, structured_data |
| NETFLOW | version, count, sequence, engine_type, engine_id, source_id, uptime |
| IPFIX | version, length, sequence, observation_domain, export_time, sets |
| SFLOW | version, agent_type, agent, sub_agent, sequence, samples |
| LLDP-MED | device_class, capabilities, network_policy, application, vlan, priority, dscp, inventory |
| LACP | version, actor_system, actor_priority, actor_key, actor_port, actor_state, partner_system, partner_priority, partner_key, partner_port, partner_state |
| STP | type, version, flags, root_id, root_cost, bridge_id, port_id, message_age, max_age, hello_time, forward_delay, mst_revision, mst_digest |
| RIP | version, command, entries, auth, next_hop_present |
| PTP | version, message, domain, sequence, transport_specific, two_step, clock_identity |
| HTTP-PROXY | method, mode, target_host, target_port, username, proxy_auth, auth_scheme, via, forwarded, xff |
| TELNET | command, option, negotiation, username |
| VNC | protocol, version, security_types, selected_security, server_name, width, height |
| WINRM | transport, wsman, soap, method, auth, username, encrypted |
| LPD | command, queue, username |
| RTP | version, payload_type, marker, sequence, timestamp, ssrc, csrc_count, extension |
| RTCP | version, packet_type, report_count, ssrc, compound |
| RTSP | type, method, status, cseq, transport, username, server, user_agent, auth |
| CAST | transport, framing, frame_length, encrypted |
| AIRPLAY | protocol, method, username, server, user_agent, feature_present, pairing_present |
| DLNA | dlna, upnp_av, profile_present, server, user_agent, transfer_mode |
| KNX | protocol, version, service, total_length |
| S7 | transport, protocol, rosctr, pdu_ref, parameter_length, data_length, function |
| OPCUA | transport, message, chunk, size, secure_channel, username |
| DNP3 | direction, primary, function, source, destination, length |
| MATTER | transport, version, session_type, secure, privacy, message_counter, exchange_present |
| THREAD | layer, mesh, originator_size, final_size, hops_left, deep_hops |
| OPENVPN | transport, opcode, key_id, username, session_id_present, peer_id |
| IKE | version, exchange, username, flags, message_id, initiator_spi, responder_spi, natt |
| ESP | spi, sequence |
| AH | next_header, payload_length, spi, sequence |

## Completion definition for one protocol

A protocol is not considered integrated merely because its parser compiles. Completion requires:

- canonical enable bit, CLI membership and help entry;
- safe BPF/dispatcher reachability;
- bounded parser and malformed/truncation fixtures;
- explicit privacy assertions for every emitted field;
- fast-complete/fast-drop behavior where bulk traffic can follow;
- canonical vector and legacy compatibility coverage;
- collector acceptance and inventory mapping;
- native, sanitizer and ARM64 gates;
- removal or folding of the isolated staging header when its owning engine is established.

The v6 release is not complete while any staged protocol above remains only an isolated header,
unless the user explicitly removes that protocol from v6 scope.
