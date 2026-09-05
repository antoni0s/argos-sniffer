# Argos Sniffer v6 — Master Protocol Integration Matrix

This document turns the canonical CLI taxonomy into an integration-readiness matrix. It is planning/specification only and does not authorize runtime wiring while the active v6 packet/state/config/telemetry contracts are still moving.

Before integrating any row, re-read the current `version-6` source and verify the exact owner, trigger/BPF path, output contract and state lifecycle.

## Status legend

- **production** — already represented by an active production owner/engine in v6; exact runtime behavior must still be re-verified before edits.
- **staging** — isolated parser/header exists and must be promoted into v6 after its readiness gates.
- **planned** — present in CLI taxonomy/backlog but no isolated staging parser is claimed here.
- **hold** — staging/planning exists but runtime integration is blocked by a known architectural dependency.

## Integration rule for every protocol

A protocol is ready for promotion only when all of these are true:

1. canonical CLI bit and group membership are defined;
2. trigger/BPF reachability is defined;
3. owner/module boundary is verified from current source;
4. output vector and fields are frozen;
5. stable fingerprint material is defined where useful;
6. fast-complete / fast-drop condition is explicit;
7. privacy exclusions are asserted;
8. positive + malformed/truncated fixtures exist;
9. collector compatibility is verified;
10. native, sanitizer and ARM64 gates pass.

These conditions determine when and how promotion is safe; they do not make the staged v6 protocol
optional. HOLD rows also remain v6 scope and require their named dependency to be resolved first.

---

## NETWORK

| Group | Protocol | Status | Planned owner | Trigger / BPF requirement | Candidate output / fingerprint | Fast-complete / privacy | Test gate |
|---|---|---:|---|---|---|---|---|
| addressing | dhcp | production | network/addressing owner | UDP 67/68, bounded DHCP header/options | DHCP vector: msg type, hostname, PRL, VCI, client-id class; fingerprint = PRL + VCI + bounded option behavior | complete after useful options; never emit secrets | production regression + malformed options |
| addressing | dhcpv6 | production | network/addressing owner | UDP 546/547 | DHCPV6: msg type, client/server DUID class, ORO, vendor/user class; fingerprint = ORO + class hints | complete after first useful message/options | IPv6 truncation fixtures |
| addressing | arp | production | network owner | EtherType 0x0806 | ARP: op, sender/target MAC/IP; evidence for ownership/relationship, not app fingerprint | stateless single-frame | malformed ARP |
| addressing | ndp | production | network owner | ICMPv6 NDP types | NDP: NS/NA/RS/RA role + link-layer options; fingerprint = option/capability pattern where useful | single control message | malformed/ext-header cases |
| addressing | ra | production | network owner | ICMPv6 RA | RA: router lifetime, flags, prefixes, MTU, RDNSS/DNSSL classes; fingerprint = bounded RA option pattern | one bounded RA | never emit arbitrary option blobs |
| discovery | mdns | production | discovery owner | UDP 5353 multicast | MDNS: service names/types, hostname, TXT keys (bounded); fingerprint = service set + product hints | stop after bounded answers | redact/limit TXT values |
| discovery | ssdp | production | discovery owner | UDP 1900 multicast | SSDP: method, ST/NT/USN, server, location host; fingerprint = server + service types | one message | no body fetch in sniffer |
| discovery | upnp | production | discovery owner | SSDP/HTTP metadata path | UPNP: device/service identifiers observed passively | bounded headers only | no active fetch by default |
| discovery | llmnr | staging | fold into discovery owner | UDP/TCP 5355 | LLMNR: query/response name/type | one bounded DNS-like record | DNS-like label bounds + TCP framing + exact BPF reachability |
| discovery | wsd | production | discovery owner | UDP 3702 | WSD: action, endpoint/device types, scopes (bounded) | one SOAP control frame | never retain arbitrary XML body |
| discovery | nbns | production | discovery owner | UDP 137 | NBNS: name/type/flags | one bounded message | name encoding bounds |
| l2-discovery | lldp | production | l2 owner | EtherType 0x88cc | LLDP: chassis/port/system name/desc/capabilities; fingerprint = TLV capability/inventory pattern | single LLDPDU | bounded TLVs |
| l2-discovery | cdp | production | l2 owner | SNAP/CDP multicast | CDP: device-id, port-id, platform, version, capabilities | single PDU | bounded TLVs |
| l2-discovery | edp | production | l2 owner | EtherType/SNAP as verified at integration | EDP: peer/platform metadata | one PDU | verify current parser |
| l2-discovery | fdp | production | l2 owner | vendor L2 discovery trigger | FDP: peer/platform metadata | one PDU | verify current parser |
| l2-discovery | mndp | production | l2/discovery owner | UDP 5678 | MNDP: identity/platform/version/interface metadata | one message | bounded attributes |
| l2-discovery | lldp-med | production | `argos_l2.h` | EtherType 0x88cc + MED TLVs | `LLDP-MED`: device_class, capabilities, network_policy, application, vlan, priority, dscp, inventory; fingerprint = MED capability/policy/inventory tuple | complete after MED TLVs; location/serial/asset excluded; no duplicate base LLDP telemetry | permanent fixture + canonical LLDP reconciliation |
| l2-discovery | stp | production | `argos_l2.h` | STP multicast / LLC BPDU | `STP`: type, version, flags, root_id, root_cost, bridge_id, port_id, timers, MST revision/digest; fingerprint = version + bridge/root/timer/MST profile | one BPDU | malformed BPDU + single canonical parser |
| l2-discovery | lacp | production | `argos_l2.h` | EtherType 0x8809 slow protocols | `LACP`: actor/partner system, priority, key, port and state; fingerprint = actor/partner state tuple | one bounded LACPDU | malformed TLV + canonical L2 reconciliation |
| multicast | igmp | production | network owner | IP proto 2 | IGMP: version/type/group/source count; behavioral evidence | one control message | bounds on source lists |
| multicast | mld | production | network owner | ICMPv6 MLD types | MLD: version/type/group/source count | one control message | IPv6 bounds |
| routing | bgp | production | network/routing owner | TCP 179 | BGP: message type, version/open capabilities/ASN class if already observed; fingerprint = capability set | complete after OPEN for fingerprinting | never parse bulk UPDATE payload beyond bounded metadata |
| routing | ospf | production | network/routing owner | IP proto 89 | OSPF: version/type/router-id/area/options | one bounded control packet | no LSDB reconstruction |
| routing | isis | production | network/l2-routing owner | native L2 IS-IS | ISIS: PDU type, system-id/area/capabilities | one bounded PDU | TLV bounds |
| routing | rip | production | `argos_network.h` | IPv4 UDP 520 / IPv6 UDP 521, either direction | `RIP|src_mac|src_ip|dst_ip|version=<1\|2\|ng> command=<request\|response> entries=<n> auth=<none\|simple\|md5\|-> next_hop_present=<0\|1>[\|routed]`; fingerprint = complete bounded detail tuple | one datagram, max 4,096 bytes / 204 fixed-width RTE slots; no retained state | authentication type only; never retain or emit password, digest, key-id, sequence or route prefixes; permanent strict/sanitizer/BPF/ARM64 fixtures |
| redundancy | vrrp | production | network owner | IP proto 112 | VRRP: version/type/VRID/priority/address count | one packet | bounded addresses |
| redundancy | hsrp | production | network owner | UDP 1985/2029 as verified | HSRP: version/state/group/priority/virtual IP | one message | version fixtures |
| time | ntp | production | network/time owner | UDP 123 | NTP: version/mode/stratum/refid class; fingerprint = mode/version/implementation hints only if stable | one request/response | never treat timestamps as device identity |
| time | ptp | production | `argos_network.h` | EtherType 0x88f7 and UDP 319/320 | `PTP`: bounded v2 common-header version, type, domain, flags, clock/port, sequence, control, interval and correction metadata | one common header; no payload/TLV retention | native/VLAN/QinQ + UDP4/UDP6 bounds, BPF, runtime and malformed fixtures |

---

## APPLICATION

| Group | Protocol | Status | Planned owner | Trigger / BPF requirement | Candidate output / fingerprint | Fast-complete / privacy | Test gate |
|---|---|---:|---|---|---|---|---|
| name-services | dns | production | DNS/app owner | UDP/TCP 53 | DNS query/answer metadata + app-domain evidence; fingerprint = query behavior only if deliberately enabled | bounded DNS message | no payload/body beyond names/types |
| name-services | dot | production | TLS owner | TCP 853 + TLS | DOT/TLS metadata; reuse TLS client/server fingerprints | TLS handshake complete | no decrypted DNS expectation |
| encrypted | tls | production + enrichment staging | TLS owner | TLS record heuristic/ports | existing SNI/JA4/ALPN + staged `TLS-CLIENT`, `TLS-SERVER`, certificate-lite; fingerprint = JA4 + future server fingerprint + bounded cert hash | client complete after ClientHello; server complete after selected bounded handshake evidence | no secrets/tickets/key material |
| encrypted | quic | production | QUIC owner | UDP QUIC long-header/Initial | QUIC version, SNI/ALPN/JA4-equivalent inputs where available, transport params; fingerprint = version + TLS client fingerprint + TP profile | stop after Initial/handshake evidence | heavy reassembly opt-in/lazy |
| web | http | production | application/HTTP owner | TCP HTTP request/response heuristics | HTTP: method, host, UA, selected header-pattern evidence; fingerprint = bounded header-order/client pattern where useful | complete at headers | never inspect body for fingerprinting |
| web | http-proxy | production | `argos_enterprise.h:ae_http_proxy` | independently gated TCP 80/3128/8080/8118/8888; CONNECT/absolute URI or proxy headers | `HTTP-PROXY`: method, mode, target_host, target_port, username, proxy_auth, auth_scheme, via, forwarded, xff; fingerprint = proxy header/capability pattern | after request/response headers | never emit Proxy-Authorization credentials |
| remote-access | rdp | production | application/enterprise owner | TCP 3389 + TPKT/X.224 | RDP: negotiation/security/capabilities/NTLM linkage; fingerprint = negotiation/capability profile | stop after negotiation/auth metadata | no credential blobs |
| remote-access | ssh | production | application owner | TCP 22/banner + KEX | SSH: client/server banners, KEX/cipher/MAC lists if bounded; fingerprint = software banner + algorithm-set fingerprint | after banner/KEXINIT | no session payload |
| remote-access | telnet | production | `argos_enterprise.h:ae_telnet` | independently selected TCP 23, both directions, initial IAC prefix | `TELNET`: command, option, negotiation, username; fingerprint = option negotiation set | one attempt, at most 1,024 bytes / 16 commands | username unknown; no interactive or subnegotiation values |
| remote-access | vnc | staging | application facade/section | TCP 5900-range + RFB magic | `VNC`: protocol, version, security_types, selected_security, server_name, width, height; fingerprint = RFB version + security set + server geometry/name hints | after ServerInit/security negotiation | no auth response material |
| remote-access | winrm | staging | application facade/section | TCP 5985/5986 + WSMan/SOAP | `WINRM`: transport, wsman, soap, method, auth, username, encrypted; fingerprint = transport/auth/WSMan profile | after bounded headers/auth scheme | no Authorization credential blobs |
| realtime | stun-turn | production | application owner | UDP/TCP 3478/5349 + STUN magic cookie | STUN/TURN: message class/method, attributes classes; fingerprint = capability/attribute pattern | one/few control messages | never retain integrity keys |
| printing | ipp | production | application/printing owner | TCP 631 + IPP/HTTP | IPP: operation, printer/device attributes where passive; fingerprint = make/model/IPP capability set | headers/attribute block | no print-job body |
| printing | pjl | production | printing owner | TCP 9100/PJL magic | PJL: command, INFO/USTATUS/device identifiers; fingerprint = language/capability/banner | stop before print payload | no document content |
| printing | jetdirect | production | printing owner | TCP 9100 + bounded control/PJL detection | JETDIRECT: service/control evidence | early control bytes only | fast-drop bulk print data |
| printing | lpd | production | `argos_enterprise.h:ae_lpd` (existing printing section) | TCP 515; commands only toward daemon | `LPD`: command, queue, username; frozen order/caps in backlog | one payload/direction, max 1,024 inspected bytes; stop on success or failure | permanent parser, native-wire, privacy, completion, BPF, sanitizer and ARM64 fixtures |
| voice | sip | production | application/voice owner | UDP/TCP 5060/5061 + SIP methods | SIP: method/status, UA/server, supported/allow codecs/features; fingerprint = UA + capability set | after headers/SDP-lite if bounded | no media body beyond negotiation metadata |
| voice | sccp | production | voice owner | TCP 2000 + SCCP framing | SCCP: message type/device identity/capability hints | bounded control messages | no media stream |
| voice | rtp | staging | application facade/section | negotiated/dynamic UDP + RTP version bits | `RTP`: version, payload_type, marker, sequence, timestamp, ssrc, csrc_count, extension; fingerprint = payload-type/SSRC behavior only as session evidence | first valid RTP packets then complete/drop | never inspect media payload |
| voice | rtcp | staging | application facade/section | paired RTP/RTCP ports + RTCP packet types | `RTCP`: version, packet_type, report_count, ssrc, compound; fingerprint = report/profile evidence | one compound RTCP packet | no media payload |
| media | rtsp | staging | application facade/section | TCP 554/8554 + RTSP methods | `RTSP`: type, method, status, cseq, transport, username, server, user_agent, auth; fingerprint = UA/server/transport/auth-scheme profile | after SETUP/response headers or budget | never emit Authorization secret |
| media | cast | staging | application facade/section | Cast framing/ports as verified | `CAST`: transport, framing, frame_length, encrypted; fingerprint = framing/transport profile | framing evidence only | no protobuf/media payload retention |
| media | airplay | staging | application facade/section | HTTP-like AirPlay ports/magic | `AIRPLAY`: protocol, method, username, server, user_agent, feature_present, pairing_present; fingerprint = feature/UA/server profile | control headers only | never emit pairing secrets |
| media | dlna | staging | application facade/section | HTTP/UPnP AV headers | `DLNA`: dlna, upnp_av, profile_present, server, user_agent, transfer_mode; fingerprint = DLNA profile + UA/server | headers only | no media payload |

---

## ENTERPRISE

| Group | Protocol | Status | Planned owner | Trigger / BPF requirement | Candidate output / fingerprint | Fast-complete / privacy | Test gate |
|---|---|---:|---|---|---|---|---|
| fileshare | smb | production | `argos_enterprise.h` | TCP 445/139 + SMB magic | `SMB`: version, dialect, command, signing, encryption, compression, auth, capabilities; fingerprint = dialect/capability/security profile | negotiate/session setup only, then drop bulk | no file payload/auth blobs |
| fileshare | ntlm | production | identity/enterprise owner | nested in SMB/HTTP/RDP/etc. | `NTLM`: transport, message, username, domain, workstation, identity_class, windows, build; fingerprint = OS/build/workstation evidence | after bounded Type1/2/3 metadata | never emit challenge/response material |
| fileshare | nfs | production | enterprise owner | TCP/UDP 2049 + RPC | `NFS`: version, procedure, procedure_id, auth, machine; fingerprint = NFS version/auth/machine evidence | control RPC only | drop file data; no auth secrets |
| fileshare | ftp | staging | fold into `argos_enterprise.h` | TCP 21 control | `FTP`: direction, command, username, response, server, tls, passive; fingerprint = server banner/feature/auth/TLS profile | control channel only | never emit PASS or transferred data |
| storage | sunrpc | production | enterprise owner | TCP/UDP 111 + RPC magic | `SUNRPC`: program, program_id, version, procedure, auth, machine; fingerprint = program/version/auth profile | bounded call/reply | no bulk procedure payload |
| storage | nfs | production | enterprise owner | see above | same single NFS protocol bit/vector | see above | duplicate membership must not duplicate parsing |
| storage | iscsi | production | enterprise owner | TCP 3260 + iSCSI PDU | `ISCSI`: pdu, initiator, target, session, header_digest, data_digest; fingerprint = initiator/target/digest capability profile | login negotiation then fast-drop data | no SCSI data payload |
| storage | nvmeof | staging | fold into `argos_enterprise.h` | TCP 4420 + NVMe/TCP PDU | `NVMEOF`: transport, pdu, pfv, hpda, cpda, header_digest, data_digest; fingerprint = connect negotiation profile | handshake/control PDU only | fast-drop data PDUs |
| database | mysql | production | enterprise owner | TCP 3306 + handshake | `MYSQL`: protocol, server_version, capabilities, charset, auth_plugin, username; fingerprint = server_version/capability/auth-plugin | handshake/auth metadata only | no password/auth response |
| database | postgresql | production | enterprise owner | TCP 5432 + startup | `POSTGRESQL`: protocol, phase, username, application, database, ssl_requested; fingerprint = startup/application/SSL profile | startup/auth negotiation only | no query payload/password |
| database | mssql | production | enterprise owner | TCP 1433 + TDS | `MSSQL`: protocol, phase, username, version, build, subbuild, encryption; fingerprint = TDS/prelogin version/encryption profile | prelogin/login metadata | no credentials/query data |
| database | oracle | production | enterprise owner | TCP 1521 + TNS | `ORACLE`: transport, packet, username, program, version, service_present, host_present; fingerprint = TNS/version/program profile | connect negotiation only | no SQL/auth blobs |
| database | mongodb | staging | fold into `argos_enterprise.h` | TCP 27017 + MongoDB wire opcode | `MONGODB`: opcode, request_id, response_to, command, username; fingerprint = opcode/command/client metadata profile | initial command/auth metadata | never emit auth payload/data documents |
| database | redis | staging | fold into `argos_enterprise.h` | TCP 6379 + RESP | `REDIS`: protocol, frame, command, username, auth_present; fingerprint = RESP/command capability profile | initial control commands | never emit AUTH secret or values |
| identity | kerberos | production | identity owner | TCP/UDP 88 | `KERBEROS`: request, username, realm, identity_class, etype_count, etypes, preauth_present; fingerprint = realm/etype/preauth/client pattern | AS/TGS metadata only | never tickets/session keys |
| identity | ntlm | production | identity owner | nested | same NTLM bit/vector | bounded handshake | no challenge/response |
| identity | eapol | production | identity owner | EtherType 0x888e | `EAPOL`: version, eapol_type, code, method, username, identity_class; fingerprint = EAP method/capability profile | identity/method exchange only | no credential material |
| identity | radius | production | identity owner | UDP 1812/1813/1645/1646 | `RADIUS`: code, identifier, username, identity_class, service, eap, nas_present, message_authenticator; fingerprint = NAS/service/EAP profile | one request/response pair if bounded | never shared secret/authenticator sensitive material |
| identity | tacacs | staging | fold into enterprise/identity owner | TCP 49 | `TACACS`: version, type, seq, username, flags, encrypted; fingerprint = version/type/encryption profile | initial auth/author/accounting metadata | never decrypted credential material |
| directory | cldap | production | enterprise owner | UDP 389 + LDAP BER | `CLDAP`: operation, netlogon, message_id | one bounded response | BER bounds |
| directory | netlogon | production | enterprise/identity owner | CLDAP Netlogon payload | `NETLOGON`: response, opcode, flags, nt_version, domain, forest, site, dc; fingerprint = domain/site/DC capability evidence | one response | no secrets |
| directory | ldap | staging | fold into `argos_enterprise.h` | TCP 389 + BER | `LDAP`: message_id, operation, username, identity_class, auth, tls_upgrade; fingerprint = operation/auth/StartTLS profile | bind/search metadata only | never bind password or arbitrary attribute values |
| directory | ldaps | staging | fold into `argos_enterprise.h` + TLS owner | TCP 636 + TLS | `LDAPS`: transport, tls_version, record_type, ldap_encrypted; fingerprint = TLS server/client fingerprint + service context | TLS handshake only unless LDAP becomes visible via other path | no decryption expectation |
| management | snmp | production | enterprise owner | UDP 161/162 | `SNMP`: version, pdu, sysdescr, sysobjectid, security, username, engine_hash, enterprise, auth, priv, reportable; fingerprint = sysObjectID/sysDescr/security-engine profile | bounded PDU/control metadata | never community string or auth keys |
| management | ipmi | production | enterprise owner | UDP 623 / RMCP+ | `IPMI`: version, session, payload, username, netfn, command, authenticated, encrypted; fingerprint = RMCP+/cipher/session capability profile | session setup/control | no auth payload |
| management | rmcp | production | enterprise owner | UDP 623 | `RMCP`: version, sequence, class | one header/control message | no payload retention |
| management | asf | production | enterprise owner | RMCP ASF class | `ASF`: enterprise, type, tag | one message | bounded |
| management | vmware-slp | production | enterprise owner | UDP/TCP 427 + SLP | `VMWARE-SLP`: version, function, service; fingerprint = service/function profile | one SLP control message | no arbitrary service body |
| management | syslog | production | `argos_enterprise.h` | UDP/TCP 514; encrypted TLS 6514 remains unsupported | `SYSLOG|src_mac|src_ip|dst_ip|format=<rfc3164\|rfc5424> facility=<name\|n> severity=<name\|n> version=<n\|-> hostname=<host\|-> appname=<app\|-> structured_data=<0\|1>[\|routed]` | one datagram or first complete TCP header; bounded structured-data walk | message body is never retained or emitted |
| management | netflow | production | `argos_enterprise.h` | UDP 2055/9995/9996 + version | `NETFLOW|src_mac|src_ip|dst_ip|version=<5\|7\|9> count=<n> sequence=<n> engine_type=<n\|-> engine_id=<n\|-> source_id=<n\|-> uptime=<n>[\|routed]` | one datagram, max 4,096 bytes; fixed header only | no record/template decode or retained state |
| management | ipfix | production | `argos_enterprise.h` | UDP/TCP 4739 + version 10 | `IPFIX|src_mac|src_ip|dst_ip|version=10 length=<n> sequence=<n> observation_domain=<n> export_time=<n> sets=<n\|->[\|routed]` | one datagram or first complete TCP message, max 4,096 bytes; bounded set-length walk | no template/data-set body decode or retained state |
| management | sflow | production | `argos_enterprise.h` | UDP 6343 | `SFLOW|src_mac|src_ip|dst_ip|version=5 agent_type=<ipv4\|ipv6> agent=<ip\|-> sub_agent=<n> sequence=<n> samples=<n>[\|routed]` | one datagram, max 4,096 bytes; fixed header only | no sampled payload extraction or retained state |

---

## INDUSTRIAL / OT

| Group | Protocol | Status | Planned owner | Trigger / BPF requirement | Candidate output / fingerprint | Fast-complete / privacy | Test gate |
|---|---|---:|---|---|---|---|---|
| building | bacnet | production | industrial section/owner | UDP 47808 + BACnet/IP | BACNET: BVLC/NPDU/APDU service/device metadata; fingerprint = vendor/device/service capabilities where passively available | control frames only | no property bulk dump |
| building | knx | staging | industrial facade/section | UDP 3671 + KNXnet/IP | `KNX`: protocol, version, service, total_length; fingerprint = service/version profile | one control frame | bounds on declared length |
| automation | modbus | production | industrial owner | TCP 502 + MBAP | MODBUS: function/unit/exception/role metadata; fingerprint = function/device behavior only | request/response headers only | no register-value harvesting |
| automation | profinet | production | industrial owner | EtherTypes/UDP as current source verifies | PROFINET: service/device/role metadata | discovery/control only | no cyclic process data |
| automation | ethernet-ip | production | industrial owner | TCP/UDP 44818/2222 | ETHERNET-IP: command/session/status/identity hints | session/discovery/control | no I/O bulk |
| automation | cip | production | industrial owner | encapsulated EtherNet/IP CIP | CIP: service/class/instance/vendor/product hints | bounded control path | no process data |
| automation | s7 | staging | industrial facade/section | TCP 102 + TPKT/COTP/S7 | `S7`: transport, protocol, rosctr, pdu_ref, parameter_length, data_length, function; fingerprint = S7 function/role/profile | setup/control PDU only | no PLC data payload |
| automation | opcua | staging | industrial facade/section | TCP 4840 + OPC UA UA-TCP | `OPCUA`: transport, message, chunk, size, secure_channel, username; fingerprint = message/security/channel profile | HEL/ACK/OpenSecureChannel metadata | never credentials or application data |
| utility | dnp3 | staging | industrial facade/section | TCP/UDP 20000 + DNP3 magic | `DNP3`: direction, primary, function, source, destination, length; fingerprint = role/function/address profile | control header/function evidence | no object data extraction |

---

## IOT

| Group | Protocol | Status | Planned owner | Trigger / BPF requirement | Candidate output / fingerprint | Fast-complete / privacy | Test gate |
|---|---|---:|---|---|---|---|---|
| messaging | mqtt | production | IoT/application owner | TCP 1883/8883 + MQTT fixed header | MQTT: protocol/version/client-id class/username-present/will/qos/features; fingerprint = protocol/version/client capability profile | CONNECT/CONNACK only | never password or message payload |
| messaging | coap | production | IoT/application owner | UDP 5683/5684 + CoAP header | COAP: type, code, token length, options classes, URI path class; fingerprint = version/option behavior | one request/response | no body payload |
| smart-home | matter | staging | IoT facade/section | UDP/TCP 5540 and Matter framing as verified | `MATTER`: transport, version, session_type, secure, privacy, message_counter, exchange_present; fingerprint = session/security/framing profile | framing/control metadata | no encrypted/application payload |
| smart-home | thread | hold | IoT facade/section | raw IEEE 802.15.4/6LoWPAN link-type required; ordinary Ethernet/SPAN not sufficient | `THREAD`: layer, mesh, originator_size, final_size, hops_left, deep_hops; fingerprint = mesh/header profile | one bounded mesh/6LoWPAN header | integration blocked until capture link-type semantics are explicit |

---

## VPN

| Group | Protocol | Status | Planned owner | Trigger / BPF requirement | Candidate output / fingerprint | Fast-complete / privacy | Test gate |
|---|---|---:|---|---|---|---|---|
| modern-vpn | wireguard | production | VPN/application owner | UDP + WireGuard message types | WIREGUARD: message type/role/session evidence; fingerprint = protocol behavior only | handshake messages only | never keys/cookies beyond non-sensitive presence flags |
| modern-vpn | openvpn | staging | VPN facade/section | UDP/TCP 1194/common ports + opcode | `OPENVPN`: transport, opcode, key_id, username, session_id_present, peer_id; fingerprint = transport/opcode/control profile | control handshake only | never credentials/session secrets |
| ipsec-suite | ike | staging | VPN facade/section | UDP 500/4500 | `IKE`: version, exchange, username, flags, message_id, initiator_spi, responder_spi, natt; fingerprint = version/exchange/transform/capability profile when bounded | IKE_SA negotiation metadata | never key material/auth blobs |
| ipsec-suite | esp | hold | VPN facade/section | IP protocol 50, no ports | `ESP`: spi, sequence; fingerprint = SPI/session relationship evidence, not implementation identity | fixed header only | dispatcher/BPF must support non-port IP protocols first |
| ipsec-suite | ah | hold | VPN facade/section | IP protocol 51, no ports | `AH`: next_header, payload_length, spi, sequence; fingerprint = session/header evidence | fixed header only | dispatcher/BPF must support non-port IP protocols first |

---

## Cross-protocol output/fingerprint conventions

### Vector naming

- Use protocol-specific canonical names (`SMB`, `NTLM`, `NFS`, `LDAP`, `IKE`, etc.).
- Do not encode protocol variants in vector names (`SMB2 -> SMB`, `SNMPV3-USM -> SNMP`).
- Duplicate CLI membership must map to the same protocol bit and same parser/vector.

### Fingerprint design

A fingerprint should be built only from fields that are:

- passively observable;
- bounded to extract;
- stable across irrelevant session changes;
- discriminative enough to justify hashing/correlation;
- privacy-safe.

Do **not** include volatile values such as sequence numbers, transaction IDs, timestamps, SPIs/session IDs, random values or hostnames unless the purpose is explicitly relationship/session correlation rather than implementation fingerprinting.

### Output privacy

Never emit:

- passwords or authorization secrets;
- NTLM challenge/response material;
- Kerberos tickets/session keys;
- RADIUS shared secrets;
- SNMP community strings;
- TACACS decrypted credentials;
- TLS/QUIC key material;
- bulk file/media/database/process payloads.

### Fast-complete requirement

For every protocol with possible bulk traffic, the final runtime integration must prove that once useful handshake/control fingerprint evidence is complete, later bulk payload is ignored without further parser/state cost.

---

## Integration-order checklist

This checklist is mandatory v6 delivery scope. Complete every group in order; a HOLD delays its row
until the prerequisite is implemented but does not remove it from the release.

1. **Reconcile overlapping L2 staging** — LLDP-MED, LACP, STP. **Complete.**
2. **Low-rate network control** — RIP and PTP are integrated in the canonical network owner. **Complete.**
3. **Management exporters** — Syslog, NetFlow, IPFIX and sFlow. **Complete.**
4. **Application control** — LPD, HTTP proxy and Telnet runtime slices implemented; VNC and WinRM remain open.
5. **Realtime/media** — RTP, RTCP, RTSP, Cast, AirPlay, DLNA.
6. **Enterprise storage/database/directory** — FTP, NVMe/TCP, MongoDB, Redis, TACACS+, LDAP, LDAPS.
7. **Industrial** — KNXnet/IP, S7comm, OPC UA, DNP3.
8. **IoT** — Matter; Thread only after link-type/capture contract is resolved.
9. **VPN** — OpenVPN, IKE; ESP/AH only after non-port IP dispatch/BPF support is proven.

## Final audit columns to fill at integration time

### Telnet runtime slice

- cli_bit: `ARGOS_PROTOCOL_TELNET`; group `remote-access`; super-group `application`.
- owner: existing `argos_enterprise.h` handshake/control section, `ae_telnet`;
  main uses independent `argos_dispatch_telnet_enabled` before parsing/state.
  TCP 23 in either direction; no UDP, TLS, SSH or enterprise-owner implication.
- BPF: exact selected TCP/23 payload and SYN admission; SYN generation reset
  works without SYN telemetry. Unselected legacy port resolution is unchanged.
- vector: native `TELNET|src_mac|src_ip|dst_ip|<ordered fields>[|routed]`;
  command/option are the first complete command, negotiation is up to 16 ordered
  pairs. Frozen grammar and byte caps are in V6_BACKLOG. No ENT wrapper.
- state: existing directional application owner; zero retained bytes added.
  One nonempty payload attempt, success or failure, at most 1,024 inspected bytes.
  No reassembly; split commands can lose evidence. SYN reset, 60-second idle
  expiry and four-probe eviction apply. Co-selected engines share completion.
- evidence/privacy: only the contiguous initial IAC prefix; ordinary/quoted data
  ends inspection. Invalid/truncated commands or unterminated SB within that
  prefix reject output. SB values are never copied; username remains `-`.
  Negotiation is observed command sequence, not confirmed capability/agreement
  or a new stable implementation hash. Later negotiation/identity is not claimed.
- fixtures: test_telnet uses production parser/sink, exhaustive option bytes,
  truncation, SB escaping, caps, privacy, dedup and directional state. Dynamic
  BPF/kernel and config/help/source gates are permanent; strict/sanitizer/LSan
  and ARM64 compilation cover the replacement. Unique staging fixtures migrated.
- collector_mapping: native wire golden only. Deployed collector compatibility,
  executing ARM64 and hardware throughput remain C7/C10 acceptance work.

### HTTP proxy runtime slice

- cli_bit: `ARGOS_PROTOCOL_HTTP_PROXY`; group `web`; super-group `application`.
- owner: existing `argos_enterprise.h` handshake/control section; main calls
  `ae_http_proxy` behind `argos_dispatch_http_proxy_enabled`, separately from HTTP
  and enterprise port ownership. No new protocol header or dispatch facade.
- trigger/BPF: TCP 80/3128/8080/8118/8888, either direction; exact proxy bit;
  selected proxy SYNs reach the generation reset even without SYN telemetry.
  No UDP or encrypted-proxy/TLS decoding. Existing HTTP and legacy bundles retain
  their admission/serialization behavior; proxy ports cannot steal SSH replies.
- vector: native `HTTP-PROXY|src_mac|src_ip|dst_ip|<ordered fields>[|routed]`;
  grammar, caps and unknowns are frozen in V6_BACKLOG. No ENT wrapper.
- state: existing directional application table; zero retained bytes/allocations
  added. At most eight payload attempts of 4,096 bytes, complete after successful
  full headers; 60-second idle expiry, four-probe eviction and SYN reset apply.
  No reassembly. A selected co-resident protocol may complete the shared direction
  earlier. Expiry/eviction can admit another bounded generation.
- evidence/privacy: CONNECT/absolute authority or header-presence metadata only.
  Username remains unknown (`-`); credentials are never decoded. Header values,
  URI userinfo, paths, queries and bodies are excluded. Plain responses without
  proxy headers produce no record. No stable implementation hash is claimed.
- fixtures: test_http_proxy (parser, truncation, cap, privacy, sink, dedup, state),
  test_dynamic_bpf, test_bpf_capacity, config/help and source adoption checks;
  permanent strict, sanitizer/LSan and ARM64 compile gates.
- collector_mapping: native wire fixture only; deployed collector acceptance,
  hardware throughput and executing-ARM64 acceptance remain C7/C10 work.

### LPD runtime slice

- cli_bit: `ARGOS_PROTOCOL_LPD`; group: `printing`; super-group: `application`.
- owner_file: `src/argos_enterprise.h`; entry_function: `argos_enterprise_parse_tcp`
  calls `ae_lpd` only for destination TCP 515. Replies produce no command record.
- trigger/bpf_gate: `argos_dispatch_tcp_port_engine` and the shared TCP registry
  admit 515 in either direction only when LPD is selected; UDP 515 is excluded.
- vector: `LPD|src_mac|src_ip|dst_ip|command=... queue=... username=...[|routed]`.
  Required fields: command/queue; username is always present as agent or `-`.
  Queue-query filters are not requesting identities; only command 5 supplies agent.
- fingerprint_inputs: command/service shape. Queue/agent are relationship evidence,
  not a stable implementation hash; no new fingerprint algorithm is claimed.
- state_owner: existing directional `argos_flow_state_t`; state_bytes: zero added.
- max_packets: one nonempty payload per retained direction/generation;
  max_bytes: 1,024-byte prefix through first LF; timeout_ms: existing 60,000 idle.
- complete_when/drop_when: first attempt succeeds or fails; later print bytes,
  control-file bodies/subcommands and server listings are not parsed. Missing LF,
  invalid grammar and over-cap fields produce no output. No TCP reassembly.
  Capture that starts midstream cannot establish handshake provenance; eviction,
  expiry and SYN reset permit a new bounded generation, as for the existing owner.
- privacy_assertions: no body bytes or filter-list identities emitted; queue/agent
  are 95/63-byte printable tokens with record delimiters normalized to underscore.
- fixtures: `test_lpd.c`, `test_dynamic_bpf.c`, `test_dispatch_plan.c`,
  `test_config_catalog.c`, `test_help.c`, `check_config_catalog.py`;
  core strict/sanitizer/ARM64 gate.
- collector_mapping: exact sniffer wire fixture verified; deployed collector
  owner/version acceptance remains unverified under C7/C10.

### Exact-source checkpoint, 2026-09-04

Baseline `0b704b8e2d0288702cc91b86c2f66914fa6eaaab`; capture extraction does not
alter these parser/dispatch facts. See `V6_CORE_CONTRACTS.md` for open gates.
This verifies individual fields only, **not whole-row integration readiness**.

| Protocol | Verified owner / entry | Current gate and wire fact | Still unverified / blocked |
|---|---|---|---|
| TLS / DoT | `src/argos_tls.h`: `argos_tls_client_parse`, `argos_tls_server_parse`; main owns serialization | Independent canonical TLS/DoT bits; TCP 443/465/853/993/995/8443/8883; one parse, exact `TLS` and additive `DOT` emission/rate gates, `TLSSRV` for server evidence | Normalized observation fields, byte budgets, collector mapping; enrichment remains staging |
| LLDP-MED | `src/argos_l2.h`: `argos_lldp_med_parse` | EtherType 0x88cc, canonical bit/rate gate and native `LLDP-MED|...` vector | Production; collector mapping remains C7/C10 |
| LACP | `src/argos_l2.h`: `argos_lacp_parse` | EtherType 0x8809, canonical bit/rate gate and native `LACP|...` vector | Production; collector mapping remains C7/C10 |
| STP family | `src/argos_l2.h`: `argos_stp_parse`, `argos_rstp_parse`, `argos_mstp_parse` | Native/VLAN/QinQ BPF→normalization→canonical parser; declared 802.3 bounds and one native `STP|...` vector | Production; collector mapping remains C7/C10 |
| PTP | Canonical `argos_network.h:argos_network_ptp_parse`; obsolete staging header removed | Native 0x88f7 and UDP 319/320 share one runtime helper, exact bit/rate/BPF gates and frozen native `PTP|...` output | Production; retain collector golden coverage in C7/C10 |
| ESP / AH | Isolated `src/argos_esp.h` / `src/argos_ah.h`, no runtime calls | Fixed userspace owner switches and IPv4 BPF gates exist behind unselectable HOLD bits; IPv6 remains conservative and normalization skips AH to the following header | Hold: main adapters plus AH sidecar ownership/readiness review |
| Thread | Isolated `src/argos_thread.h`, no runtime call | No raw IEEE802.15.4 link type in current capture contract | Hold: capture/link-type semantics |

Canonical `cli_bit` IDs and group/super-group memberships are now exact for all
101 protocols in `src/argos_config.h` (PR #28, `b19811f0…`). The catalog uses two
fixed 64-bit words and 103 memberships; NFS and NTLM intentionally appear in two
groups but retain one bit each. `tests/check_config_catalog.py` proves exact agreement
with the taxonomy table and `tests/test_config_catalog.c` pins IDs, membership,
case semantics and masks on native/ARM64 builds.

PR #35 runtime-wires the existing legacy category/default/all/enterprise options through the
canonical fixed masks once before capture, then projects them and the IPv6/extended-metrics/
stateful-QUIC parsing features into the unchanged coarse gates. Sensor deployment is recorded
in the canonical feature state while retaining its direct compatibility boolean. No selection
state or CLI string reaches packet processing. PR #29 adds fixed
production-only enabled/unrated selection primitives and startup-order rate precedence, while
PR #30 characterizes the exact canonical protocol
bundles and keeps SYN/IPv6/extended-metrics/stateful-QUIC/sensor controls outside the
protocol bitmap; this remains startup-only and is not a runtime adoption. The current
`--enterprise` bundle spans 50 production semantics and is not the canonical enterprise
super-group. PR #31 also compiles production-only `all`/super-group/group rate targets.
PR #32 froze the then-current production-only profile masks (core 7, standard 16, full 67,
home 36, enterprise 50, sensor 67) and the qualified `--profile`/`--super-group`/`--group`
namespace while preserving broad `--enterprise`, privacy-mode `--identity` and deployment
`--sensor` compatibility semantics. None of these APIs are wired into packet processing.
PR #33 adds the exact argv-order startup selector compiler, including profile replacement,
additive qualified selectors, explicit-feature preservation and identity-group disambiguation.
Its legacy subset is consumed by main/getopt. PR #34 generates bounded profile and thematic
membership help from these same tables and derives staging markers from source status;
informational paths run before all capture/state/sink setup. Qualified selectors, fine-grained
BPF/dispatcher consumption and per-row collector mappings remain C4/C10 work. No staging
parser became enabled.

PR #36 adds a fixed 48-byte startup owner for canonical
protocol/features and bounded L2/L3/L4 route demand. Exhaustive call-counter fixtures verify
each selectable production bit as an independent gate and reject staging/HOLD activation.
The current C4 slice consumes individual bits before every native-L2 parser and before NDP/RA,
IGMP/MLD, OSPF and VRRP. LLDP-MED/STP/LACP now use the canonical `argos_l2.h` owner, protocol-native
vectors and dedup namespaces; their duplicate isolated staging headers are removed.
Current TCP/UDP production callers consume exact protocol bits through bounded port-owner
resolution. PR #41 builds matching exact protocol port lists while preserving the frozen legacy
matrix. The C3 qualified-selector audit found no LLMNR runtime/BPF owner for UDP/TCP 5355, so its
catalog status is corrected to staging until the mandatory Phase 8 integration gate. Current
production-only profile counts are therefore core 7, standard 16, full 66, home 35, enterprise 50
and sensor 66; taxonomy/group/help membership remains intact and help renders `llmnr*`.

### Encapsulation field verification — PR #16 production `18b21557…`

`src/argos_packet.h:argos_packet_decode` retains the existing CDP OUI 00000c/PID
2000, FDP OUI 00e052/PID 2000, EDP OUI 00e02b/PID 00bb and IS-IS FE:FE:03
discriminators. These normalize to 2000/f200/00bb/00fe respectively. The runtime
owner/entry is `src/argos_enterprise.h:argos_enterprise_parse_l2`, reached only after the
matching CDP/FDP/EDP/IS-IS/EAPOL/PROFINET canonical bit; main emits legacy ENT using that result.
Its input now ends at the declared 802.3 boundary, not capture padding.
`src/argos_bpf.h:argos_bpf_build` keeps the existing enterprise-enabled <=1500
length admission and unconditional VLAN/QinQ/PPPoE conservative fallbacks.
`tests/test_encapsulation.c` verifies framing bounds and canonical CDP/FDP/EDP
padding exclusion; `tests/check_network_adoption.py` guards the runtime consumer.
These are exact owner/entry/trigger/input-bound facts only: canonical bits,
complete protocol budgets, schema and collector mapping remain unverified.

Non-port checkpoint at `5af8df48…` (characterization only):

| Protocol | Exact isolated entry/input | Verified missing runtime path / adaptation |
|---|---|---|
| AH | `argos_ah.h:argos_ah_parse`, >=12 bytes, declared `(payload_len+2)*4` within slice, nonzero SPI | IPv6 walker loses own offset and accepts framing rejected by staging; IP-version alignment adapter needed. Untagged IPv4 BPF lacks 51. No runtime call. |
| ESP | `argos_esp.h:argos_esp_parse`, >=8 bytes, nonzero SPI; terminal transport has no ports | Untagged IPv4 BPF lacks 50; no runtime call even when fallback admits capture. |
| PTP | `argos_network.h:argos_network_ptp_parse`, v2 common header >=34, message_length 34..slice length | Native and UDP adapters share the same canonical entry; production selector, rate, BPF and native PTP output are wired. Payload/TLVs are not inspected. |

`tests/test_nonport_contract.c` verifies these boundaries without runtime wiring.
`V6_CORE_CONTRACTS.md` records the optional first-AH sidecar API (PR #19) and the
BPF capacity repair (PR #18; unchanged 256-instruction cap). This does not add
non-port/PTP runtime reachability. Owner/entry/parser-input facts
are exact; canonical bits, emission fields, lifecycle/bulk budgets and collector
mapping are NOT verified by these tests. Holds and existing integration order remain.

First-AH ownership update — PR #19 (`775ffbbb…`):
`src/argos_packet.h:argos_packet_decode_with_ah` now optionally returns caller-owned
`argos_packet_ah_view_t` offset/length during the existing normalization walk.
Exact framing facts: first AH only, >=12 bytes, IPv6 multiple-of-eight length,
declared-IP bounds, no nonfirst-fragment evidence, empty on any decode failure.
Terminal transport semantics are unchanged. `tests/test_packet_ah.c` verifies
these against frozen PR #18 decode; no runtime caller adopts the new API yet.
The earlier missing AH offset/length API is resolved, but AH's planned runtime
trigger/owner, no-port BPF/dispatch, canonical bit, observation/privacy budgets
and collector mapping remain HOLD. The isolated parser must consume this bounded
framing at future integration; it must not repeat the extension walk. This is
partial field-level verification, not a completed integration-ready row.

State-owner update — PR #20 (`8e38cde6…`): existing optional SYN correlation and
DNS request/response tracking now belong to each `argos_runtime_state_t` instance
in `argos_flow_state.h` (`syn_track`, `dns_track`). `-E` still prepares both tables
before capture; packet selection, keys, probes and TTLs are unchanged. Preparation
is transactional and repeated enable/destroy is safe; lifecycle/allocation-trap
fixtures cover independent owners and first evidence. This verifies owner/lifecycle
fields only, not canonical bits, per-protocol byte budgets or collector mapping.
PR #22 (`83384902…`) moves the existing bounded dedup cache allocation to enabled-only
startup preparation. First evidence and failed preparation never allocate or retry;
keys, probes, TTL and wire behavior remain unchanged. PR #23 (`b799b791…`) prepares
the existing 8 KiB IPv4 and 5 KiB IPv6 ownership tables only for enabled L2 families;
ARP/NDP never allocate/retry and partial OOM remains family-local/fail-open. Packet-time
QUIC allocation is closed by PR #24 (`76472e9d…`): `argos_quic_state_t` owns an
enabled-only 81,919-byte workspace and the opt-in 593,408-byte/64-session heavy table;
packet calls do not allocate/retry. This verifies lifecycle/state ownership only;
canonical bits, exact row fields/budgets and collector mapping remain open, and no
staging row is promoted.

For each row, the integrating change must replace any generic/planned wording with exact current-source facts:

```text
cli_bit=
group_membership=
super_group_membership=
owner_file=
entry_function=
trigger=
bpf_gate=
state_owner=
vector=
required_fields=
optional_fields=
fingerprint_inputs=
max_packets=
max_bytes=
state_bytes=
timeout_ms=
complete_when=
drop_when=
privacy_assertions=
fixtures=
collector_mapping=
```

This document is the master checklist for turning the v6 CLI taxonomy into a verified runtime implementation without making the packet path monolithic or unbounded.
