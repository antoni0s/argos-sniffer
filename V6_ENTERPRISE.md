# Argos Sniffer v6 — Enterprise Fingerprinting

Argos Sniffer v6 extends the existing passive home/SMB fingerprint vectors into enterprise infrastructure while preserving the original design goal: **bounded work per packet, no payload logging, and aggressive fast-drop of elephant flows**.

The v6 development branch is intentionally opt-in through `--enterprise` / `--enterprise-verbose`. It is not yet implied by legacy `-a` / `-A` while performance is being validated on OpenWrt and SPAN/TAP sensors.

## Architecture

### 1. Control-plane first

Enterprise protocols are inspected only where identity/version evidence is expected:

- handshake / login negotiation
- service discovery / advertisements
- routing hellos / OPEN messages
- device-identity queries and responses
- printer / VoIP registration metadata

Bulk data operations are either ignored immediately or mark the directional application flow as complete.

### 2. Reuse the existing fixed flow table

TCP enterprise parsing reuses Argos' existing fixed-size application flow cache instead of adding a second connection tracker. A flow is no longer inspected when:

- the protocol parser declares the fingerprint complete, or
- the existing bounded payload packet budget is exhausted.

This keeps SMB copies, NFS reads/writes, iSCSI I/O and print jobs from becoming packet-by-packet L7 workloads.

### 3. Kernel prefilter + user-space command filter

`--enterprise` installs an expanded classic-BPF whitelist for relevant control ports, OSPF and enterprise L2 discovery protocols. The application parser then performs the precise command/opcode/procedure check.

Tagged/encapsulated traffic that is unsafe to classify with fixed classic-BPF offsets is passed to the existing bounded user-space decoder rather than using brittle offsets.

### 4. Privacy-minimized telemetry

New output type:

```text
ENT|mac|src_ip|dst_ip|protocol|fingerprint[|routed]
```

Argos emits device/product/protocol evidence. It intentionally avoids credential material and message bodies. EAP identities are reduced to a class (`machine`, `user`, `opaque`) instead of emitting the identity string. Kerberos does not emit user principals.

## Implemented v6 protocol coverage

| Area | Protocol | v6 evidence / fast-drop behavior |
|---|---|---|
| Storage | NFS / SunRPC | RPC program/version/procedure, AUTH_SYS machine name; NFS READ/WRITE fast-complete |
| Storage | iSCSI | Login Request/Response, InitiatorName, TargetName, SessionType; SCSI/Data opcodes fast-complete |
| Database | MS SQL TDS | PRELOGIN version/build token; SQL Batch/RPC/Tabular data fast-complete |
| Database | Oracle TNS | CONNECT metadata such as PROGRAM/HOST/SERVICE_NAME/VERSION; DATA fast-complete |
| Identity | SMB2 / NTLMSSP | SESSION_SETUP only, NTLM message type, Windows version/build where present, domain/workstation; READ/WRITE fast-complete |
| Identity | Kerberos TCP/UDP | AS-REQ/TGS-REQ class and privacy-minimized realm evidence |
| Identity | CLDAP / Netlogon | DnsDomain / NtVer locator-query evidence |
| Identity | EAPoL / 802.1X | EAP type (Identity/MD5/TLS/TTLS/PEAP/FAST), identity class only |
| Management | IPMI / RMCP / ASF | Correct RMCP class distinction, ASF/IANA and IPMI control metadata |
| Management | VMware SLP | VMware/WBEM service advertisements |
| Management | SNMP | sysDescr/sysObjectID evidence when visible |
| L2 discovery | CDP | Device ID, platform, software release, native VLAN |
| L2 discovery | EDP | Extreme display name, slot/port and software version from EDP TLVs |
| L2 discovery | FDP | Foundry/Brocade DeviceID, platform, software version, interface |
| L2 discovery | MNDP | MikroTik/RouterOS neighbor evidence |
| Routing | BGP | OPEN version, ASN, hold time, router ID and capability-code order; UPDATE fast-complete |
| Routing | OSPF | Hello-only router ID, area, hello/dead timers and options |
| Routing | IS-IS | L1/L2 LAN IIH and P2P IIH system ID, hold timer, circuit/priority; LSP/CSNP/PSNP ignored |
| Printing | PJL / 9100 | First-payload `@PJL INFO ID` / COMMENT evidence, then flow complete |
| Printing | IPP | IPP session and printer-make-and-model attribute when visible |
| VoIP | SIP | REGISTER/INVITE response User-Agent / Server evidence |
| VoIP | Cisco SCCP | RegisterMessage device name, device type and max streams |
| OT / ICS | EtherNet/IP / CIP | ListIdentity vendor/device/product/firmware/serial/product name |
| OT / ICS | PROFINET DCP | Identify station name, vendor ID and device ID; cyclic RT data ignored |
| OT / ICS | BACnet/IP | I-Am announcement detection |
| OT / ICS | Modbus TCP | FC43/MEI Device Identification vendor/product/revision; FC03/04 fast-complete |

## Additional enterprise fingerprints added in v6

These were not in the initial proposal but have high evidence-to-cost value:

- **SSH** — server/client identification banner only
- **MySQL** — server greeting version
- **PostgreSQL** — protocol 3.0 StartupMessage application/database evidence
- **RDP** — TPKT/X.224 connection negotiation and mstshash cookie when present

## Important corrections made during implementation

- SMB2 `Command` is parsed from the SMB2 header field used for `SESSION_SETUP (0x0001)`, `READ (0x0008)` and `WRITE (0x0009)`; bulk commands are not parsed as fingerprint payload.
- RMCP **ASF is class `0x06`** and **IPMI is class `0x07`**.
- NFSv3 procedure numbers used for fast-drop are `READ=6`, `WRITE=7`; `FSINFO=19` remains useful control-plane evidence.
- OSPFv2 Hello offsets are taken after the 24-byte OSPF header: HelloInterval at 28, Options at 30 and RouterDeadInterval at 32.
- EDP is LLC/SNAP OUI `00:E0:2B`, PID `0x00BB`.
- FDP is LLC/SNAP Foundry OUI `00:E0:52`, PID `0x2000` and is distinct from Cisco CDP despite sharing PID `0x2000` under a different OUI.

## Validation

`tests/test_enterprise.c` contains bounded synthetic fixtures for the most offset-sensitive additions, including SCCP, Kerberos/TCP, OSPF, IS-IS, EDP, FDP and iSCSI bulk fast-drop behavior.

Production validation should additionally use sanitized PCAP fixtures from real implementations because several enterprise protocols have optional fields, segmentation and vendor extensions that synthetic packets cannot fully cover.

## Next high-value candidates

Candidates should be added only when they provide strong device/product evidence without turning Argos into a general DPI engine:

1. **RADIUS** — NAS-Identifier, Calling/Called-Station patterns and EAP method metadata without credential attributes.
2. **TACACS+** — version/type/sequence/encryption-state metadata only; never authentication bodies.
3. **LLDP-MED** — IP phone model/capabilities, network policy, PoE and inventory TLVs.
4. **VRRP / HSRP** — router/firewall role and virtual-router fingerprints.
5. **LACP / STP family** — switch/bridge infrastructure evidence from slow control frames.
6. **SNMPv3 EngineID enrichment** — authoritative engine identity when present in unencrypted security parameters.
7. **Database enrichment** — stronger vendor/build mapping tables for TDS/MySQL/PostgreSQL without parsing query contents.

The acceptance rule remains: **strong fingerprint value, bounded parser work, no content surveillance, and an explicit elephant-flow escape path.**
