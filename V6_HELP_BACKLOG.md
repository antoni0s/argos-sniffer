# Argos Sniffer v6 — Help System Backlog

This document defines the v6 CLI help layout. It is a documentation/implementation contract only and does not authorize runtime CLI wiring until the active config/bitmap contracts are stable.

## Design goal

The base `--help` must stay approximately one terminal screen. Detailed protocol membership belongs in thematic help screens, one per super-group plus focused operational topics.

Do **not** add a giant generic `--help-protocols`; that would recreate the oversized help output this design is intended to avoid.

Thematic help membership should ultimately be generated from the same canonical tables used by the engine-enable bitmap so documentation and runtime behavior cannot drift.

## Base `--help`

```text
argos-sniffer v6.0
Passive network fingerprinting & telemetry engine

USAGE
  argos-sniffer [OPTIONS] [PROFILE | SUPER-GROUP | GROUP | PROTOCOL...]

QUICK START
  --all
      Enable all vectors.

  --profile core
  --profile standard
  --profile full
  --profile home
  --profile enterprise
  --profile sensor

SUPER GROUPS
  --network
  --application
  --super-group enterprise
  --industrial
  --iot
  --vpn

RATE LIMITING
  lowercase protocol = normal / rate-limited
  UPPERCASE protocol = unrated

  Example:
      --dns
      --DNS

CAPTURE
  -i, --interface <iface>
  -r <mac>
  -R <mac>
  -p, --promisc
  -c <count>

OUTPUT
  -o <path>
  -u <host>:<port>
  -U <host>:<port>

ADVANCED
  -E, --extended-metrics
  -W, --quic-stateful
  --sensor
  --identity[=hash|raw]

MORE HELP
  --help-profiles      Profiles and exact contents
  --help-network       Network groups/protocols
  --help-application   Application groups/protocols
  --help-enterprise    Enterprise groups/protocols
  --help-industrial    OT/ICS groups/protocols
  --help-iot           IoT groups/protocols
  --help-vpn           VPN groups/protocols
  --help-capture       Interfaces, sensor mode and filters
  --help-output        Telemetry sinks and record formats
  --help-rate          Rate limiting, dedup and unrated mode
  --help-identity      Identity/privacy options
  --help-performance   Performance/heavy-engine options

  --version
```

## `--help-enterprise`

```text
ENTERPRISE

  --super-group enterprise
      Enable all enterprise groups.

  --fileshare
      smb, ntlm, nfs, ftp*

  --storage
      sunrpc, nfs, iscsi, nvmeof*

  --database
      mysql, postgresql, mssql, oracle, mongodb*, redis*

  --identity
      kerberos, ntlm, eapol, radius, tacacs*

  --directory
      cldap, netlogon, ldap*, ldaps*

  --management
      snmp, ipmi, rmcp, asf, vmware-slp,
      syslog*, netflow*, ipfix*, sflow*

  * proposed / not currently implemented
```

## `--help-network`

```text
NETWORK

  --network
      Enable all network groups.

  --addressing
      dhcp, dhcpv6, arp, ndp, ra

  --discovery
      mdns, ssdp, upnp, llmnr, wsd, nbns

  --l2-discovery
      lldp, cdp, edp, fdp, mndp, lldp-med*, stp*, lacp*

  --multicast
      igmp, mld

  --routing
      bgp, ospf, isis, rip*

  --redundancy
      vrrp, hsrp

  --time
      ntp, ptp*
```

## `--help-rate`

```text
RATE LIMITING

  Lowercase protocol
      Normal rate-limited/deduplicated telemetry.

  UPPERCASE protocol
      Same protocol without rate limiting.

  Examples:
      --dns       normal DNS
      --DNS       unrated DNS
      --radius    normal RADIUS
      --RADIUS    unrated RADIUS

  -f <seconds>
      General deduplication window.
      Default: 35 seconds.

  --no-rate-limit=<target>
      Remove rate limiting from:
          all
          super-group
          group

  Examples:
      --no-rate-limit=all
      --no-rate-limit=enterprise
      --no-rate-limit=identity
```

## Remaining thematic help screens

### `--help-profiles`

Must list every profile and its exact canonical membership. The frozen
production-only profile policy is:

- `core`: current default — SYN, IPv6, mDNS/SSDP/UPnP/WSD, DHCPv4/v6 and NBNS.
- `standard`: current `-a` protocol/capability bundle, rate-limited.
- `full`: every production protocol plus SYN and IPv6.
- `home`: production members of addressing, discovery, L2 discovery, multicast,
  time, name-services, encrypted, web, realtime, printing, voice, messaging,
  smart-home and modern-vpn, plus SYN and IPv6.
- `enterprise`: the existing 50-protocol enterprise/control-plane compatibility
  bundle plus IPv6 handling; it is intentionally narrower than `full`.
- `sensor`: every production protocol plus SYN, IPv6 and extended metrics.

Profile membership must come from the same canonical enable tables as runtime selection.
No profile enables a staging/HOLD protocol, raw/hashed observed-identity mode,
stateful QUIC or SPAN/TAP deployment mode. `--profile sensor` selects evidence;
`--sensor` remains a separate deployment option requiring interface/name validation.

## CLI namespace and compatibility

For v6, preserve existing scripts while making ambiguous selectors explicit:

- `--enterprise` and `--enterprise-verbose` retain their current broad 50-protocol
  compatibility bundle for the documented legacy window.
- `--super-group enterprise` selects only the canonical enterprise super-group.
- `--profile enterprise` selects the frozen enterprise profile above.
- `--group identity` selects the canonical identity group; `--identity[=hash|raw]`
  remains exclusively the observed-identity privacy mode.
- `--profile sensor` never implies `--sensor`, and `--sensor` never silently expands
  protocol membership.

Other unambiguous super-groups may retain their direct long aliases. Help must label
the two legacy enterprise flags as compatibility aliases and must not describe them as
the canonical enterprise super-group.

### `--help-application`

Must expose only the application super-group and its groups:

- name-services
- encrypted
- web
- remote-access
- realtime
- printing
- voice
- media

### `--help-industrial`

Must expose only:

- building
- automation
- utility

### `--help-iot`

Must expose only:

- messaging
- smart-home

### `--help-vpn`

Must expose only:

- modern-vpn
- ipsec-suite

### `--help-capture`

Must document:

- interface selection;
- ignored/local MAC filters (`-r`, `-R`) according to the final preserved semantics;
- promiscuous mode;
- packet count/termination behavior;
- sensor/SPAN deployment mode;
- capture/filter interaction;
- VLAN/QinQ/PPPoE caveats where relevant.

### `--help-output`

Must document:

- local output path;
- UDP/remote telemetry sinks;
- stdout/local fan-out semantics;
- JSONL/streaming mode only after the active output contract is frozen;
- canonical vector grammar and compatibility mode only after schema freeze.

### `--help-identity`

Must document:

- observable identity policy;
- `--identity` modes;
- hashed vs raw identity behavior;
- allowed fields: username, principal, realm/domain, machine account, workstation, identity class, application identity;
- prohibited secrets: passwords, authentication responses/blobs, tickets, session keys, shared secrets and cryptographic keys.

### `--help-performance`

Must document only performance-affecting features, including:

- `--extended-metrics`;
- `--quic-stateful`;
- any future flow-shape feature if promoted;
- heavy-engine/runtime-state implications;
- defaults and whether the feature is lazily allocated;
- explicit note that normal passive operation remains bounded/lightweight.

## Proposed marker semantics

During development documentation, `*` means proposed/staged and not yet production-integrated.

Example:

```text
ftp*
nvmeof*
lldp-med*
```

Before the final v6 release, this marker must be generated from actual engine implementation status or removed. It must never become stale hand-maintained documentation.

## Implementation requirements

- [x] Base `--help` stays approximately one terminal screen.
- [x] No generic giant `--help-protocols` screen.
- [x] One thematic help screen per super-group.
- [x] Dedicated operational help for capture, output, rate, identity and performance.
- [x] Help membership generated from the same canonical tables as the engine-enable bitmap.
- [x] Profile membership generated from canonical profile masks/tables.
- [x] Lowercase/UPPERCASE rate semantics documented consistently everywhere.
- [x] `-f` default shown from the real compiled/configured default rather than duplicated magic text.
- [x] `--no-rate-limit` targets documented against canonical super-group/group names.
- [x] Proposed/staged `*` marker derived from implementation status.
- [x] Unknown thematic help option exits with a clear bounded error and no protocol dump.
- [x] `--version` remains cheap and does not initialize capture/state engines.
- [x] Help paths do not initialize AF_PACKET, BPF, flow state, telemetry sinks or other runtime subsystems.

## Regression tests

- [x] `--help` contains all top-level categories and remains under the agreed line/byte budget.
- [x] `--help-network` lists only network groups/protocols.
- [x] `--help-enterprise` lists only enterprise groups/protocols.
- [x] Each super-group help matches canonical group membership exactly.
- [x] Profiles shown by `--help-profiles` match the actual enable masks exactly.
- [x] Lowercase and uppercase protocol examples remain valid parser inputs.
- [x] `--help-rate` shows the actual default dedup interval.
- [ ] Help output is identical in native and ARM64 builds for the same feature set.
- [x] Help execution performs no Argos packet capture/state/sink allocation.

## Promotion gate

This help design should be implemented only after the active CLI/config/bitmap ownership is stable. At promotion time, re-read the current `version-6` source and preserve any legacy short-option behavior that the compatibility plan still requires.
