# argos-sniffer v6.0

Passive network fingerprinting & telemetry engine

**`argos-sniffer`** is a high-performance, lightweight, passive packet capture and network telemetry engine written in C for **OpenWrt/Linux gateways** and dedicated **Linux SPAN/TAP sensors**. It serves as the data-emitter core for the **Argos Network Sentinel** ecosystem, observing traffic passively with no active probing or packet injection.

**v6 development branch — runtime build: `6.0.0-dev`.** The executable remains
`argos-sniffer`; the product title and subtitle match `--help` and `--version`.
Release acceptance and remaining protocol integration are tracked in `progress.md`.

Previous v5 development history:

> v5.3.1 keeps the established level-triggered epoll receive path after runtime testing showed that synchronous bounded RX draining increased AF_PACKET drops under burst traffic. It also adds conservative kernel cBPF prefiltering and suppresses zero-payload IPv4 TCP ACK/window-update traffic before it reaches the userspace parser.
>
> v5.3.0 added native SPAN/TAP sensor operation while preserving the existing gateway mode and legacy telemetry format by default.

---

## Highlights

* **Gateway + Sensor in One Binary:** The normal gateway path remains the default; `--sensor` explicitly enables SPAN/TAP operation. Both modes use the same protocol parsers.
* **Dedicated Linux SPAN/TAP Sensor:** Run Argos on a Linux host receiving mirrored traffic from a firewall, router or managed switch without placing Argos inline.
* **SPAN/TAP Observation Context:** Sensor records carry sensor name, capture interface and VLAN context in an `OBS` envelope without changing the underlying Argos event.
* **VLAN & QinQ Awareness:** Captures 802.1Q / 802.1ad VLAN IDs, supports outer/inner QinQ context, and consumes Linux `PACKET_AUXDATA` metadata when NIC hardware strips a VLAN tag.
* **Unnumbered Capture NIC Support:** Repeatable `--inside CIDR` definitions classify internal IPv4/IPv6 networks even when the dedicated SPAN interface has no IP address.
* **Promiscuous Capture:** Sensor mode automatically enables promiscuous mode on the selected capture interface.
* **Zero Network Impact:** Operates strictly passively using Linux `AF_PACKET` raw packet sockets; no active probes, scans, ARP requests or injected packets are required by the sniffer.
* **L3/L4 OS Fingerprinting:** TCP SYN/SYN-ACK options, MSS, Window Scale, TTL, open-port discovery and TCP connection latency/state metrics (`TCPLVL`).
* **L7 Application Telemetry:** Plain HTTP `User-Agent`, TLS SNI, JA4-like fingerprints, ALPN and stateful QUIC / HTTP/3 inspection.
* **DNS Metrics & Threat Signals:** DNS parsing, response latency, entropy calculations (`DNSEXT`) and high-entropy anomaly detection (`ALERT`).
* **Local Discovery & Identity:** DHCPv4/v6, mDNS, SSDP/UPnP, WSD, NBNS, LLDP, ARP, NDP and IPv6 Router Advertisements.
* **Routed-Source Classification:** Identifies off-link clients observed behind LAN next-hop routers and preserves the optional `|routed` marker.
* **Flexible Telemetry Sinks:** `stdout`, Unix-domain socket (`-o`), UDP-only (`-u`) or UDP + stdout (`-U`).
* **Low-Resource Architecture:** Bounded state tables, deduplication and optional heavier QUIC/extended metrics suitable for routers and small Linux sensors.

---

## Operating Modes

### Gateway mode — default

No new option is required. Existing gateway invocations and legacy records remain unchanged:

```sh
argos-sniffer -i br-lan -a -E -W
```

```text
DNS|aa:bb:cc:dd:ee:ff|192.168.1.20|example.com
TLS|aa:bb:cc:dd:ee:ff|192.168.1.20|203.0.113.10|443|example.com|...|h2
```

### SPAN / TAP sensor mode

Sensor mode is intended for a dedicated Linux system connected to:

* a managed-switch **SPAN / port-mirror destination**;
* a mirrored firewall/router interface or trunk;
* a physical or virtual **network TAP**;
* a hypervisor/vSwitch mirror destination that presents the copied frames to a Linux interface.

Argos is not inline in this design. The production traffic continues through the switch/firewall normally while a copy is delivered to the sensor.

```text
                         production traffic
 Clients / VLANs  ------------------------------>  Firewall / Router
       |                                                |
       |                                                |
       +---------- Managed Switch / SPAN source --------+
                              |
                              | mirrored copy only
                              v
                       +--------------+
                       | Linux Sensor |
                       |              |
                       | eno2  SPAN   |  no IP required
                       | eno1  MGMT   |------------------> Collector
                       +--------------+
```

A basic sensor invocation:

```sh
argos-sniffer \
  --sensor \
  --sensor-name sensor-athens-01 \
  --inside 192.168.0.0/16 \
  --inside 10.0.0.0/8 \
  -i eno2 \
  -a -E -W
```

`--sensor-name` is required with `--sensor`. Sensor mode also requires an explicit capture interface; `-i any` is intentionally rejected so every observation has an unambiguous physical/logical capture source.

---

## SPAN / TAP Deployment Guide

### 1. Choose what to mirror

The quality of the inventory depends on what the switch or firewall delivers to the sensor.

For broad network visibility, mirror the **firewall/router LAN trunk or the relevant VLANs in both directions**. This normally provides north-south traffic and routed inter-VLAN traffic while keeping the sensor completely passive.

For visibility into traffic that never reaches the router, mirror the required access ports/VLANs as well. Same-VLAN unicast can be switched locally and therefore may never appear on a firewall/router uplink SPAN source.

The SPAN destination should be a dedicated interface. Do not use the capture port as an ordinary switched client port unless the platform explicitly supports that design.

### 2. Use separate capture and management interfaces

The recommended sensor layout is:

```text
eno1  -> management / SSH / telemetry collector path
eno2  -> SPAN/TAP capture only
```

The capture NIC does **not** need an IP address. Keeping it unnumbered avoids the sensor itself participating in the monitored network:

```sh
ip addr flush dev eno2
ip link set eno2 up
```

Sensor mode enables promiscuous capture automatically, so a separate `-p` is not required.

Check the interface before starting Argos:

```sh
ip -br link show eno2
ip addr show dev eno2
```

You can confirm that the mirror is actually delivering frames independently of Argos:

```sh
tcpdump -ni eno2 -e -nn
```

### 3. Define the inside networks

A gateway can learn directly connected prefixes from its own interfaces. A dedicated SPAN NIC is often unnumbered, so the sensor needs explicit knowledge of which observed source networks are internal.

Use repeatable `--inside` options:

```sh
--inside 192.168.10.0/24 \
--inside 192.168.20.0/24 \
--inside 10.20.0.0/16 \
--inside 2001:db8:1234::/48
```

IPv4 and IPv6 CIDRs can be mixed. Explicit sensor CIDRs are checked before the existing private/local and learned-interface prefix logic. This is particularly important for internal IPv6 GUA prefixes because they cannot be identified as inside merely from RFC1918-style address classification.

`--inside` is sensor-only and is rejected without `--sensor`.

### 4. Give every sensor a stable identity

Use a meaningful, stable `--sensor-name` rather than a temporary hostname:

```sh
--sensor-name dc1-core-span01
```

The name is carried in every sensor telemetry record, allowing one collector to receive observations from multiple distributed sensors while preserving their origin.

Example multi-sensor design:

```text
Branch A SPAN sensor ----\
Branch B SPAN sensor -----+---- UDP / VPN ----> Central Argos Collector
DC core SPAN sensor -----/
```

### 5. Send telemetry to the collector

UDP-only remote telemetry:

```sh
argos-sniffer \
  --sensor \
  --sensor-name branch-a-span01 \
  --inside 192.168.10.0/24 \
  -i eno2 \
  -a -E -W \
  -u 10.10.100.10:51412
```

`-u` sends structured telemetry to the remote collector **without stdout output**.

To send the same telemetry remotely while retaining stdout for a local supervisor or debugging, use `-U`:

```sh
argos-sniffer \
  --sensor \
  --sensor-name branch-a-span01 \
  --inside 192.168.10.0/24 \
  -i eno2 \
  -a -E -W \
  -U 10.10.100.10:51412
```

Remote UDP output is deliberately non-blocking and best-effort so an unreachable collector cannot stall packet capture. It is not encrypted or authenticated. Use a trusted management network, isolated telemetry VLAN or VPN when telemetry crosses an untrusted network.

IPv6 collector literals use bracket notation, for example:

```sh
-U '[2001:db8::10]:51412'
```

### 6. Exclude infrastructure MACs when appropriate

The existing gateway/firewall MAC exclusions remain available in sensor mode. For example:

```sh
-r aa:bb:cc:dd:ee:01 \
-r aa:bb:cc:dd:ee:02
```

`-r` is the normal soft exclusion for known router/firewall MACs; `-R` provides the existing hard exclusion behavior.

This is useful when a mirrored trunk contains large amounts of infrastructure-originated traffic that should not become endpoint identity evidence.

---

## Sensor Observation Envelope

Gateway records retain the legacy format. Sensor mode wraps the **same parser output** with observation metadata:

```text
OBS|sensor_name|interface|vlan|<legacy Argos record>
```

Examples:

```text
# Untagged
OBS|sensor-athens-01|eno2|0|DNS|aa:bb:cc:dd:ee:ff|192.168.1.20|example.com

# 802.1Q VLAN 20
OBS|sensor-athens-01|eno2|20|TLS|aa:bb:cc:dd:ee:ff|192.168.20.20|203.0.113.10|443|example.com|...|h2

# QinQ: outer VLAN 100, inner VLAN 20
OBS|sensor-athens-01|eno2|100/20|SYN|aa:bb:cc:dd:ee:ff|192.168.20.20|64|64240|7|1460|M*,S,T,N,W*|443
```

The envelope fields are:

| Field | Meaning |
| --- | --- |
| `OBS` | Identifies a distributed sensor observation. |
| `sensor_name` | Stable value supplied with `--sensor-name`. |
| `interface` | Linux interface on which the frame was observed. |
| `vlan` | `0` for untagged, a VLAN ID for 802.1Q, or `outer/inner` for QinQ. |
| remaining fields | Original Argos event, unchanged. |

A collector can therefore identify sensor telemetry by the leading `OBS` field, extract observation context, then pass the remaining record to the normal Argos parser. Gateway deployments remain wire-compatible because the `OBS` envelope is added only in explicit sensor mode.

---

## VLAN, QinQ and Hardware VLAN Offload

Argos understands VLAN context from the captured Ethernet frame and Linux packet metadata.

Supported observation forms include:

```text
0       untagged frame
20      802.1Q VLAN 20
100/20  QinQ outer VLAN 100, inner VLAN 20
```

On Linux, NIC hardware may remove a VLAN header before the frame reaches the packet socket. Argos enables `PACKET_AUXDATA` so VLAN information supplied by the kernel can still be associated with the observation when available.

SPAN configuration matters: some switches mirror the original tagged trunk frames, while others can present traffic differently depending on the source/destination port configuration. Validate the actual sensor-side frames with:

```sh
tcpdump -ni eno2 -e -nn -vv
```

Do not assume VLAN tags will be visible merely because the production interface is a trunk; verify the mirror behavior of the switch/firewall being used.

---

## What a SPAN Sensor Can and Cannot See

A sensor can only analyze packets copied to its capture interface.

**Normally visible when the relevant uplink/trunk is mirrored:**

* client Internet-bound traffic;
* return traffic from the firewall/router;
* routed inter-VLAN flows that cross the mirrored L3 path;
* TCP SYN/SYNACK fingerprints and connection state visible on that path;
* DNS, TLS, QUIC, HTTP and other enabled vectors carried by mirrored traffic;
* VLAN context when the mirror preserves it or Linux supplies it through packet metadata.

**Potentially missing:**

* same-VLAN unicast switched entirely between access ports;
* traffic on VLANs/ports not included in the SPAN session;
* discovery multicast/broadcast not forwarded to the selected mirror source;
* traffic hidden by switch SPAN limitations, oversubscription or dropped mirror frames;
* application identity that is cryptographically hidden from passive observation.

A TAP can provide more deterministic physical visibility than a switch mirror, but Argos processes either source in the same sensor mode.

### SPAN oversubscription

A mirror destination has finite bandwidth. Mirroring multiple busy full-duplex sources into one slower destination can exceed the destination link capacity before traffic even reaches Argos. No userspace capture optimization can recover frames that the switch never delivered.

For high-volume deployments:

* keep the SPAN destination at least as fast as the expected aggregate mirrored traffic;
* avoid mirroring unrelated high-volume links;
* monitor switch SPAN/drop counters where the platform exposes them;
* compare Argos capture statistics with an independent `tcpdump` test when troubleshooting loss.

---

## Sensor vs Gateway Mode

| Capability | Gateway | SPAN/TAP Sensor |
| --- | --- | --- |
| Passive AF_PACKET capture | Yes | Yes |
| Existing protocol parsers | Yes | Yes |
| Legacy event payload | Yes | Yes, inside `OBS` envelope |
| Explicit `--sensor-name` | No | Required |
| Repeatable `--inside CIDR` | No | Yes |
| Promiscuous capture | Optional | Automatic |
| `-i any` | Existing behavior | Rejected |
| Unnumbered capture NIC | Possible | Recommended |
| VLAN/QinQ observation context | Parsed | Added to `OBS` envelope |
| Remote UDP telemetry | Yes | Yes |
| Inline/network forwarding role | No | No |

---

## Build

### Native Linux Build

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic src/argos-sniffer.c -lm -o argos-sniffer
```

### Minimal Build Without QUIC Parser

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -DARGOS_QUIC_STUB src/argos-sniffer.c -lm -o argos-sniffer
```

### Static OpenWrt ARM64 Example

```sh
docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src alpine:latest sh -c "
  apk add --no-cache gcc musl-dev linux-headers && \
  gcc -Os -s -static -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -o argos-sniffer src/argos-sniffer.c -lm"
```

### GitHub Actions / Release Builds

The repository's **Build Linux binaries** workflow validates the source and builds static Linux binaries for **ARM64** and **x86_64**, including UPX-compressed variants and SHA-256 checksum files.

Normal pushes and manual workflow runs produce GitHub Actions artifacts. A pushed tag matching the source version, for example:

```sh
git tag v5.3.1
git push origin v5.3.1
```

triggers the tagged-release path and publishes the binaries to the corresponding GitHub Release. The workflow rejects a release tag that does not match `VERSION` in `src/argos-sniffer.c`.

For 5.3.1 the release assets are:

```text
argos-sniffer-5.3.1-arm64
argos-sniffer-5.3.1-arm64-upx
SHA256SUMS-arm64
argos-sniffer-5.3.1-x86_64
argos-sniffer-5.3.1-x86_64-upx
SHA256SUMS-x86_64
```

See `BUILDING.md` for additional build details.

---

## CLI Syntax

```text
argos-sniffer [-i iface] [-r router_mac] [-x filter_expr]
              [-z filter | -Z filter] [-o path] [-u ip:port] [-U ip:port]
              [-f seconds] [FLAGS...]

argos-sniffer --sensor --sensor-name NAME [--inside CIDR ...]
              -i SPAN_INTERFACE [FLAGS...]
```

### Important Options

| Option | Description |
| --- | --- |
| `--sensor` | Enable SPAN/TAP sensor mode. Automatically enables promiscuous capture. |
| `--sensor-name <name>` | Stable logical sensor name placed in every `OBS` envelope. Required in sensor mode. |
| `--inside <CIDR>` | Explicit internal IPv4/IPv6 network. Repeatable. Sensor mode only. |
| `-i <iface>` | Capture interface. Sensor mode requires an explicit interface and rejects `any`. |
| `-a` / `-A` | Enable all telemetry vectors, quiet/deduplicated or uncapped. |
| `-v` / `-V` | Enable IPv6 parsing when selecting vectors individually. |
| `-E` | Enable `TCPLVL`, DNS latency and entropy metrics. |
| `-W` | Enable bounded stateful QUIC / HTTP/3 inspection. |
| `-f <seconds>` | General deduplication window; default `35`. |
| `-o <path>` | Send telemetry to a Unix-domain socket. |
| `-u <host:port>` | Send telemetry only to a remote UDP collector. |
| `-U <host:port>` | Send telemetry to remote UDP collector and stdout. |
| `-r <mac>` / `-R <mac>` | Soft / hard MAC exclusion. `-r` is suitable for known gateway/firewall MACs. |
| `-x <expr>` | Exclude matching traffic before parsing. |
| `-z <expr>` | Live packet inspector; enables promiscuous capture. |
| `-Z <expr>` | Restrict structured telemetry to matching traffic. |
| `-p` | Explicitly enable promiscuous capture; sensor mode already enables it. |

---

## Telemetry Vectors

The same parsers are used in gateway and sensor mode. Lowercase flags apply deduplication; uppercase flags enable uncapped output.

| Vector / Protocol | Quiet | Raw | Scope |
| --- | --- | --- | --- |
| TCP SYN / SYNACK | `-s` | `-S` | TCP OS fingerprint, ports and `TCPLVL` correlation. |
| DHCPv4 / DHCPv6 | `-d` | `-D` | Hostname, Vendor Class, PRL, DUID, ORO and FQDN. |
| TLS / QUIC | `-t` | `-T` | SNI, JA4-like fingerprint, ALPN and HTTP/3. |
| HTTP User-Agent | `-h` | `-H` | Plain HTTP client identity. |
| mDNS / SSDP / WSD | `-m` | `-M` | Local discovery and service identity. |
| DNS | `-q` | `-Q` | Queries, response latency, qtype/rcode and entropy. |
| NBNS | `-n` | `-N` | NetBIOS names. |
| LLDP / ARP / NDP / RA | `-l` | `-L` | L2/L3 ownership and topology evidence. |
| All vectors | `-a` | `-A` | Enable all vectors and IPv6. |

---

## Legacy Telemetry Format

The payload after an optional sensor `OBS` envelope remains the existing Argos wire format:

```text
SYN|mac|src_ip|ttl|window|wscale|mss|opts|dst_port[|routed]
SYNACK|mac|src_ip|ttl|window|wscale|mss|opts|src_port[|routed]
TCPLVL|mac|src_ip|dst_ip|dst_port|rtt_us|retrans_count|state_event[|routed]
TLS|mac|src_ip|dst_ip|dst_port|sni|ja4|alpn[|routed]
QUIC|mac|src_ip|dst_ip|dst_port|sni|version[|routed]
HTTP|mac|src_ip|user_agent[|routed]
DNS|mac|src_ip|query_domain[|routed]
DNSEXT|mac|src_ip|dst_ip|query_domain|qtype|rcode|latency_ms|entropy[|routed]
ALERT|mac|src_ip|HIGH_DNS_ENTROPY|query_domain|entropy[|routed]
DHCP|mac|src_ip|hostname|vendor_class|prl[|routed]
DHCP6|mac|src_ip|msg_type|duid_type|vendor_class|oro|fqdn[|routed]
MDNS|mac|src_ip|port|qname[|routed]
NBNS|mac|src_ip|netbios_name[|routed]
LLDP|mac|sysname|sysdesc[|routed]
ARP|mac|sender_ip|target_ip|op[|routed]
NDP|mac|src_ip|type|target_ip|flags[|routed]
RA|mac|src_ip|hop_limit|flags|router_lifetime|prefix|prefix_len|mtu[|routed]
L7|mac|src_ip|dst_port|payload[|routed]
```

---

## Complete Remote SPAN Sensor Example

Example for a Linux box with `eno1` as management and `eno2` connected to the switch mirror destination:

```sh
# Capture interface: no L3 configuration required
ip addr flush dev eno2
ip link set eno2 up

# Verify mirrored traffic first
tcpdump -c 20 -ni eno2 -e -nn

# Start Argos sensor
./argos-sniffer \
  --sensor \
  --sensor-name core-span-01 \
  --inside 172.16.0.0/16 \
  --inside 192.168.0.0/16 \
  --inside 2001:db8:1234::/48 \
  -i eno2 \
  -a -E -W \
  -u 10.10.100.10:51412
```

For local debugging while also sending to the collector, replace `-u` with `-U`.

---

## Troubleshooting SPAN Sensors

If the sensor sees little or no telemetry, verify the mirror before changing Argos:

```sh
tcpdump -ni eno2 -e -nn
```

If `tcpdump` sees no expected traffic, check the switch/firewall SPAN source, direction, VLAN selection and destination port.

If VLAN identity is unexpected:

```sh
tcpdump -ni eno2 -e -nn -vv
```

Check whether the mirrored frames arrive tagged and whether NIC VLAN offload changes what packet capture sees.

If remote telemetry is missing but local parsing works, temporarily use `-U` instead of `-u`. This keeps stdout visible while the same records are sent to the remote collector and helps separate capture/parser issues from the telemetry path.

If packet drops are suspected, compare Argos statistics with an independent capture under the same load. Remember that SPAN oversubscription can drop packets at the switch before Linux receives them.

---

## Security & Privacy

* `argos-sniffer` is passive and does not inject or alter monitored traffic.
* Use it only on networks you own or are authorized to monitor.
* Telemetry may contain MAC addresses, hostnames, DNS queries, TLS SNI and other network identity evidence.
* Remote UDP telemetry is not encrypted or authenticated.
* Protect distributed sensor telemetry with network isolation, a management VLAN or a secure tunnel/VPN when crossing an untrusted network.
* An unnumbered SPAN capture interface plus a separate management interface is the recommended deployment model.

---

## License

Distributed under the **GNU General Public License v3.0 (GPLv3)**.
