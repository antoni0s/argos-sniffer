# Argos Sniffer (`argos-sniffer`)

**`argos-sniffer`** is a high-performance, lightweight, passive packet capture and network telemetry engine written in C for **OpenWrt/Linux gateways** and dedicated **Linux SPAN/TAP sensors**. It serves as the data-emitter core for the **Argos Network Sentinel** ecosystem, observing traffic passively with no active probing or packet injection.

**Current development release: 5.3.0**

> v5.3.0 adds native SPAN/TAP sensor operation while preserving the existing gateway mode and legacy telemetry format by default.

---

## Highlights

* **Gateway + Sensor in One Binary:** The normal gateway path remains the default; `--sensor` explicitly enables SPAN/TAP operation. Both modes use the same protocol parsers.
* **SPAN/TAP Observation Context:** Sensor records carry sensor name, capture interface and VLAN context in an `OBS` envelope without changing the underlying Argos event.
* **VLAN & QinQ Awareness:** Captures 802.1Q / 802.1ad VLAN IDs, supports outer/inner QinQ context, and consumes Linux `PACKET_AUXDATA` metadata when NIC hardware strips a VLAN tag.
* **Unnumbered Capture NIC Support:** Repeatable `--inside CIDR` definitions classify internal IPv4/IPv6 networks even when the dedicated SPAN interface has no IP address.
* **Zero Network Impact:** Operates strictly passively using Linux `AF_PACKET` raw packet sockets; no active probes, scans, or injected packets.
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

### SPAN / TAP sensor mode — v5.3.0

Use a dedicated Linux interface connected to a switch SPAN/mirror port or network TAP. Sensor mode is explicit and automatically enables promiscuous capture.

```sh
argos-sniffer \
  --sensor \
  --sensor-name sensor-athens-01 \
  --inside 192.168.0.0/16 \
  --inside 10.0.0.0/8 \
  -i eno2 \
  -a -E -W
```

`--sensor-name` is required with `--sensor`. Sensor mode also requires an explicit capture interface; `-i any` is intentionally rejected.

For a dedicated SPAN NIC, keeping the capture interface unnumbered is recommended:

```sh
ip addr flush dev eno2
ip link set eno2 up
```

Use a separate management interface when remote telemetry is required.

---

## Sensor Observation Envelope

Gateway records retain the legacy format. Sensor mode wraps the same parser output with observation metadata:

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

A collector can therefore identify sensor telemetry by the leading `OBS` field, extract `sensor_name`, `interface` and `vlan`, then pass the remaining legacy record to the normal Argos parser.

---

## Inside Network Classification

A SPAN interface commonly has no configured IP prefix, so v5.3.0 adds repeatable explicit inside-network definitions:

```sh
--inside 192.168.10.0/24 \
--inside 192.168.20.0/24 \
--inside 10.20.0.0/16 \
--inside 2001:db8:1234::/48
```

Explicit `--inside` networks are checked before the existing private/local and learned-interface prefix logic. This is especially important for internal IPv6 GUA prefixes observed on an unnumbered SPAN NIC.

`--inside` and `--sensor-name` are sensor-only options and are rejected unless `--sensor` is present.

---

## SPAN Visibility Notes

A sensor can only inspect traffic delivered to its capture interface. Mirroring a firewall/router trunk normally provides excellent north-south and inter-VLAN visibility, but same-VLAN unicast traffic may remain entirely inside the switch and never reach that SPAN source. Discovery protocols such as mDNS/SSDP may also depend on the switch's mirroring and multicast configuration.

For maximum visibility, mirror the relevant VLANs/ports or use a network TAP.

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

### GitHub Actions — Manual Sensor Builds

The `Build Argos Sensor` workflow is manual (`workflow_dispatch`) and produces:

```text
argos-sniffer-linux-amd64
argos-sniffer-linux-arm64
```

Run it from **Actions → Build Argos Sensor → Run workflow** and select the branch to build. Artifacts are retained for 14 days.

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
| `-p` | Explicitly enable promiscuous capture. |

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

## Remote Sensor Example

```sh
argos-sniffer \
  --sensor \
  --sensor-name sensor-athens-01 \
  --inside 192.168.0.0/16 \
  --inside 10.0.0.0/8 \
  -i eno2 \
  -a -E -W \
  -u 10.10.100.10:51412
```

UDP telemetry is intentionally lightweight and best-effort. It is not encrypted or authenticated; use it only over a trusted management network or VPN.

---

## Security & Privacy

* `argos-sniffer` is passive and does not inject or alter monitored LAN traffic.
* Use it only on networks you own or are authorized to monitor.
* Telemetry may contain MAC addresses, hostnames, DNS queries and TLS SNI values.
* Protect remote telemetry with network isolation or a secure tunnel when crossing an untrusted network.

---

## License

Distributed under the **GNU General Public License v3.0 (GPLv3)**.
