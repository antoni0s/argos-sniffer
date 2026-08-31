# Argos Sniffer (`argos-sniffer`)

**`argos-sniffer`** is a high-performance, lightweight, passive packet capture and network telemetry engine written in C for **OpenWrt** gateways and Linux hosts. It serves as the data emitter core for the **Argos Network Sentinel** ecosystem, quietly observing local traffic with zero network overhead, zero packet injection, and complete passivity.

**Current stable release: 5.2.1**

---

## Highlights

* **Zero Network Impact:** Operates strictly passively using Linux raw packet sockets (`AF_PACKET`) and in-kernel BPF filters—no active probes, scans, or battery drain on sleeping IoT devices.
* **L3/L4 OS Fingerprinting:** TCP SYN/SYN-ACK options (p0f-style layout, MSS, Window Scale, TTL, open port discovery) and TCP connection state/latency metrics (`TCPLVL`).
* **L7 Application Telemetry:** Plain HTTP `User-Agent`, TLS SNI, JA4-like fingerprints, ALPN negotiation, and stateful QUIC / HTTP/3 inspection.
* **DNS Metrics & Threat Signals:** Query parsing, response latency, entropy calculations (`DNSEXT`), and high-entropy anomaly detection (`ALERT`).
* **Local Discovery & Identity:** Captures DHCPv4 / DHCPv6 (DUID, FQDN, Vendor Class), mDNS, SSDP / UPnP, WSD, NetBIOS (NBNS), LLDP, ARP, NDP, and IPv6 Router Advertisements (RA).
* **Routed-Source Classification:** Automatically identifies off-link clients arriving behind LAN next-hop routers (`[|routed]`), supporting IPv6 ULA and delegated prefixes.
* **Flexible Telemetry Sinks:** Emits structured UTF-8 pipe-delimited records to `stdout`, a Unix Domain Socket (`-o`), or a remote UDP collector. `-U` fans out to UDP + stdout; `-u` selects UDP-only.
* **Low-Resource Architecture:** Optimized for constrained MIPS, ARM, and x86_64 routers with bounded sliding-window deduplication and lazy QUIC state allocation.

---

## Build

### Native Build (Full QUIC Support)
```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic src/argos-sniffer.c -lm -o argos-sniffer
```

### Minimal Build (Without QUIC Parser)

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -DARGOS_QUIC_STUB src/argos-sniffer.c -lm -o argos-sniffer
```

### Static Cross-Compilation (OpenWrt ARM64 Example)

```sh
docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src alpine:latest sh -c "
  apk add --no-cache gcc musl-dev linux-headers && \
  gcc -Os -s -static -ffunction-sections -fdata-sections \
    -Wl,--gc-sections -o argos-sniffer src/argos-sniffer.c -lm"
```

---

## CLI Syntax & Usage

```text
USAGE:
  argos-sniffer [-i iface] [-r router_mac] [-x filter_expr] [-z filter | -Z filter] [-f seconds] [FLAGS...]
  OR:
  argos-sniffer [iface]  (Listens on the given interface with all quiet vectors enabled: -a)
```

### Quick Examples

```sh
# Standard quiet daemon capture on br-lan (all vectors enabled)
argos-sniffer br-lan

# Extended daemon mode with QUIC (-W), TCP/DNS metrics (-E), and a 35-second dedup window
argos-sniffer -i br-lan -a -E -W -f 35

# Pipe telemetry directly to a Unix socket or a remote UDP collector
argos-sniffer -i br-lan -a -o /var/run/argos.sock
argos-sniffer -i br-lan -a -U 192.168.1.50:51412
# Send telemetry to a UDP collector only (no stdout)
argos-sniffer -i br-lan -a -u 192.168.1.50:51412
# UDP + stdout + syslog fan-out for a distributed daemon
argos-sniffer -i br-lan -a -U 192.168.1.50:51412

# Exclude router MAC from self-profiling and ignore a specific host/subnet
argos-sniffer -i br-lan -r aa:bb:cc:00:11:22 -x 'host 192.168.1.10' -a

# Mode 1: Live packet inspector (replaces tcpdump, auto-promiscuous)
argos-sniffer -i br-lan -z 'ether host aa:bb:cc:00:11:22' -c 50

# Mode 2: Restrict structured telemetry parsing strictly to a target device
argos-sniffer -i br-lan -Z 'ether host aa:bb:cc:00:11:22' -a -p
```

---

## Options & Flags

| Option | Description |
| --- | --- |
| `[iface]` / `-i <iface>` | Network interface to monitor (`br-lan`, `eth0`, or `any` for per-packet interface context). |
| `-a` / `-A` | Enable **all** telemetry vectors (`-a` quiet / deduplicated, `-A` fully uncapped). Enables IPv6 automatically. |
| `-v` / `-V` | Enable IPv6 packet parsing when selecting vectors individually. |
| `-E` | Enable extended TCP state/latency (`TCPLVL`) and DNS telemetry (`DNSEXT`). |
| `-W` | Enable bounded stateful QUIC / HTTP/3 inspection. |
| `-f <seconds>` | Deduplication window in seconds (default: `35s`, `0` = disabled). |
| `-o <path>` | Stream pipe-delimited records to a Unix-domain socket. |
| `-u <ip:port>` | Stream telemetry to a trusted UDP collector only. |
| `-U <ip:port>` | Stream telemetry to a trusted UDP collector and `stdout`. |
| `-r <mac>` / `-R <mac>` | Soft / hard MAC exclusion for router interfaces. |
| `-x <expr>` | BPF/expression filter to exclude packets before parsing. |
| `-z <expr>` | **Mode 1 (Live Inspector):** Dumps packet headers matching filter; forces promiscuous capture. |
| `-Z <expr>` | **Mode 2 (Targeted Profiler):** Restricts telemetry parsing strictly to matching traffic. |
| `-c <count>` | Stop after capturing `N` packets (Mode 1 only; `0` = continuous). |
| `-p` | Enable **Promiscuous Mode** to capture unicast traffic across bridged switch ports. |

---

## Telemetry Vectors

Lowercase vector flags enforce the deduplication window (`-f`), while uppercase flags stream raw, uncapped events.

| Vector / Protocol | Quiet (Dedup) | Verbose (Raw) | Captures & Telemetry Scope |
| --- | --- | --- | --- |
| **TCP SYN / p0f** | `-s` | `-S` | OS fingerprinting (MSS, Window Scale, SACK, TS layout, TTL) & SYN-ACK port discovery. |
| **DHCPv4 & DHCPv6** | `-d` | `-D` | Hostnames (Opt 12), Vendor Class (Opt 60), PRL (Opt 55), DUID, and FQDN. |
| **TLS & QUIC** | `-t` | `-T` | TLS SNI, JA4-like fingerprint, ALPN negotiation, and HTTP/3 handshake versions. |
| **HTTP User-Agent** | `-h` | `-H` | Plain HTTP `User-Agent` strings observed on ports 80 and 8080. |
| **L7 Multicast** | `-m` | `-M` | mDNS (port 5353), SSDP / UPnP (port 1900), and WSD device discovery. |
| **DNS & Extensions** | `-q` | `-Q` | DNS query domains, response codes, latency metrics, and entropy scoring. |
| **NetBIOS (NBNS)** | `-n` | `-N` | NetBIOS Name Service queries and registrations (UDP 137). |
| **Link & Identity** | `-l` | `-L` | LLDP switch identity, ARP ownership, NDP neighbor discovery, and IPv6 RA. |
| **All Vectors** | `-a` | `-A` | Enables all vectors above simultaneously (also enables IPv6 parsing). |
| **IPv6 Inspection** | `-v` | `-V` | Enables IPv6 inspection when selecting vectors individually. |

---

## Telemetry Output Format

Every event is emitted as a single UTF-8 newline-delimited, pipe-separated (`|`) record. If a source is determined to be behind a downstream router or sub-gateway, the optional `routed` tag is appended at the end:

```text
SYN|mac|src_ip|ttl|window|wscale|mss|opts_layout|dst_port[|routed]
SYNACK|mac|src_ip|ttl|window|wscale|mss|opts_layout|src_port[|routed]
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

### Sample Output Stream

```text
root@router ~ # argos-sniffer br-lan -a -E -W
SYN|aa:bb:cc:01:02:03|192.168.1.150|64|64240|7|1460|M*,S,T,N,W*|443
SYNACK|aa:bb:cc:01:02:99|192.168.1.1|64|65535|8|1460|M*,N,W*,N,N,S|80
TCPLVL|aa:bb:cc:01:02:03|192.168.1.150|142.250.180.206|443|18450|0|ESTABLISHED
TLS|aa:bb:cc:01:02:03|192.168.1.150|142.250.180.206|443|github.com|t13d1516h2_8daaf6152771_002f|h2
QUIC|aa:bb:cc:01:02:03|192.168.1.150|142.250.180.206|443|youtube.com|00000001
HTTP|aa:bb:cc:01:02:04|192.168.1.120|Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
DNS|aa:bb:cc:01:02:03|192.168.1.150|api.github.com
DNSEXT|aa:bb:cc:01:02:03|192.168.1.1|api.github.com|1|0|14.25|3.12
ALERT|aa:bb:cc:01:02:08|192.168.1.210|HIGH_DNS_ENTROPY|v8x9a2k1m4z7q0p3l5.dga-botnet.org|4.85
DHCP|aa:bb:cc:01:02:05|0.0.0.0|DESKTOP-RIG|MSFT 5.0|1,3,6,15,31,33,43,44,46,47,119,121,249,252
DHCP6|aa:bb:cc:01:02:06|fe80::211:22ff:fe33:4455|SOLICIT|DUID-LLT|android-dhcp6|23,24|pixel-phone.lan
MDNS|aa:bb:cc:01:02:07|192.168.1.180|5353|Living-Room-Speaker.local
NBNS|aa:bb:cc:01:02:05|192.168.1.110|WORKGROUP<00>
LLDP|aa:bb:cc:01:02:99|openwrt-gateway.lan|OpenWrt 23.05.4 Linux 5.15.150 aarch64
ARP|aa:bb:cc:01:02:03|192.168.1.150|192.168.1.1|REQUEST
NDP|aa:bb:cc:01:02:06|2001:db8::10|NEIGHBOR_SOLICIT|2001:db8::1|ROUTER
RA|aa:bb:cc:01:02:99|fe80::1|64|MANAGED,OTHER|1800|2001:db8:cafe::|64|1500
L7|aa:bb:cc:01:02:10|192.168.1.190|1900|M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"
SYN|aa:bb:cc:01:02:99|10.10.30.45|64|65535|8|1460|M*,N,W*,N,N,S|443|routed
```

---

## Routed-Source Semantics

The `routed` marker indicates the topological origin of the observed device:

* **Classification Criteria:** A packet source is marked as `routed` when its IP belongs to an off-link subnet (private IPv4, IPv6 ULA, or delegated prefix) received through a known LAN next-hop MAC, or when recent ARP/NDP ownership evidence contradicts the observed Ethernet frame MAC.
* **Bridge Awareness:** When listening explicitly on a bridge interface (`-i br-lan`), classification validates IP addresses against the bridge’s connected prefixes. When running with `-i any`, per-packet interface indexing is used to prevent cross-interface false positives.

---

## Security & Privacy

* **Passive Operation:** `argos-sniffer` never transmits, injects, or alters LAN packets.
* **Data Sensitivity:** Use it at a network with devices you own only. Emitted telemetry contains hostnames, DNS queries, SNIs, and MAC addresses. If streaming telemetry via UDP (`-U`), ensure traffic traverses a dedicated VLAN, management interface, or WireGuard/IPsec tunnel.

---

## License

Distributed under the **GNU General Public License v3.0 (GPLv3)**. Ensure a standard `LICENSE` file is included at the repository root.
