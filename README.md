# Argos Sniffer (`argos-sniffer`)

**`argos-sniffer`** is a high-performance, low-level packet capture and passive telemetry engine written in **C**, built specifically for **OpenWrt** routers. 
It acts as the core data collection engine for the Argos Network Sentinel ecosystem, operating with zero network overhead and complete passivity.

---

## Purpose

Active network scanners (such as Nmap) can wake sleeping IoT devices, trigger battery-saving states, or congest home networks. **`argos-sniffer`** eliminates these issues by relying entirely on **Passive Network Sniffing**. 

Its core objectives are:
* **Zero-Impact Monitoring:** Listens silently to network traffic passing through the bridge/interface without injecting or modifying packets.
* **Real-Time Fingerprinting:** Extracts device identifiers, operating systems, hostnames, and application-layer protocols on the fly.
* **Dual-Mode Operation:** Functions as both a background structured telemetry stream for daemons and a native live packet inspector (replacing `tcpdump`).
* **Lightweight Embedded Footprint:** Designed as a standalone compiled C binary optimized for embedded OpenWrt architectures (ARM64, MIPS, x86_64) using Linux raw sockets (`AF_PACKET`) and kernel BPF filters.

---

## CLI Usage & Syntax

```text
USAGE:
  argos-sniffer [-i iface] [-r router_mac] [-x exclude_mac] [-z target_mac | -Z target_mac] [-f seconds] [FLAGS...]
  OR:
  argos-sniffer [iface]  (Auto-assigns interface and enables all vectors with -a)
```

### Quick Run Examples
```sh
# Run with all telemetry vectors enabled on br-lan (short syntax)
argos-sniffer br-lan

# Run daemon profiler excluding router and specific device, listening on br-lan with 35s deduplication
argos-sniffer -i br-lan -r f8:5e:3c:a0:69:75 -x d4:12:43:7c:3b:36 -a -f 35

# Mode 1: Live packet capture for a single device (replaces tcpdump, auto-enables promiscuous mode)
argos-sniffer -i br-lan -z e8:fb:1c:b2:9b:9f -c 50

# Mode 2: Restrict telemetry vectors to a single target device across the LAN
argos-sniffer -i br-lan -Z e8:fb:1c:b2:9b:9f -a -p
```

---

## Options & Operational Flags

* **`[iface]` / `-i <iface>`**: Interface to listen on (default: `br-lan`). Positional interface argument automatically activates `-a`.
* **`-r <mac>`**: Router MAC address to exclude from self-profiling (supports multiple declarations).
* **`-x <mac>`**: Exclude a specific MAC address from telemetry capture (supports multiple declarations).
* **`-z <target_mac>`**: **Mode 1 (Live Inspector)** — Captures and dumps full packet headers to/from the target MAC in `tcpdump` format. Auto-enables promiscuous mode.
* **`-Z <target_mac>`**: **Mode 2 (Targeted Profiler)** — Restricts standard telemetry vector parsing exclusively to the specified MAC address.
* **`-c <count>`**: Maximum packet capture limit before terminating (Mode 1 only; default: `0` for unlimited).
* **`-p`**: Enables **Promiscuous Mode** to capture unicast traffic across bridged switch ports.
* **`-f <seconds>`**: Deduplication / Rate-limiting window in seconds (default: `35s`, `0` to disable).

---

## Telemetry Vectors

Vector flags control which protocols are parsed and emitted. **Lowercase** flags apply deduplication/rate-limiting windows (`-f`), while **Uppercase** flags stream raw, uncapped events.

| Vector / Protocol | Rate-Limited | Uncapped | Description |
| :--- | :---: | :---: | :--- |
| **TCP SYN / p0f** | `-s` | `-S` | Passive OS fingerprinting via TCP options (MSS, Window Scale, SACK, TS) & SYN-ACK open port discovery. |
| **DHCP Options** | `-d` | `-D` | Extracts Hostname (Opt 12), Vendor Class ID (Opt 60), and Parameter Request List (Opt 55). |
| **TLS ClientHello** | `-t` | `-T` | Parses SNI (Server Name Indication) domains from HTTPS handshakes. |
| **HTTP User-Agent** | `-h` | `-H` | Extracts browser, OS, and client version strings from ports 80/8080. |
| **L7 Multicast** | `-m` | `-M` | Captures mDNS (port 5353) and SSDP/UPnP (port 1900) device announcements. |
| **DNS Queries** | `-q` | `-Q` | Inspects local UDP port 53 DNS lookups for domain activity. |
| **NetBIOS (NBNS)** | `-n` | `-N` | Decodes NetBIOS Name Service registrations and queries (UDP 137). |
| **LLDP Discovery** | `-l` | `-L` | Extracts Link Layer Discovery Protocol System Name and System Description frames (EtherType `0x88cc`). |
| **All Vectors** | `-a` | `-A` | Enables all vectors above (`-a` rate-limited, `-A` raw/uncapped). |
| **IPv6 Handling** | `-v` | `-V` | Enables IPv6 inspection (filters for link-local `fe80::/10`, ULA `fc00::/7`, and `::`). |

---

## Telemetry Output Format

In Mode 2, `argos-sniffer` emits pipe-delimited (`|`) UTF-8 lines designed for daemon parsing:

```text
SYN|mac|src_ip|ttl|window|wscale|mss|opts_layout|dst_port
SYNACK|mac|src_ip|ttl|window|wscale|mss|opts_layout|src_port
HTTP|mac|src_ip|user_agent
SNI|mac|src_ip|hostname
LLDP|mac|sysname|sysdesc
NBNS|mac|src_ip|netbios_name
DHCP|mac|src_ip|hostname|vendor_class|prl
DNS|mac|src_ip|query_domain
MDNS|mac|src_ip|port|qname
L7|mac|src_ip|dst_port|payload
```

---

## Source Code & Compilation

The source code is located at `usr/share/argos/src/argos-sniffer.c`.

### Static Compilation (Alpine Docker for OpenWrt ARM64 / x86_64)
```sh
docker run --rm -v $(pwd):/workspace alpine sh -c "
    apk add build-base upx
    gcc -O3 -static /workspace/usr/share/argos/src/argos-sniffer.c -o /workspace/usr/bin/argos-sniffer
    upx --best /workspace/usr/bin/argos-sniffer
"
```

---

## License

This project is open-source software licensed under the **GNU General Public License v3.0 (GPLv3)**.
