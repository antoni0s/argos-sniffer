# Argos Sniffer (`argos-sniffer`)

**`argos-sniffer`** is a lightweight, low-level packet capture tool written in C for **OpenWrt** routers. It acts as the data collection engine for the Argos Network Sentinel ecosystem, quietly observing local traffic with zero network overhead and complete passivity.

---

## Why Passive Sniffing?

Active network scanners like Nmap generate traffic that can wake sleeping IoT devices, drain battery life, and clutter up home networks. `argos-sniffer` takes a strictly passive approach:

* **Zero Network Impact:** Listens silently on your bridge interface (`br-lan`) without injecting, transmitting, or modifying a single packet.
* **Real-Time Fingerprinting:** Extracts device types, hostnames, OS signatures, and protocols on the fly from everyday ambient traffic.
* **Dual-Mode Flexibility:** Works as a structured telemetry feed for background daemons or as a quick, targeted replacement for `tcpdump`.
* **Built for Low-Resource Hardware:** Written in pure C with minimal memory overhead, using Linux raw sockets (`AF_PACKET`) and in-kernel BPF filters to run smoothly on constrained MIPS, ARM, and x86_64 routers.

---

### What It Tracks

* **Passive OS & Device Profiling:**
  * **TCP Handshakes (p0f-style):** SYN/SYN-ACK packet options, window scaling, MSS, TTL, and open port detection.
  * **DHCP Leases:** Hostnames (Option 12), Vendor IDs (Option 60), and Parameter Request Lists (Option 55).
  * **Web & Domain Names:** DNS queries, plain HTTP `User-Agent` strings, and TLS Server Name Indication (SNI) handshakes.
  * **Local Discovery Protocols:** mDNS, SSDP / UPnP device broadcasts, NetBIOS (NBNS), and LLDP frames.
* **Smart Deduplication:** An in-memory sliding window drops repeated packets from chatty devices right at the capture layer, protecting downstream scripts and databases from event floods.

---

## CLI Syntax & Usage

```text
USAGE:
  argos-sniffer [-i iface] [-r router_mac] [-x exclude_mac] [-z target_mac | -Z target_mac] [-f seconds] [FLAGS...]
  OR:
  argos-sniffer [iface]  (Listens on the given interface and enables all vectors with -a)
```

### Quick Examples

```sh
# Sniff all telemetry vectors on br-lan (quick syntax)
argos-sniffer br-lan

# Run daemon mode on br-lan, excluding the router and a specific client, with a 35-second dedup window
argos-sniffer -i br-lan -r aa:bb:cc:00:11:22 -x aa:bb:cc:33:44:55 -a -f 35

# Mode 1: Live packet capture for a single device (replaces tcpdump, auto-promiscuous)
argos-sniffer -i br-lan -z aa:bb:cc:00:11:22 -c 50

# Mode 2: Restrict telemetry parsing to a single target device across the LAN
argos-sniffer -i br-lan -Z aa:bb:cc:00:11:22 -a -p
```

---

## Options & Flags

* **`[iface]` / `-i <iface>`**: Network interface to monitor (default: `br-lan`). Providing the interface name directly activates `-a` automatically.
* **`-r <mac>`**: Router MAC address to exclude from self-profiling (can be used multiple times).
* **`-x <mac>`**: Client MAC address to ignore (can be used multiple times).
* **`-z <target_mac>`**: **Mode 1 (Live Inspector)** — Dumps raw packet headers to/from the target MAC in `tcpdump` style. Automatically turns on promiscuous mode.
* **`-Z <target_mac>`**: **Mode 2 (Targeted Profiler)** — Limits structured telemetry parsing strictly to this MAC.
* **`-c <count>`**: Stop after capturing this many packets (Mode 1 only; `0` = continuous).
* **`-p`**: Enable **Promiscuous Mode** to catch unicast switch traffic across bridged ports.
* **`-f <seconds>`**: Deduplication window in seconds (default: `35s`, set to `0` to disable).

---

## Telemetry Vectors

Vector flags control which protocols `argos-sniffer` parses. **Lowercase** flags apply the deduplication window (`-f`), while **Uppercase** flags stream raw, uncapped events.

| Vector / Protocol | Deduplicated | Uncapped | What It Captures |
| :--- | :---: | :---: | :--- |
| **TCP SYN / p0f** | `-s` | `-S` | Passive OS fingerprinting (MSS, Window Scale, SACK, TS) & SYN-ACK port discovery. |
| **DHCP Options** | `-d` | `-D` | Hostnames (Opt 12), Vendor Class (Opt 60), and Parameter Lists (Opt 55). |
| **TLS ClientHello** | `-t` | `-T` | SNI (Server Name Indication) domains from HTTPS connection starts. |
| **HTTP User-Agent** | `-h` | `-H` | Browser, OS, and client strings over plain HTTP (ports 80/8080). |
| **L7 Multicast** | `-m` | `-M` | mDNS (port 5353) and SSDP/UPnP (port 1900) device announcements. |
| **DNS Queries** | `-q` | `-Q` | Local DNS lookups over UDP port 53. |
| **NetBIOS (NBNS)** | `-n` | `-N` | NetBIOS Name Service queries and registrations (UDP 137). |
| **LLDP Discovery** | `-l` | `-L` | Switch/system names and descriptions via LLDP (`0x88cc`). |
| **All Vectors** | `-a` | `-A` | Enables every vector above (`-a` deduplicated, `-A` raw). |
| **IPv6 Inspection** | `-v` | `-V` | Parses IPv6 traffic (filters link-local `fe80::/10`, ULA `fc00::/7`, and `::`). |

---

## Telemetry Output Format

In daemon mode, `argos-sniffer` outputs UTF-8 pipe-delimited (`|`) lines ready for scripts and logging daemons:

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

### Sample Output Stream

```text
root@router ~ # argos-sniffer br-lan
SYN|aa:bb:cc:dd:ee:01|10.0.0.254|64|64240|10|1460|M*,S,T,N,W*|1
DNS|aa:bb:cc:dd:ee:02|10.0.0.101|optimizationguide-pa.googleapis.com
MDNS|aa:bb:cc:dd:ee:03|10.0.0.187|5353|device-alpha.local
LLDP|aa:bb:cc:dd:ee:01|server-home.dnsprovider.org|Linux Distro 13 (codename) Linux 7.1.8+generic x86_64
SYN|aa:bb:cc:dd:ee:02|fd00:1234:5678:0:d050:6d30:f0c6:5232|64|65535|8|1432|M*,N,W*,N,N,S|443
SYNACK|aa:bb:cc:dd:ee:04|fd00:1234:5678::1|64|64440|7|1432|M*,N,N,S,N,W*|443
SNI|aa:bb:cc:dd:ee:02|fd00:1234:5678:0:d050:6d30:f0c6:5232|adguard.internal.dnsprovider.org
DNS|aa:bb:cc:dd:ee:02|10.0.0.101|wpad.lan
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|teams.events.data.microsoft.com
SYN|aa:bb:cc:dd:ee:03|10.0.0.187|128|65535|8|1460|M*,N,W*,N,N,S|443
SNI|aa:bb:cc:dd:ee:03|10.0.0.187|ngep.blackspider.com
DHCP|aa:bb:cc:dd:ee:05|0.0.0.0|CLIENT-DHCP|android-dhcp-client|1,3,6,15,26,28,51,58,59,43,114,108
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|connectivitycheck.gstatic.com
HTTP|aa:bb:cc:dd:ee:05|10.0.0.195|Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36
```

---

## Static Build (OpenWrt ARM64 Example)

Compile a self-contained static binary using an Alpine Docker container:

```sh
docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src alpine:latest sh -c "
  apk add --no-cache gcc musl-dev linux-headers && \
  gcc -Os -s -static \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -o argos-sniffer argos-sniffer.c"
```

---

## License

Distributed under the **GNU General Public License v3.0 (GPLv3)**.
