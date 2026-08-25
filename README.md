# Argos Sniffer (`argos-sniffer`)

**`argos-sniffer`** is the high-performance, low-level packet capture and passive telemetry engine written in **C**, built specifically for **OpenWrt** routers. It acts as the core data collector for the Argos Network Sentinel ecosystem, operating with zero network overhead and complete passivity.

---

## Purpose

Active network scanners (such as Nmap) can wake sleeping IoT devices, trigger power-saving states, or congest home networks. **`argos-sniffer`** eliminates these issues by relying entirely on **Passive Network Sniffing**. 

Its core objectives are:
* **Zero-Impact Monitoring:** Listens silently to network traffic passing through the bridge/interface without injecting or modifying packets.
* **Real-Time Fingerprinting:** Extracts device identifiers, operating systems, and application-layer protocols on the fly.
* **Lightweight Footprint:** Designed as a standalone compiled C binary optimized for embedded OpenWrt environments (ARM/MIPS/x86), ensuring minimal CPU and memory consumption.

---

## Supported Vectors & CLI Flags

The sniffer uses granular command-line flags to control which telemetry vectors are captured, parsed, and streamed to a daemon:

argos-sniffer v4.8 - Passive LAN traffic fingerprinter & live inspector for OpenWrt

USAGE:
  argos-sniffer [-i iface] [-r router_mac] [-z target_mac] [-f seconds] [FLAGS...]

OPTIONS:
  -i <iface>      Interface to listen on (default: br-lan)
  -r <mac>        Router's own MAC (can be used multiple times) to exclude self-profiling
  -z <target_mac> Native Live Sniffer mode for a specific MAC (replaces tcpdump)
  -c <count>      Maximum packet count before exiting (default: 0 for unlimited)
  -p              Enable promiscuous mode (auto-enabled if -z is set)
  -f <seconds>    Deduplication window in seconds (default: 35)

TELEMETRY VECTORS (Lowercase = ENABLE WITH RATE LIMIT | Uppercase = ENABLE NO LIMIT):
  -s / -S         TCP SYN (p0f) & SYNACK (open ports) fingerprinting
  -m / -M         mDNS (5353) / SSDP (1900) payload logging
  -d / -D         DHCP options (Hostname, VCI, PRL Option 55) logging
  -n / -N         NetBIOS Name Service (UDP 137) logging
  -q / -Q         DNS Queries (UDP port 53)
  -h / -H         HTTP User-Agent extraction (port 80/8080)
  -t / -T         TLS ClientHello SNI extraction (port 443)
  -l / -L         LLDP (L2 neighbor discovery)
  -a / -A         Enable ALL vectors above (a = with limits, A = without limits)
  -v / -V         Enable IPv6 handling

OUTPUT FORMAT (pipe-delimited for daemon, or formatted text for -z):
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



## Source Code & Compilation

The source code is located at `usr/share/argos/src/argos-sniffer.c`. 

### Manual Cross-Compilation (Example for OpenWrt ARM64/Alpine Docker):
```sh
docker run --rm -v $(pwd):/workspace alpine sh -c "
    apk add build-base libpcap-dev upx
    gcc -O3 -static /workspace/usr/share/argos/src/argos-sniffer.c -lpcap -o /workspace/usr/bin/argos-sniffer
    upx --best /workspace/usr/bin/argos-sniffer
"
