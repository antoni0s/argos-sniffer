# Argos Sniffer (`argos-sniffer`)

**`argos-sniffer`** is a high-performance, low-level packet capture written in **C** to feed a passive telemetry engine, built specifically for **OpenWrt** routers. 
It acts as the core data collection engine for the Argos Network Sentinel ecosystem, operating with zero network overhead and complete passivity.

---

## Purpose

Active network scanners (such as Nmap) can wake sleeping IoT devices, trigger battery-saving states, or congest home networks. **`argos-sniffer`** relies entirely on **Passive Network Sniffing**. 

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
argos-sniffer -i br-lan -r aa:bb:cc:00:11:22 -x aa:bb:cc:33:44:55 -a -f 35

# Mode 1: Live packet capture for a single device (replaces tcpdump, auto-enables promiscuous mode)
argos-sniffer -i br-lan -z aa:bb:cc:00:11:22 -c 50

# Mode 2: Restrict telemetry vectors to a single target device across the LAN
argos-sniffer -i br-lan -Z aa:bb:cc:00:11:22 -a -p
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
## Example Output Format
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
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|webdefence.global.blackspider.com
SYN|aa:bb:cc:dd:ee:03|10.0.0.187|128|65535|8|1460|M*,N,W*,N,N,S|8082
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|proxy.localdomain
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|ngep.blackspider.com
SYN|aa:bb:cc:dd:ee:03|10.0.0.187|128|65535|8|1460|M*,N,W*,N,N,S|443
SNI|aa:bb:cc:dd:ee:03|10.0.0.187|ngep.blackspider.com
DNS|aa:bb:cc:dd:ee:02|10.0.0.101|chrome.cloudflare-dns.com
DNS|aa:bb:cc:dd:ee:05|fd00:1234:5678:0:cf9:3ddf:64c4:d266|www.google.com
SYN|aa:bb:cc:dd:ee:05|10.0.0.195|64|65535|10|1212|M*,S,T,N,W*,?,N,N|853
SYN|aa:bb:cc:dd:ee:05|10.0.0.195|64|65535|10|1460|M*,S,T,N,W*|443
SNI|aa:bb:cc:dd:ee:05|10.0.0.195|api.weather.com
SYN|aa:bb:cc:dd:ee:06|10.0.0.110|64|65535|10|1212|M*,S,T,N,W*,?,N,N|853
SYNACK|aa:bb:cc:dd:ee:01|10.0.0.254|63|65160|10|1460|M*,S,T,N,W*|443
SYN|aa:bb:cc:dd:ee:06|10.0.0.110|64|65535|10|1460|M*,S,T,N,W*|443
L7|aa:bb:cc:dd:ee:02|10.0.0.101|1900|m-search * http/1.1  host: 239.255.255.250:1900  man: "ssdp:discover"  mx: 1  st: urn:dial-multiscreen-org:service:dial:1  user-agent: chromium/128.0.6613.138 windows
SNI|aa:bb:cc:dd:ee:06|10.0.0.110|eu-teams.events.data.microsoft.com
SNI|aa:bb:cc:dd:ee:06|10.0.0.110|mobile.pipe.aria.microsoft.com
L7|aa:bb:cc:dd:ee:01|10.0.0.254|1900|notify * http/1.1  host:239.255.255.250:1900  cache-control:max-age=130  location:http://10.0.0.254:8200/rootdesc.xml  server: linux dlnadoc/1.50 upnp/1.0 minidlna/1.3.3  nt:urn:schemas-upnp-org:service:connectionmanager:1  usn:uuid:4d696e69-444c-164e-9d41-aaubahost01::urn:schemas-upnp-org:service:connectionmanager:1  nts:ssdp:alive
DHCP|aa:bb:cc:dd:ee:05|0.0.0.0|CLIENT-DHCP|android-dhcp-client|1,3,6,15,26,28,51,58,59,43,114,108
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|connectivitycheck.gstatic.com
SYN|aa:bb:cc:dd:ee:05|10.0.0.195|64|65535|10|1460|M*,S,T,N,W*|80
SNI|aa:bb:cc:dd:ee:05|10.0.0.195|www.google.com
HTTP|aa:bb:cc:dd:ee:05|10.0.0.195|Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|dns.adguard-dns.com
L7|aa:bb:cc:dd:ee:05|10.0.0.195|1900|m-search * http/1.1  host: 239.255.255.250:1900  man: "ssdp:discover"  st: urn:schemas-upnp-org:device:internetgatewaydevice:1  mx: 1    m-search * http/1.1  host: 239.255.255.250:1900  man: "ssdp:discover"  st: urn:schemas-upnp-org:device:internetgatewaydevice:1  mx: 1    m-search * http/1.1  host: 239.255.255.250:1900  man: "ssdp:discover"  st: urn:schemas-upnp-org:device:internetgatewaydevice:1  mx: 1
HTTP|aa:bb:cc:dd:ee:05|10.0.0.195|Dalvik/2.1.0 (Linux; U; Android OS; Device-Model Build/RANDOMBUILD)
HTTP|aa:bb:cc:dd:ee:05|10.0.0.195|okhttp/4.9.3
SNI|aa:bb:cc:dd:ee:06|10.0.0.110|teams.events.data.microsoft.com
SNI|aa:bb:cc:dd:ee:05|10.0.0.195|next.internal.dnsprovider.org
SNI|aa:bb:cc:dd:ee:05|10.0.0.195|insight.samsunghealth.com
MDNS|aa:bb:cc:dd:ee:05|10.0.0.195|5353|1.195.0.10.in-addr.arpa
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|google.com
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|www.google.com
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|.google.com
DNS|aa:bb:cc:dd:ee:05|10.0.0.195|google.com.onion
SYN|aa:bb:cc:dd:ee:05|10.0.0.195|64|4000|-1|-1|none|53
L7|aa:bb:cc:dd:ee:05|10.0.0.195|1900|m-search * http/1.1  host: 239.255.255.250:1900  man: "ssdp:discover"  st: urn:schemas-upnp-org:device:internetgatewaydevice:1  mx: 1
SNI|aa:bb:cc:dd:ee:06|10.0.0.110|eu-mobile.events.data.microsoft.com
SNI|aa:bb:cc:dd:ee:06|10.0.0.110|api.weather.com
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|eu-office.events.data.microsoft.com
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|connectivitycheck.gstatic.com
DNS|aa:bb:cc:dd:ee:03|fd00:1234:5678:0:3c10:2c3e:2824:eb92|eu-v20.events.data.microsoft.com
SNI|aa:bb:cc:dd:ee:03|10.0.0.187|eu-v20.events.data.microsoft.com
```
---

### Static Compilation (Alpine Docker for OpenWrt ARM64)
```sh
docker run --rm --platform linux/arm64 -v "$PWD":/src -w /src alpine:latest sh -c "\
  apk add --no-cache gcc musl-dev linux-headers && \
  gcc -Os -s -static \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -o argos-sniffer argos-sniffer.c"
"
```

---

## License

This project is open-source software licensed under the **GNU General Public License v3.0 (GPLv3)**.
