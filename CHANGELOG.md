# Changelog

All notable changes to **Argos Sniffer** are documented in this file.

The project follows release-oriented version history. Development experiments that are reverted before release are recorded when they are useful for explaining later design decisions.

## [5.3.1] - 2026-08-31

### Performance & packet capture

- Increased the requested Linux `AF_PACKET` receive buffer (`SO_RCVBUF`) from **1 MiB to 2 MiB** to provide more headroom during burst traffic.
- Kept the established **level-triggered epoll + single `recvmsg()` per readiness event** receive path.
- Tested a bounded synchronous RX-drain implementation and reverted it after runtime testing showed increased `AF_PACKET` packet drops under burst traffic.
- Added a conservative classic-BPF kernel prefilter for normal capture mode so irrelevant traffic can be discarded before consuming userspace receive-buffer capacity.
- Added kernel-side suppression of **zero-payload IPv4 TCP ACK/window-update packets**. TCP SYN/FIN/RST packets remain visible, while payload-bearing HTTP/HTTPS traffic required by the HTTP/TLS parsers is retained.
- Kept live packet-dump mode (`-z`) outside the Argos kernel prefilter so live inspection remains unrestricted.

### Kernel prefilter safety

- ARP and LLDP remain accepted.
- IPv6 remains accepted wholesale to avoid unsafe assumptions around extension-header offsets.
- VLAN, QinQ and PPPoE frames remain accepted wholesale so encapsulated traffic is not incorrectly discarded by fixed-offset rules.
- Untagged IPv4 TCP retains SYN/FIN/RST and useful payload-bearing HTTP/TLS traffic.
- Untagged IPv4 UDP retains Argos discovery, DNS and QUIC traffic.

### Validation

- Source changes validated with `gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror`.
- Kernel-filter changes validated with a real Linux `AF_PACKET` + `SO_ATTACH_FILTER` smoke test.
- Runtime burst testing included sustained HTTPS transfers and `PACKET_STATISTICS` drop monitoring.

## [5.3.0] - 2026-08-31

### SPAN / TAP sensor mode

- Added native `--sensor` operation for dedicated Linux SPAN/mirror-port and network-TAP deployments.
- Added `--sensor-name NAME` for stable sensor identity.
- Added repeatable `--inside CIDR` definitions for explicit inside-network classification, including unnumbered capture interfaces.
- Sensor mode requires an explicit capture interface and rejects `-i any`.
- Sensor mode automatically enables promiscuous capture.
- Added sensor observation envelope while preserving the existing Argos telemetry record as the payload:

  `OBS|sensor_name|interface|vlan|<legacy Argos record>`

- Added VLAN/QinQ observation context, including Linux `PACKET_AUXDATA` support when NIC hardware strips VLAN tags.
- Preserved legacy gateway mode and legacy telemetry format by default.
- Reused the existing protocol parsers and fingerprinting vectors in both gateway and sensor modes.

### Deployment

- Added Linux SPAN/TAP deployment documentation and examples.
- Added dedicated amd64 and arm64 sensor build artifacts/workflow support.

## History policy

For future releases, add the newest version above the previous one and group notable changes under concise sections such as **Added**, **Changed**, **Fixed**, **Performance**, **Validation**, or **Security**. Keep temporary CI/helper workflows out of the release history unless they materially change how Argos is built or released.
