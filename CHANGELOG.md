# Changelog

All notable changes to **Argos Sniffer** are documented in this file.

The project follows release-oriented version history. Development experiments that are reverted before release are recorded when they are useful for explaining later design decisions. Older entries below are reconstructed conservatively from the repository's own commit history and historical source changelog notes; details that cannot be verified from the repository are intentionally omitted.

## [5.3.1]

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

## [5.3.0]

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

## [5.2.4]

### Telemetry output

- Finalized the CLI distinction between the two native UDP telemetry modes.
- `-u <ip>:<port>` is the **UDP-only** remote collector mode and does not retain stdout output.
- `-U <ip>:<port>` retains the distributed **UDP + stdout** fan-out behavior.
- Corrected README examples for UDP-only operation.
- Removed obsolete telemetry sink bookkeeping left behind by the output-path changes.

## [5.2.3]

### Release

- Bumped the sniffer release from 5.2.2 to **5.2.3** after the telemetry-output work.
- Preserved portable-test compilation without requiring syslog headers.
- Used debug-priority syslog handling for high-volume distributed telemetry where applicable.

## [5.2.2]

### Telemetry output

- Added native telemetry sink work for distributed operation.
- Added local syslog support during the initial 5.2.2 telemetry-output implementation.
- Added remote UDP telemetry fan-out while retaining stdout for a supervising local daemon.
- Documented the native UDP/stdout/syslog output paths and the trusted-path requirement for unencrypted UDP telemetry.

## [5.2.1]

### Repository & build layout

- Established **5.2.1** as the stable source release in the repository.
- Moved/standardized the build source path under `src/argos-sniffer.c` and updated README build commands accordingly.
- Added strict GitHub Actions compile validation for the full QUIC build and the `ARGOS_QUIC_STUB` build.
- Added static **ARM64** release builds, UPX-compressed ARM64 artifacts and SHA-256 release checksums.
- Added static **x86_64** builds and UPX-compressed x86_64 release artifacts.
- Added tagged-release asset publishing with source-version/tag consistency checks.

### Historical baseline carried into 5.2.x

- Passive `AF_PACKET` capture with TCP SYN/SYN-ACK fingerprinting and TCP option extraction.
- Target packet inspector (`-z`) and target-filtered structured telemetry (`-Z`).
- IPv4 and IPv6 local/private-source classification.
- VLAN-aware capture and userspace L2 extraction.
- Stateful telemetry deduplication/rate limiting.
- DHCP, DNS, mDNS, SSDP, WSD, NetBIOS, HTTP and TLS-oriented telemetry vectors present in the pre-5.2 codebase.

## [4.9.1]

### Discovery

- Added **WS-Discovery (WSD)** payload extraction on UDP/3702 to the `-m` / `-M` discovery vector.
- Extended L7 discovery handling from mDNS/SSDP to include WSD, improving passive identification opportunities for devices such as ONVIF cameras and printers.

### Design note

- At this historical point, QUIC/UDP 443 tracking was intentionally not implemented; later 5.x development superseded that decision with stateful QUIC/HTTP3 inspection.

## [4.9]

### Targeted telemetry

- Added `-Z <mac>` target-filtered telemetry for Mode 2 so structured fingerprinting could be restricted to one device.
- Added IPv6 private/local source classification as the IPv6 counterpart to the existing IPv4 source-address privacy filter.
- Increased the telemetry deduplication hash table from **512 to 4096 slots** to reduce collision-driven suppression resets on busy networks.
- Ignored `SIGPIPE` so a disappearing downstream log consumer no longer silently terminates the sniffer on the next stdout write.

## History policy

For future releases, add the newest version above the previous one and group notable changes under concise sections such as **Added**, **Changed**, **Fixed**, **Performance**, **Validation**, or **Security**. Keep temporary CI/helper workflows out of the release history unless they materially change how Argos is built or released.
