"""Guard the real dispatch call sites, not a copied dispatcher implementation."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
s = (root / "src/argos-sniffer.c").read_text()
loop = s[s.index("/* Main packet capture and processing loop */"):]
tcp = loop[loop.index("if (protocol == IPPROTO_TCP) {"):]
udp = tcp[tcp.index("else if (protocol == IPPROTO_UDP) {"):]
tcp = tcp[:tcp.index("else if (protocol == IPPROTO_UDP) {")]
call = "argos_packet_transport_normalized(&packet_view, IPPROTO_"
assert loop.count(call) == 2
assert loop.index("if (!is_ip_packet) continue;") < loop.index(call)
assert loop.index("if (ipv4_is_frag) continue;") < loop.index(call)
assert tcp.index(call + "TCP") < tcp.index("memcpy(&tcp_hdr") < tcp.index("if (!tcp_relevant)")
assert udp.index("if (l4_offset + 8 > l3_packet_end)") < udp.index("ntohs(udp->dest)")
assert udp.index("if (!udp_relevant)") < udp.index("argos_network_owner6_mismatch") < udp.index(call + "UDP")
assert udp.index(call + "UDP") < udp.index("if (payload_len <= 0)") < udp.index("parse_dhcp6")
assert "tcp->doff" not in tcp and "udp->len" not in udp
assert "int tcp_hl = transport.header_len;" in tcp
assert "int opt_total = tcp_hl - 20" in tcp
print("Runtime transport adoption/order invariants: PASS")
