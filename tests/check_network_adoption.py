"""Check the real runtime consumer and preserve cheap owner-cache gating."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "src/argos-sniffer.c").read_text()
loop = source[source.index("/* Main packet capture and processing loop */"):]
assert loop.count("argos_network_context4(") == 1
assert loop.count("argos_network_context6(") == 1
assert "argos_network_is_lan" not in loop
assert "argos_network_routed" not in loop
assert "argos_network_packet_context_t network_context = {0};" in loop
assert "int is_outbound = network_context.source_side;" in loop
assert "int routed_evidence = network_context.routed;" in loop
assert loop.index("argos_packet_decode(") < loop.index("argos_network_context4(")
assert loop.index("argos_network_context6(") < loop.index("if (filter_exclude.is_active")
assert loop.index("if (filter_mode1.is_active)") < loop.index("if (is_router_mac(src_mac))")
assert loop.index("if (is_router_mac(src_mac))") < loop.index("argos_raw_identity_v6(")
router = loop[loop.index("if (is_router_mac(src_mac))"):loop.index("argos_raw_identity_v6(")]
assert "!is_ip_packet || !argos_network_router_exception(ip_protocol," in router
assert "buffer + l4_offset, l3_packet_end - l4_offset, is_outbound)" in router
assert "memcpy" not in router and "len >= l4_offset" not in router
assert loop.count("argos_network_router_exception(") == 1
assert "argos_enterprise_parse_l2(l3_proto, buffer + l3_offset, l3_packet_end - l3_offset, &ent)" in loop
inspector = source[source.index("static void dump_target_packet("):].split("\n#endif", 1)[0]
assert "const argos_packet_view_t *v" in inspector
assert "ipv4_header_info" not in inspector and "ipv6_packet_info" not in inspector
assert "argos_packet_tcp_header_length" in inspector
assert "dump_target_packet(&packet_view);" in loop
assert loop.index("argos_raw_identity_v6(") < loop.index("if (filter_mode2.is_active)")
tcp = loop[loop.index("if (protocol == IPPROTO_TCP) {"):]
udp = tcp[tcp.index("else if (protocol == IPPROTO_UDP) {"):]
tcp = tcp[:tcp.index("else if (protocol == IPPROTO_UDP) {")]
for body, relevant in ((tcp, "tcp"), (udp, "udp")):
    assert body.index(f"if (!{relevant}_relevant)") < body.index("argos_network_owner6_mismatch")
    assert "if (!routed_evidence && is_outbound && (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED))" in body
print("Runtime network context and owner-gating invariants: PASS")
