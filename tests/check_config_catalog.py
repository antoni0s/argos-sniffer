#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
backlog = (ROOT / "V6_BACKLOG.md").read_text(encoding="utf-8")
header = (ROOT / "src/argos_config.h").read_text(encoding="utf-8")
dispatch = (ROOT / "src/argos_dispatch.h").read_text(encoding="utf-8")
bpf_source = (ROOT / "src/argos_bpf.h").read_text(encoding="utf-8")
main_source = (ROOT / "src/argos-sniffer.c").read_text(encoding="utf-8")

taxonomy = backlog.split("## Canonical CLI taxonomy backlog", 1)[1]
taxonomy = taxonomy.split("## Canonical vector schema backlog", 1)[0]
expected = {}
for line in taxonomy.splitlines():
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if len(cells) != 3 or cells[0] in {"Super-group", "---"}:
        continue
    if not re.fullmatch(r"[a-z-]+", cells[0]):
        continue
    expected[cells[1]] = (cells[0], [item.strip() for item in cells[2].split(",")])

group_block = header.split("#define ARGOS_GROUP_CATALOG(X)", 1)[1]
group_block = group_block.split("typedef enum", 1)[0]
groups = {
    ident: (super_name.lower(), name)
    for ident, super_name, name in re.findall(
        r'X\(([A-Z0-9_]+), ([A-Z0-9_]+), "([a-z0-9-]+)"\)', group_block
    )
}

protocol_block = header.split("#define ARGOS_PROTOCOL_CATALOG(X)", 1)[1]
protocol_block = protocol_block.split("typedef enum", 1)[0]
protocols = {
    ident: (super_name.lower(), name)
    for ident, super_name, name in re.findall(
        r'X\(([A-Z0-9_]+), ([A-Z0-9_]+), "([a-z0-9-]+)",', protocol_block
    )
}

membership_block = header.split("#define ARGOS_GROUP_MEMBERSHIP_CATALOG(X)", 1)[1]
membership_block = membership_block.split("static const argos_group_membership_t", 1)[0]
actual = {name: (super_name, []) for _, (super_name, name) in groups.items()}
for group_id, protocol_id in re.findall(
    r'X\(([A-Z0-9_]+), ([A-Z0-9_]+)\)', membership_block
):
    assert group_id in groups, f"unknown group id {group_id}"
    assert protocol_id in protocols, f"unknown protocol id {protocol_id}"
    super_name, group_name = groups[group_id]
    protocol_super, protocol_name = protocols[protocol_id]
    assert super_name == protocol_super, f"{group_name}/{protocol_name} crosses super-groups"
    actual[group_name][1].append(protocol_name)

assert actual == expected, "V6_BACKLOG taxonomy and argos_config catalog differ"
assert len(protocols) == 101
assert len(actual) == 28

# Runtime adoption gate: legacy argv flags must compile through the canonical
# owner once, then produce the fixed startup dispatch plan before capture.
required_main_markers = (
    "argos_cli_selection_init(&cli_selection)",
    "argos_cli_selection_apply_legacy(&cli_selection",
    "argos_cli_selection_apply_legacy_all(&cli_selection",
    "argos_cli_selection_finalize(&cli_selection)",
    "argos_dispatch_plan_compile(&dispatch_plan, &cli_selection)",
    "argos_dispatch_any_rate_limited(&dispatch_plan)",
    '{"profile", required_argument, NULL, OPT_PROFILE}',
    '{"super-group", required_argument, NULL, OPT_SUPER_GROUP}',
    '{"group", required_argument, NULL, OPT_GROUP}',
    '{"protocol", required_argument, NULL, OPT_PROTOCOL}',
    '{"no-rate-limit", required_argument, NULL, OPT_NO_RATE_LIMIT}',
    "ARGOS_CLI_SELECTOR_PROFILE, optarg",
    "ARGOS_CLI_SELECTOR_SUPER_GROUP, optarg",
    "ARGOS_CLI_SELECTOR_GROUP, optarg",
    "ARGOS_CLI_SELECTOR_PROTOCOL, optarg",
    "ARGOS_CLI_SELECTOR_NO_RATE_LIMIT, optarg",
)
for marker in required_main_markers:
    assert marker in main_source, f"missing runtime config adoption marker: {marker}"
assert "opt_syn = opt_multi = opt_dhcp" not in main_source
packet_loop = main_source.split("argos_capture_open(&capture", 1)[1]
assert "cli_selection" not in packet_loop, "selection compiler leaked into packet processing"
assert "argos_cli_selection_" not in packet_loop, "selection API leaked into packet processing"
assert "dispatch_plan" in packet_loop, "fixed dispatch plan is not consumed by packet processing"
assert "argos_protocol_catalog" not in packet_loop, "protocol catalog leaked into packet processing"
assert "argos_dispatch_plan_compile" in dispatch

# BPF must consume the same fixed plan at startup. Link/network admission may
# not regress to the removed broad l2/ipv6 fields or main-local reconstruction.
assert "argos_bpf_config_compile(&bpf_cfg, &dispatch_plan" in main_source
assert ".l2 =" not in main_source and ".ipv6 =" not in main_source
assert "cfg->protocols = plan->protocols.enabled" in bpf_source
for obsolete in ("cfg->multi", "cfg->dhcp", "cfg->netbios", "cfg->dns",
                 "cfg->http", "cfg->tls", "cfg->enterprise"):
    assert obsolete not in bpf_source, f"coarse BPF gate remains: {obsolete}"
for protocol in ("HTTP", "NTLM", "TLS", "DOT", "QUIC", "DHCP", "NBNS", "DNS",
                 "SSDP", "UPNP", "WSD", "MDNS", "WIREGUARD", "STUN_TURN"):
    assert f"HAS({protocol})" in bpf_source, f"exact BPF gate missing: {protocol}"
for route in (
    "ARGOS_DISPATCH_L2_ARP", "ARGOS_DISPATCH_L2_LLDP",
    "ARGOS_DISPATCH_L2_LLC", "ARGOS_DISPATCH_L2_SLOW",
    "ARGOS_DISPATCH_L2_EAPOL", "ARGOS_DISPATCH_L2_PROFINET",
    "ARGOS_DISPATCH_L2_PTP",
    "ARGOS_DISPATCH_L3_IPV6", "ARGOS_DISPATCH_L3_IGMP",
    "ARGOS_DISPATCH_L3_OSPF", "ARGOS_DISPATCH_L3_VRRP",
    "ARGOS_DISPATCH_L3_ESP", "ARGOS_DISPATCH_L3_AH",
    "ARGOS_DISPATCH_L4_TCP", "ARGOS_DISPATCH_L4_UDP",
):
    assert route in bpf_source, f"canonical BPF route missing: {route}"
for fallback in ("0x8100", "0x88a8", "0x8864"):
    assert f"abpf_pass_ethertype(p, {fallback})" in bpf_source
for readiness_marker in ("HAS(PTP)", "ARGOS_DISPATCH_L2_PTP",
                         "ARGOS_DISPATCH_L3_ESP", "ARGOS_DISPATCH_L3_AH"):
    assert readiness_marker in bpf_source, f"missing no-port/PTP readiness gate: {readiness_marker}"

# First fine-grained consumer slice: every native-L2/non-port parser must have
# its canonical engine gate in the immediately enclosing source region.
parser_gates = {
    "parse_lldp(": "ARGOS_PROTOCOL_LLDP",
    "argos_lldp_med_parse(": "ARGOS_PROTOCOL_LLDP_MED",
    "argos_stp_parse(": "ARGOS_PROTOCOL_STP",
    "argos_lacp_parse(": "ARGOS_PROTOCOL_LACP",
    "argos_enterprise_parse_l2(": "l2_engine",
    "parse_arp_vector(": "ARGOS_PROTOCOL_ARP",
    "argos_mld_parse(": "ARGOS_PROTOCOL_MLD",
    "parse_ndp_vector(": "nd_engine",
    "argos_igmp_parse(": "ARGOS_PROTOCOL_IGMP",
    "argos_vrrp_parse(": "ARGOS_PROTOCOL_VRRP",
    "argos_enterprise_parse_ipproto(": "ARGOS_PROTOCOL_OSPF",
}
for parser, gate in parser_gates.items():
    call = packet_loop.index(parser)
    assert gate in packet_loop[max(0, call - 1400):call], f"{parser} lacks {gate} gate"
assert "runtime_cfg.enterprise_enabled && l3_proto" not in packet_loop
assert "runtime_cfg.enterprise_enabled && protocol == 2U" not in packet_loop
assert "runtime_cfg.enterprise_enabled && protocol == 112U" not in packet_loop
assert "runtime_cfg.enterprise_enabled && protocol == 89U" not in packet_loop

# Transport callers use protocol bits/port-engine resolution before parser or
# state work; compatibility category booleans may not leak into the packet loop.
for obsolete in (
    "opt_multi", "opt_dhcp", "opt_netbios", "opt_dns", "opt_http", "opt_tls",
    "runtime_cfg.enterprise_enabled", "runtime_cfg.enterprise_rate_limited",
):
    assert obsolete not in packet_loop, f"coarse transport gate leaked: {obsolete}"
for marker in (
    "argos_dispatch_tcp_port_engine(",
    "argos_dispatch_udp_port_engine(",
    "ARGOS_PROTOCOL_HTTP", "ARGOS_PROTOCOL_QUIC", "ARGOS_PROTOCOL_WIREGUARD",
    "ARGOS_PROTOCOL_NTLM", "ARGOS_PROTOCOL_RADIUS",
):
    assert marker in packet_loop, f"missing transport gate: {marker}"
for parser, gate in {
    "parse_tls_sni(": "tls_tcp || dot_tcp",
    "argos_enterprise_parse_tcp(": "tcp_engine < ARGOS_PROTOCOL_COUNT",
    "ae_http_proxy(": "proxy_tcp && payload_len > 0",
    "ae_telnet(": "telnet_tcp && payload_len > 0",
    "ae_winrm(": "winrm_tcp && payload_len > 0",
    "argos_enterprise_parse_udp(": "udp_engine < ARGOS_PROTOCOL_COUNT",
    "argos_identity_ntlm_type3(": "ARGOS_PROTOCOL_NTLM",
    "argos_identity_radius_access_request(": "ARGOS_PROTOCOL_RADIUS",
    "argos_network_rip_parse(": "udp_engine == ARGOS_PROTOCOL_RIP",
}.items():
    call = packet_loop.index(parser)
    assert gate in packet_loop[max(0, call - 1800):call], f"{parser} lacks {gate} gate"
assert "app_demand && tcp->syn" in packet_loop
assert "if (app_track && argos_flow_should_skip" in packet_loop
assert "if (emit_tls &&" in main_source
assert "if (emit_dot && dport == 853U" in main_source
assert "argos_network_ptp_parse(" in main_source
assert "argos_dispatch_ptp_udp_enabled(&dispatch_plan, sport, dport)" in main_source
assert "l3_proto == 0x88f7U" in main_source
assert 'dedup_should_suppress(mac, "PTP",' in main_source
assert 'emit_telemetry("PTP|%s|%s|%s|%s%s\\n"' in main_source
assert 'emit_telemetry("ENT|%s|%s|%s|PTP|' not in main_source
assert 'argos_network_rip_parse(' in main_source
assert 'argos_network_ripng_parse(' in main_source
assert 'dedup_should_suppress(mac_str, "RIP", rip.detail' in main_source
assert 'emit_telemetry("RIP|%s|%s|%s|%s%s\\n"' in main_source
assert 'emit_telemetry("ENT|%s|%s|%s|RIP|' not in main_source
for vector in ("SYSLOG", "NETFLOW", "IPFIX", "SFLOW", "LPD", "HTTP-PROXY", "TELNET", "VNC", "WINRM"):
    assert f'return "{vector}"' in main_source
    assert f'emit_telemetry("ENT|%s|%s|%s|{vector}|' not in main_source
assert 'dedup_should_suppress(text_mac, vector ? vector : "ENT"' in main_source
assert 'emit_telemetry("%s|%s|%s|%s|%s%s\\n", vector' in main_source
assert "emit_enterprise_result(tcp_engine, &ent_tcp" in main_source
assert "emit_enterprise_result(udp_engine, &ent_udp" in main_source
assert "if (engine == ARGOS_PROTOCOL_LPD) return 1;" in main_source
assert not (ROOT / "src" / ("argos_" + "lpd.h")).exists()
assert not (ROOT / "src" / ("argos_" + "http_proxy.h")).exists()
assert not (ROOT / "src" / ("argos_" + "telnet.h")).exists()
assert "if (telnet_tcp) fingerprint_complete = 1;" in main_source
assert not (ROOT / "src" / ("argos_" + "vnc.h")).exists()
assert "if (vnc_tcp)" in packet_loop
assert packet_loop.index("parse_vnc_flow(") < packet_loop.index("if (app_track && argos_flow_should_skip")
assert "argos_flow_prepare_context(&runtime_state.application)" not in packet_loop
assert not (ROOT / "src" / ("argos_" + "winrm.h")).exists()
assert "argos_dispatch_winrm_enabled" in packet_loop
assert "ae_winrm(" in packet_loop
assert "ARGOS_WINRM_HTTP_PORT" in bpf_source and "ARGOS_WINRM_HTTPS_PORT" in bpf_source
for obsolete in ("argos_syslog.h", "argos_netflow.h", "argos_ipfix.h", "argos_sflow.h"):
    assert not (ROOT / "src" / obsolete).exists(), f"obsolete staging header remains: {obsolete}"
for vector in ("LLDP-MED", "STP", "LACP"):
    assert f'dedup_should_suppress(mac_str, "{vector}"' in main_source
    assert f'emit_telemetry("{vector}|%s|-|-|%s%s\\n"' in main_source
for legacy in ("LLDP-MED", "STP", "RSTP", "MSTP", "LACP"):
    assert f'emit_telemetry("ENT|%s|-|-|{legacy}|' not in main_source
print("Canonical config catalog matches V6_BACKLOG taxonomy: PASS")
