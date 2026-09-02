#!/usr/bin/env python3
from pathlib import Path

p = Path("src/argos-sniffer.c")
s = p.read_text(encoding="utf-8")


def replace_once(old: str, new: str, label: str) -> None:
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {n}")
    s = s.replace(old, new, 1)


def insert_before(marker: str, text: str, label: str) -> None:
    global s
    n = s.count(marker)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one marker, found {n}")
    s = s.replace(marker, text + marker, 1)


replace_once('#include "argos_quic_heavy.h"\n#endif\n',
             '#include "argos_quic_heavy.h"\n#endif\n#include "argos_enterprise.h"\n',
             'enterprise header include')
replace_once('#define VERSION "5.3.1"', '#define VERSION "6.0.0-dev"', 'version bump')

# Extend Ethernet parsing with the 802.3 LLC/SNAP families used by CDP and IS-IS.
insert_before(
    '        /* PPPoE Session stage (common on DSL/fiber ONTs): 6-byte PPPoE\n',
    '''        /* IEEE 802.3 + LLC/SNAP control protocols. The 16-bit field at\n         * Ethernet offset 12 is a payload length (<=1500), not an EtherType.\n         * CDP uses SNAP OUI 00:00:0c + PID 0x2000. IS-IS uses LLC FE:FE:03. */\n        if (eth_type <= 1500U) {\n            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&\n                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&\n                buffer[offset + 4] == 0x00U && buffer[offset + 5] == 0x0cU &&\n                read_be16(buffer + offset + 6) == 0x2000U) {\n                *l3_proto = 0x2000U;\n                return offset + 8;\n            }\n            if (len >= offset + 3 && buffer[offset] == 0xfeU && buffer[offset + 1] == 0xfeU &&\n                buffer[offset + 2] == 0x03U) {\n                *l3_proto = 0x00feU;\n                return offset + 3;\n            }\n            return -1;\n        }\n''',
    '802.3 LLC/SNAP support')

# CLI state and long options. Enterprise stays opt-in during the v6 development cycle.
replace_once(
    '    int opt_syn = 0, opt_multi = 0, opt_dhcp = 0, opt_netbios = 0, opt_dns = 0, opt_http = 0, opt_tls = 0, opt_l2 = 0, opt_v6 = 0, opt_promisc = 0;\n'
    '    int opt_syn_rl = 0, opt_multi_rl = 0, opt_dhcp_rl = 0, opt_netbios_rl = 0, opt_dns_rl = 0, opt_http_rl = 0, opt_tls_rl = 0, opt_l2_rl = 0;\n'
    '    int opt;\n'
    '    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE };\n',
    '    int opt_syn = 0, opt_multi = 0, opt_dhcp = 0, opt_netbios = 0, opt_dns = 0, opt_http = 0, opt_tls = 0, opt_l2 = 0, opt_v6 = 0, opt_promisc = 0;\n'
    '    int opt_syn_rl = 0, opt_multi_rl = 0, opt_dhcp_rl = 0, opt_netbios_rl = 0, opt_dns_rl = 0, opt_http_rl = 0, opt_tls_rl = 0, opt_l2_rl = 0;\n'
    '    int opt_enterprise = 0, opt_enterprise_rl = 1;\n'
    '    int opt;\n'
    '    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE, OPT_ENTERPRISE, OPT_ENTERPRISE_VERBOSE };\n',
    'enterprise CLI state')
replace_once(
    '        {"inside", required_argument, NULL, OPT_INSIDE},\n'
    '        {NULL, 0, NULL, 0}\n',
    '        {"inside", required_argument, NULL, OPT_INSIDE},\n'
    '        {"enterprise", no_argument, NULL, OPT_ENTERPRISE},\n'
    '        {"enterprise-verbose", no_argument, NULL, OPT_ENTERPRISE_VERBOSE},\n'
    '        {NULL, 0, NULL, 0}\n',
    'enterprise long options')
replace_once(
    '            case OPT_INSIDE: if (!add_inside_prefix(optarg)) return 1; break;\n'
    "            case 'E': opt_ext_metrics = 1; break;\n",
    '            case OPT_INSIDE: if (!add_inside_prefix(optarg)) return 1; break;\n'
    '            case OPT_ENTERPRISE: opt_enterprise = 1; opt_enterprise_rl = 1; opt_v6 = 1; break;\n'
    '            case OPT_ENTERPRISE_VERBOSE: opt_enterprise = 1; opt_enterprise_rl = 0; opt_v6 = 1; break;\n'
    "            case 'E': opt_ext_metrics = 1; break;\n",
    'enterprise switch cases')
replace_once(
    '    if (!filter_mode1.is_active && !opt_syn && !opt_multi && !opt_dhcp && !opt_netbios && !opt_dns && !opt_http && !opt_tls && !opt_l2) {\n',
    '    if (!filter_mode1.is_active && !opt_syn && !opt_multi && !opt_dhcp && !opt_netbios && !opt_dns && !opt_http && !opt_tls && !opt_l2 && !opt_enterprise) {\n',
    'default vector condition')

# Help text and telemetry contract.
replace_once(
    '"     [--sensor --sensor-name name [--inside CIDR ...]]\\n"\n',
    '"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose]\\n"\n',
    'help usage')
replace_once(
    '"  -W              Enable Stateful QUIC Inspection (reassembles fragmented Kyber ClientHellos)\\n"\n',
    '"  --enterprise    Enable v6 enterprise handshake/discovery fingerprints (rate-limited).\\n"\n'
    '"  --enterprise-verbose  Enable enterprise fingerprints without telemetry deduplication.\\n"\n'
    '"  -W              Enable Stateful QUIC Inspection (reassembles fragmented Kyber ClientHellos)\\n"\n',
    'help enterprise options')
replace_once(
    '"  -l / -L         LLDP + ARP + IPv6 NDP/Router Advertisement discovery\\n"\n'
    '"  -a / -A         Enable ALL vectors above (a = with limits, A = without limits)\\n"\n',
    '"  -l / -L         LLDP + ARP + IPv6 NDP/Router Advertisement discovery\\n"\n'
    '"  --enterprise    Enterprise/storage/identity/routing/OT control-plane fingerprints\\n"\n'
    '"                  (development opt-in; intentionally not implied by -a/-A yet)\\n"\n'
    '"  -a / -A         Enable ALL legacy vectors above (a = with limits, A = without limits)\\n"\n',
    'help enterprise vector')
replace_once(
    '"  L7|mac|src_ip|dst_port|payload[|routed]\\n\\n"\n',
    '"  L7|mac|src_ip|dst_port|payload[|routed]\\n"\n'
    '"  ENT|mac|src_ip|dst_ip|protocol|fingerprint[|routed]\\n\\n"\n',
    'help ENT output')

# Use an expanded cBPF whitelist only when enterprise mode is enabled.
replace_once(
    '            if (attach_argos_kernel_filter(sock) < 0) {\n',
    '            if ((opt_enterprise ? attach_argos_enterprise_kernel_filter(sock) : attach_argos_kernel_filter(sock)) < 0) {\n',
    'enterprise kernel filter selection')

# Accept the enterprise L2 protocols into the normal packet identity pipeline.
replace_once(
    '            } else if (l3_proto == 0x88cc || l3_proto == 0x0806) {\n'
    '                /* LLDP / ARP: no IP addresses. Filters can still match on MAC.\n',
    '            } else if (l3_proto == 0x88cc || l3_proto == 0x0806 ||\n'
    '                       (opt_enterprise && (l3_proto == 0x888eU || l3_proto == 0x8892U ||\n'
    '                                           l3_proto == 0x2000U || l3_proto == 0x00feU))) {\n'
    '                /* L2 discovery/control: no IP addresses. Filters can still match on MAC.\n',
    'enterprise L2 admission')
replace_once(
    '            if (l3_proto == 0x88cc || l3_proto == 0x0806) {\n'
    '                memcpy(device_mac, src_mac, 6);\n',
    '            if (l3_proto == 0x88cc || l3_proto == 0x0806 ||\n'
    '                (opt_enterprise && (l3_proto == 0x888eU || l3_proto == 0x8892U ||\n'
    '                                    l3_proto == 0x2000U || l3_proto == 0x00feU))) {\n'
    '                memcpy(device_mac, src_mac, 6);\n',
    'enterprise L2 source identity')

insert_before(
    '            if (l3_proto == 0x0806) {\n',
    '''            if (opt_enterprise && (l3_proto == 0x888eU || l3_proto == 0x8892U ||\n                                   l3_proto == 0x2000U || l3_proto == 0x00feU)) {\n                argos_enterprise_result_t ent;\n                if (argos_enterprise_parse_l2(l3_proto, buffer + l3_offset, (int)len - l3_offset, &ent) && ent.emit) {\n                    char ent_sig[640];\n                    snprintf(ent_sig, sizeof(ent_sig), "%s|%s", ent.proto, ent.detail);\n                    if (!dedup_should_suppress(mac_str, "ENT", ent_sig, opt_enterprise_rl))\n                        emit_telemetry("ENT|%s|-|-|%s|%s\\n", mac_str, ent.proto, ent.detail);\n                }\n                continue;\n            }\n''',
    'enterprise L2 telemetry')

# OSPF is an IP protocol rather than TCP/UDP. Only Hello packets are parsed.
insert_before(
    '            if (protocol == IPPROTO_TCP) {\n',
    '''            if (opt_enterprise && protocol == 89U && l4_offset >= 0 && l4_offset < l3_packet_end) {\n                argos_enterprise_result_t ent;\n                if (argos_enterprise_parse_ipproto(protocol, buffer + l4_offset, l3_packet_end - l4_offset, &ent) && ent.emit) {\n                    char ent_mac[18], ent_sig[640];\n                    if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);\n                    else format_mac(src_mac, ent_mac);\n                    snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent.proto, ent.detail);\n                    if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                        emit_telemetry("ENT|%s|%s|%s|%s|%s%s\\n", ent_mac, src_ip_str, dst_ip_str, ent.proto, ent.detail, routed_str);\n                }\n                continue;\n            }\n\n''',
    'OSPF parser integration')

# Enterprise TCP becomes relevant, reuses the existing fixed flow table and packet budget.
replace_once(
    '                int tcp_relevant = (opt_syn && (tcp->syn || tcp->rst || tcp->fin)) ||\n'
    '                                   (opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                   (opt_tls && dport == 443U);\n',
    '                int tcp_relevant = (opt_syn && (tcp->syn || tcp->rst || tcp->fin)) ||\n'
    '                                   (opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                   (opt_tls && dport == 443U) ||\n'
    '                                   (opt_enterprise && argos_enterprise_tcp_port(sport, dport));\n',
    'enterprise TCP relevance')
replace_once(
    '                int app_track = payload_len > 0 &&\n'
    '                                ((opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                 (opt_tls && dport == 443U));\n',
    '                int enterprise_tcp = opt_enterprise && argos_enterprise_tcp_port(sport, dport);\n'
    '                int app_track = payload_len > 0 &&\n'
    '                                ((opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                 (opt_tls && dport == 443U) || enterprise_tcp);\n',
    'enterprise app tracking')
insert_before(
    '                if (app_track) {\n'
    '                    int fingerprint_complete = app_flow_payload_complete(\n',
    '''                argos_enterprise_result_t ent_tcp;\n                int ent_tcp_seen = 0;\n                if (enterprise_tcp && payload_len > 0) {\n                    ent_tcp_seen = argos_enterprise_parse_tcp(sport, dport, buffer + payload_offset, payload_len, &ent_tcp);\n                    if (ent_tcp_seen && ent_tcp.emit) {\n                        char ent_mac[18], ent_sig[768];\n                        if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);\n                        else format_mac(src_mac, ent_mac);\n                        snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent_tcp.proto, ent_tcp.detail);\n                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                            emit_telemetry("ENT|%s|%s|%s|%s|%s%s\\n", ent_mac, src_ip_str, dst_ip_str, ent_tcp.proto, ent_tcp.detail, routed_str);\n                    }\n                }\n\n''',
    'enterprise TCP parser')
replace_once(
    '                    int fingerprint_complete = app_flow_payload_complete(\n'
    '                        dport, buffer + payload_offset, payload_len);\n'
    '                    app_flow_note_payload(flow_ip_version, flow_src_addr, flow_dst_addr,\n',
    '                    int fingerprint_complete = app_flow_payload_complete(\n'
    '                        dport, buffer + payload_offset, payload_len);\n'
    '                    if (ent_tcp_seen && ent_tcp.complete) fingerprint_complete = 1;\n'
    '                    app_flow_note_payload(flow_ip_version, flow_src_addr, flow_dst_addr,\n',
    'enterprise flow complete')

# Enterprise UDP is stateless and does not allocate/track flows.
replace_once(
    '                                   (opt_dns && (dport == 53U || sport == 53U)) ||\n'
    '                                   (opt_tls && dport == 443U);\n',
    '                                   (opt_dns && (dport == 53U || sport == 53U)) ||\n'
    '                                   (opt_tls && dport == 443U) ||\n'
    '                                   (opt_enterprise && argos_enterprise_udp_port(sport, dport));\n',
    'enterprise UDP relevance')
insert_before(
    '            }\n        }\n        if (opt_v6) {\n',
    '''                if (opt_enterprise && argos_enterprise_udp_port(sport, dport)) {\n                    argos_enterprise_result_t ent_udp;\n                    if (argos_enterprise_parse_udp(sport, dport, payload, payload_len, &ent_udp) && ent_udp.emit) {\n                        char ent_mac[18], ent_sig[768];\n                        if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);\n                        else format_mac(src_mac, ent_mac);\n                        snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent_udp.proto, ent_udp.detail);\n                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                            emit_telemetry("ENT|%s|%s|%s|%s|%s%s\\n", ent_mac, src_ip_str, dst_ip_str, ent_udp.proto, ent_udp.detail, routed_str);\n                    }\n                }\n''',
    'enterprise UDP parser')

p.write_text(s, encoding="utf-8")
print("v6 enterprise integration applied successfully")
