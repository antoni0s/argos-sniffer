from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
main_path = ROOT / "src/argos-sniffer.c"

source = main_path.read_text()

include_anchor = '#include "argos_telemetry.h"\n'
if source.count(include_anchor) != 1:
    raise SystemExit("unexpected telemetry include count")
source = source.replace(include_anchor, include_anchor + '#include "argos_packet.h"\n', 1)

link_enum = "typedef enum { LINK_UNSUPPORTED = 0, LINK_ETHERNET = 1, LINK_RAW_IP = 2, LINK_COOKED = 3, LINK_PER_PACKET = 4 } link_type_t;\n"
if source.count(link_enum) != 1:
    raise SystemExit("link type enum anchor changed")
source = source.replace(link_enum, "", 1)

read_be = "static inline uint16_t read_be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }\n"
if source.count(read_be) != 1:
    raise SystemExit("read_be16 anchor changed")
source = source.replace(read_be, "", 1)

skip_start = source.index("/**\n * Walk IPv6 extension headers")
skip_end = source.index("#ifndef ARGOS_PORTABLE_TEST\nstatic link_type_t hatype_to_link", skip_start)
source = source[:skip_start] + source[skip_end:]

strip_start = source.index("static uint16_t frame_outer_vlan = 0;")
strip_end = source.index("/* ============================================================================\n * SECTION: Shunting-Yard Filter Engine", strip_start)
source = source[:strip_start] + source[strip_end:]

ip_helpers_start = source.index("static int ipv4_header_info(")
ip_helpers_end = source.index("static void dump_target_packet(", ip_helpers_start)
source = source[:ip_helpers_start] + source[ip_helpers_end:]

normalize_start = source.index("            unsigned char src_mac[6], dst_mac[6]; uint16_t l3_proto = 0;")
normalize_end = source.index("            const struct in6_addr *filt_src_ip6", normalize_start)
replacement = '''            argos_packet_view_t packet_view;
            if (!argos_packet_decode(pkt_type, buffer, (int)len, opt_v6, &packet_view)) continue;

            unsigned char *src_mac = packet_view.src_mac;
            unsigned char *dst_mac = packet_view.dst_mac;
            uint16_t l3_proto = packet_view.l3_proto;
            int l3_offset = packet_view.l3_offset;

            if (opt_sensor_mode) {
                uint16_t outer = packet_view.outer_vlan;
                uint16_t inner = packet_view.inner_vlan;
                if (aux_vlan_valid) {
                    if (outer == 0U) outer = aux_vlan;
                    else if (aux_vlan != outer) { inner = outer; outer = aux_vlan; }
                }
                snprintf(sensor_observation_iface, sizeof(sensor_observation_iface), "%s", current_iface->name);
                sensor_observation_outer_vlan = outer;
                sensor_observation_inner_vlan = inner;
            }

            static const unsigned char zero_mac[6] = {0,0,0,0,0,0};
            static const unsigned char bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
            /* RAW_IP (PPP/TUN/WireGuard) has no MAC, so zero-MAC validation
             * applies only to Ethernet and cooked link-layer frames. */
            if (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED) {
                if (memcmp(src_mac, zero_mac, 6) == 0 || memcmp(src_mac, bcast_mac, 6) == 0) continue;
            }

            uint32_t src_ip_num = 0, dst_ip_num = 0;
            int is_outbound = 0;
            int source_offlink_routed = 0;
            struct in6_addr src_ip6_addr, dst_ip6_addr;
            memset(&src_ip6_addr, 0, sizeof(src_ip6_addr));
            memset(&dst_ip6_addr, 0, sizeof(dst_ip6_addr));
            int is_ipv6_packet = packet_view.ip_version == 6U;
            int is_ip_packet = packet_view.is_ip;
            uint8_t ip_protocol = packet_view.ip_protocol;
            uint8_t ip_ttl = packet_view.ip_ttl;
            int l4_offset = packet_view.l4_offset;
            int ipv4_is_frag = packet_view.nonfirst_fragment;

            if (packet_view.ip_version == 4U) {
                memcpy(&src_ip_num, packet_view.src_addr, 4U);
                memcpy(&dst_ip_num, packet_view.dst_addr, 4U);
                int src_lan = is_lan_ipv4(src_ip_num);
                int dst_lan = is_lan_ipv4(dst_ip_num);
                source_offlink_routed = is_routed_source_ipv4(src_ip_num, packet_ifindex);
                if (!src_lan && !dst_lan && !source_offlink_routed) continue;
                is_outbound = src_lan || source_offlink_routed;
            } else if (packet_view.ip_version == 6U) {
                memcpy(&src_ip6_addr, packet_view.src_addr, 16U);
                memcpy(&dst_ip6_addr, packet_view.dst_addr, 16U);
                int src_lan = is_lan_ipv6(&src_ip6_addr);
                int dst_lan = is_lan_ipv6(&dst_ip6_addr);
                source_offlink_routed = is_routed_source_ipv6(&src_ip6_addr, packet_ifindex);
                if (!src_lan && !dst_lan && !source_offlink_routed) continue;
                is_outbound = src_lan || source_offlink_routed;
            } else if (l3_proto == 0x88ccU || l3_proto == 0x0806U ||
                       (runtime_cfg.enterprise_enabled &&
                        (l3_proto <= 1500U || l3_proto == 0x8809U || l3_proto == 0x888eU ||
                         l3_proto == 0x8892U || l3_proto == 0x2000U || l3_proto == 0x00feU ||
                         l3_proto == 0x00bbU || l3_proto == 0xf200U))) {
                /* L2 discovery/control frames intentionally have no IP view. */
            } else {
                continue;
            }

            int l3_packet_end = packet_view.packet_end;

'''
source = source[:normalize_start] + replacement + source[normalize_end:]

old_raw_v4 = "argos_raw_identity_v4(buffer + l3_offset + 12, src_mac);\n                    argos_raw_identity_v4(buffer + l3_offset + 16, dst_mac);"
new_raw_v4 = "argos_raw_identity_v4(packet_view.src_addr, src_mac);\n                    argos_raw_identity_v4(packet_view.dst_addr, dst_mac);"
if source.count(old_raw_v4) != 1:
    raise SystemExit("raw IPv4 identity anchor changed")
source = source.replace(old_raw_v4, new_raw_v4, 1)

main_path.write_text(source)
