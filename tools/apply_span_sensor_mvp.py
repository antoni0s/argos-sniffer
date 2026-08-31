#!/usr/bin/env python3
from pathlib import Path
import re

SRC = Path("src/argos-sniffer.c")
text = SRC.read_text(encoding="utf-8")

if "ARGOS SPAN SENSOR MVP" in text:
    print("SPAN sensor MVP already applied")
    raise SystemExit(0)


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    text = text.replace(old, new, 1)


# getopt_long() is Linux/POSIX-only and main() is already excluded by
# ARGOS_PORTABLE_TEST, so this does not touch the portable parser tests.
replace_once(
    "#include <unistd.h>\n#include <signal.h>\n",
    "#include <unistd.h>\n#include <getopt.h>\n#include <signal.h>\n",
    "getopt include",
)

# Sensor mode is strictly opt-in. These globals are only observation/output
# context; the protocol parsers remain shared with gateway mode.
replace_once(
    "int opt_quic_heavy = 0;          /* Flag to enable heavy stateful QUIC reassembly */\n"
    "int opt_ext_metrics = 0;         /* Default: Heavy metrics (entropy, RTT, latency) disabled */\n",
    "int opt_quic_heavy = 0;          /* Flag to enable heavy stateful QUIC reassembly */\n"
    "int opt_ext_metrics = 0;         /* Default: Heavy metrics (entropy, RTT, latency) disabled */\n\n"
    "/* ARGOS SPAN SENSOR MVP ---------------------------------------------------\n"
    " * Gateway mode remains the default and keeps the legacy wire format.\n"
    " * Sensor mode adds only an observation envelope at the telemetry sink. */\n"
    "#define SENSOR_NAME_MAX 64\n"
    "#define SENSOR_IFACE_MAX 32\n"
    "static int opt_sensor_mode = 0;\n"
    "static char sensor_name[SENSOR_NAME_MAX] = {0};\n"
    "static char sensor_observation_iface[SENSOR_IFACE_MAX] = {0};\n"
    "static uint16_t sensor_observation_outer_vlan = 0;\n"
    "static uint16_t sensor_observation_inner_vlan = 0;\n",
    "sensor globals",
)

# Prefix sensor records centrally, after parsing. This guarantees all existing
# parsers continue to emit their exact legacy event shape.
old_emit = '''static void emit_telemetry(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void emit_telemetry(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (len < 0) return;
    if (len >= (int)sizeof(buffer)) {
        /* Still emit a truncated record rather than silently dropping a
         * long HTTP UA / DNS name -- collectors would otherwise miss the event. */
        len = (int)sizeof(buffer) - 1;
    }
    if (len > 0) {
        if (use_ipc) {
            sendto(ipc_sock, buffer, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr));
        }
        if (use_remote) {
            sendto(remote_sock, buffer, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&remote_addr, remote_addr_len);
        }
        /* -U is a fan-out sink: keep stdout active for the local daemon while
         * also delivering the same record to the remote UDP collector. */
        if ((use_remote && !udp_only) || (!use_remote && !use_ipc)) {
            fputs(buffer, stdout);
        }
    }
}
'''
new_emit = '''static void emit_telemetry(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void emit_telemetry(const char *format, ...) {
    char event[1024];
    va_list args;
    va_start(args, format);
    int event_len = vsnprintf(event, sizeof(event), format, args);
    va_end(args);

    if (event_len < 0) return;
    if (event_len >= (int)sizeof(event)) {
        /* Preserve the legacy 1024-byte event bound. The sensor envelope is
         * added outside this buffer so enabling --sensor cannot reduce the
         * amount of parser payload that fits in a record. */
        event_len = (int)sizeof(event) - 1;
    }
    if (event_len <= 0) return;

    const char *wire = event;
    int wire_len = event_len;
    char sensor_wire[1280];
    if (opt_sensor_mode) {
        char vlan[24];
        if (sensor_observation_inner_vlan != 0U) {
            snprintf(vlan, sizeof(vlan), "%u/%u",
                     (unsigned)sensor_observation_outer_vlan,
                     (unsigned)sensor_observation_inner_vlan);
        } else {
            snprintf(vlan, sizeof(vlan), "%u", (unsigned)sensor_observation_outer_vlan);
        }
        int n = snprintf(sensor_wire, sizeof(sensor_wire), "OBS|%s|%s|%s|%.*s",
                         sensor_name,
                         sensor_observation_iface[0] ? sensor_observation_iface : "unknown",
                         vlan, event_len, event);
        if (n < 0) return;
        wire_len = n >= (int)sizeof(sensor_wire) ? (int)sizeof(sensor_wire) - 1 : n;
        wire = sensor_wire;
    }

    if (use_ipc) {
        sendto(ipc_sock, wire, (size_t)wire_len, MSG_DONTWAIT, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr));
    }
    if (use_remote) {
        sendto(remote_sock, wire, (size_t)wire_len, MSG_DONTWAIT, (struct sockaddr *)&remote_addr, remote_addr_len);
    }
    /* -U is a fan-out sink: keep stdout active for the local daemon while
     * also delivering the same record to the remote UDP collector. */
    if ((use_remote && !udp_only) || (!use_remote && !use_ipc)) {
        fwrite(wire, 1U, (size_t)wire_len, stdout);
    }
}
'''
replace_once(old_emit, new_emit, "telemetry sink")

# Explicit inside networks are kept separate from learned interface prefixes.
# This is essential for an unnumbered SPAN NIC, and count==0 means gateway
# classification follows the existing path byte-for-byte.
replace_once(
    "static lan_pfx_t lan_pfx[MAX_LAN_PFX];\nstatic int lan_pfx_count = 0;\n",
    "static lan_pfx_t lan_pfx[MAX_LAN_PFX];\nstatic int lan_pfx_count = 0;\n"
    "static lan_pfx_t configured_inside[MAX_LAN_PFX];\n"
    "static int configured_inside_count = 0;\n",
    "inside prefix storage",
)
replace_once(
    "static int is_lan_ipv4(uint32_t ip_be) {\n    if (is_private_ipv4(ip_be)) return 1;\n",
    "static int is_lan_ipv4(uint32_t ip_be) {\n"
    "    for (int i = 0; i < configured_inside_count; i++) {\n"
    "        if (configured_inside[i].family == AF_INET &&\n"
    "            (ip_be & configured_inside[i].v4mask) == configured_inside[i].v4) return 1;\n"
    "    }\n"
    "    if (is_private_ipv4(ip_be)) return 1;\n",
    "inside IPv4 match",
)
replace_once(
    "static int is_lan_ipv6(const struct in6_addr *addr) {\n    if (is_private_ipv6(addr)) return 1;\n",
    "static int is_lan_ipv6(const struct in6_addr *addr) {\n"
    "    for (int i = 0; i < configured_inside_count; i++) {\n"
    "        if (configured_inside[i].family != AF_INET6) continue;\n"
    "        int ok = 1;\n"
    "        for (int b = 0; b < 16; b++) {\n"
    "            if ((addr->s6_addr[b] & configured_inside[i].v6mask.s6_addr[b]) !=\n"
    "                configured_inside[i].v6.s6_addr[b]) { ok = 0; break; }\n"
    "        }\n"
    "        if (ok) return 1;\n"
    "    }\n"
    "    if (is_private_ipv6(addr)) return 1;\n",
    "inside IPv6 match",
)

# VLAN extraction remains part of the shared L2 decoder. Gateway mode simply
# ignores the observation metadata, so packet parsing behavior is unchanged.
replace_once(
    "/* ============================================================================\n * SECTION: Universal L2 Stripper\n",
    "static uint16_t frame_outer_vlan = 0;\n"
    "static uint16_t frame_inner_vlan = 0;\n\n"
    "/* ============================================================================\n * SECTION: Universal L2 Stripper\n",
    "VLAN context globals",
)
replace_once(
    "static int strip_l2(link_type_t type, const unsigned char *buffer, int len,\n"
    "                    unsigned char *src_mac, unsigned char *dst_mac, uint16_t *l3_proto) {\n"
    "    if (type == LINK_ETHERNET) {\n",
    "static int strip_l2(link_type_t type, const unsigned char *buffer, int len,\n"
    "                    unsigned char *src_mac, unsigned char *dst_mac, uint16_t *l3_proto) {\n"
    "    frame_outer_vlan = 0;\n"
    "    frame_inner_vlan = 0;\n"
    "    if (type == LINK_ETHERNET) {\n",
    "VLAN context reset",
)
old_vlan = '''        if (eth_type == 0x8100 || eth_type == 0x88A8) {
            if (len < 18) return -1;
            eth_type = read_be16(buffer + 16); offset = 18;
            /* QinQ / 802.1ad+802.1Q double tag: a second TPID may follow. */
            if (eth_type == 0x8100 || eth_type == 0x88A8) {
                if (len < 22) return -1;
                eth_type = read_be16(buffer + 20); offset = 22;
            }
        }
'''
new_vlan = '''        if (eth_type == 0x8100 || eth_type == 0x88A8) {
            if (len < 18) return -1;
            frame_outer_vlan = (uint16_t)(read_be16(buffer + 14) & 0x0fffU);
            eth_type = read_be16(buffer + 16); offset = 18;
            /* QinQ / 802.1ad+802.1Q double tag: retain both VLAN IDs as
             * outer/inner observation context while parsing the same L3 data. */
            if (eth_type == 0x8100 || eth_type == 0x88A8) {
                if (len < 22) return -1;
                frame_inner_vlan = (uint16_t)(read_be16(buffer + 18) & 0x0fffU);
                eth_type = read_be16(buffer + 20); offset = 22;
            }
        }
'''
replace_once(old_vlan, new_vlan, "VLAN decoder")

# Sensor-specific CLI helpers. Names are deliberately restricted so the pipe
# wire format cannot be broken by user-supplied metadata.
helper_anchor = '''static inline int is_hard_excluded_mac(const unsigned char *shost) {
    for (int i = 0; i < hard_exclude_mac_count; i++) if (memcmp(shost, hard_exclude_macs[i], 6) == 0) return 1;
    return 0;
}

'''
helper_code = helper_anchor + '''static int valid_sensor_name(const char *name) {
    if (!name || !*name || strlen(name) >= SENSOR_NAME_MAX) return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.')) return 0;
    }
    return 1;
}

static int add_inside_prefix(const char *spec) {
    if (!spec || !*spec || configured_inside_count >= MAX_LAN_PFX) {
        fprintf(stderr, "Error: invalid or too many --inside prefixes\n");
        return 0;
    }
    char buf[INET6_ADDRSTRLEN + 8];
    size_t n = strlen(spec);
    if (n >= sizeof(buf)) {
        fprintf(stderr, "Error: --inside prefix too long: %s\n", spec);
        return 0;
    }
    memcpy(buf, spec, n + 1U);
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash++ = '\0';
        if (!*slash || strchr(slash, '/')) {
            fprintf(stderr, "Error: invalid --inside CIDR: %s\n", spec);
            return 0;
        }
    }

    lan_pfx_t e; memset(&e, 0, sizeof(e));
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        int bits = 32;
        if (slash && !parse_cidr_bits(slash, 32, &bits)) {
            fprintf(stderr, "Error: invalid IPv4 --inside CIDR: %s\n", spec);
            return 0;
        }
        uint32_t mask_host = bits == 0 ? 0U : (uint32_t)(0xffffffffU << (32 - bits));
        e.family = AF_INET;
        e.v4mask = htonl(mask_host);
        e.v4 = a4.s_addr & e.v4mask;
    } else if (inet_pton(AF_INET6, buf, &a6) == 1) {
        int bits = 128;
        if (slash && !parse_cidr_bits(slash, 128, &bits)) {
            fprintf(stderr, "Error: invalid IPv6 --inside CIDR: %s\n", spec);
            return 0;
        }
        e.family = AF_INET6;
        e.v6 = a6;
        int remain = bits;
        for (int i = 0; i < 16; i++) {
            if (remain >= 8) { e.v6mask.s6_addr[i] = 0xffU; remain -= 8; }
            else if (remain > 0) { e.v6mask.s6_addr[i] = (uint8_t)(0xffU << (8 - remain)); remain = 0; }
            else e.v6mask.s6_addr[i] = 0U;
            e.v6.s6_addr[i] &= e.v6mask.s6_addr[i];
        }
    } else {
        fprintf(stderr, "Error: invalid --inside address: %s\n", spec);
        return 0;
    }
    configured_inside[configured_inside_count++] = e;
    return 1;
}

'''
replace_once(helper_anchor, helper_code, "sensor CLI helpers")

# Help text: gateway output stays documented first; sensor envelope is additive.
replace_once(
    '"argos-sniffer v" VERSION " - Passive LAN traffic fingerprinter & live inspector\\n"\n'
    '"                  for OpenWrt and any Linux gateway\\n\\n"\n',
    '"argos-sniffer v" VERSION " - Passive LAN traffic fingerprinter & live inspector\\n"\n'
    '"                  for OpenWrt/Linux gateways and SPAN/TAP sensors\\n\\n"\n',
    "help title",
)
replace_once(
    '"USAGE:\\n  %s [-i iface] [-r router_mac] [-x filter_expr] [-z filter_expr | -Z filter_expr] [-o path] [-u ip:port] [-U ip:port] [-f sec] [FLAGS...] [-W]\\n"\n',
    '"USAGE:\\n  %s [-i iface] [-r router_mac] [-x filter_expr] [-z filter_expr | -Z filter_expr] [-o path] [-u ip:port] [-U ip:port] [-f sec] [FLAGS...] [-W]\\n"\n'
    '"     [--sensor --sensor-name name [--inside CIDR ...]]\\n"\n',
    "help usage",
)
replace_once(
    '"  -p              Enable promiscuous mode (auto-enabled if -z is set)\\n"\n',
    '"  -p              Enable promiscuous mode (auto-enabled by -z and --sensor)\\n"\n'
    '"  --sensor        SPAN/TAP sensor mode. Requires an explicit -i interface.\\n"\n'
    '"  --sensor-name   Stable sensor name used in the OBS telemetry envelope.\\n"\n'
    '"  --inside CIDR   Explicit inside IPv4/IPv6 network; repeat for multiple prefixes.\\n"\n'
    '"                  Recommended for unnumbered SPAN NICs and required for IPv6 GUA.\\n"\n',
    "help sensor options",
)
replace_once(
    '"OUTPUT FORMAT:\\n"\n',
    '"OUTPUT FORMAT:\\n"\n'
    '"  Gateway mode keeps the legacy records below unchanged.\\n"\n'
    '"  Sensor mode: OBS|sensor_name|interface|vlan|<legacy_record>\\n"\n'
    '"               vlan=0 untagged, N single-tag, outer/inner for QinQ.\\n"\n',
    "help output envelope",
)

# getopt_long() adds the three opt-in sensor controls without consuming any
# existing short option or changing current invocation semantics.
replace_once(
    "    int opt;\n\n    if (argc == 1) { print_help(argv[0]); return 0; }\n",
    "    int opt;\n"
    "    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE };\n"
    "    static const struct option long_options[] = {\n"
    "        {\"sensor\", no_argument, NULL, OPT_SENSOR},\n"
    "        {\"sensor-name\", required_argument, NULL, OPT_SENSOR_NAME},\n"
    "        {\"inside\", required_argument, NULL, OPT_INSIDE},\n"
    "        {NULL, 0, NULL, 0}\n"
    "    };\n\n"
    "    if (argc == 1) { print_help(argv[0]); return 0; }\n",
    "long option table",
)
replace_once(
    '    while ((opt = getopt(argc, argv, "i:r:R:x:z:Z:o:u:U:c:f:sSmMdDnNqQhHtTlLvVpaAWE")) != -1) {\n'
    '        switch (opt) {\n'
    "            case 'E': opt_ext_metrics = 1; break;\n",
    '    while ((opt = getopt_long(argc, argv, "i:r:R:x:z:Z:o:u:U:c:f:sSmMdDnNqQhHtTlLvVpaAWE", long_options, NULL)) != -1) {\n'
    '        switch (opt) {\n'
    "            case OPT_SENSOR: opt_sensor_mode = 1; opt_promisc = 1; break;\n"
    "            case OPT_SENSOR_NAME:\n"
    "                if (!valid_sensor_name(optarg)) {\n"
    "                    fprintf(stderr, \"Error: --sensor-name may contain only letters, digits, '.', '_' and '-' (max 63 chars).\\n\");\n"
    "                    return 1;\n"
    "                }\n"
    "                snprintf(sensor_name, sizeof(sensor_name), \"%s\", optarg);\n"
    "                break;\n"
    "            case OPT_INSIDE: if (!add_inside_prefix(optarg)) return 1; break;\n"
    "            case 'E': opt_ext_metrics = 1; break;\n",
    "getopt sensor cases",
)

# Validate the profile only after all options have been parsed, so option order
# is irrelevant. Gateway mode refuses sensor-only metadata rather than silently
# changing classification.
replace_once(
    "    if (optind < argc) { fprintf(stderr, \"Error: Unrecognized extra argument.\\n\"); return 1; }\n\n"
    "    if (filter_mode1.is_active && filter_mode2.is_active) {\n",
    "    if (optind < argc) { fprintf(stderr, \"Error: Unrecognized extra argument.\\n\"); return 1; }\n\n"
    "    if (!opt_sensor_mode && (sensor_name[0] || configured_inside_count > 0)) {\n"
    "        fprintf(stderr, \"Error: --sensor-name/--inside require --sensor.\\n\");\n"
    "        return 1;\n"
    "    }\n"
    "    if (opt_sensor_mode) {\n"
    "        if (!sensor_name[0]) {\n"
    "            fprintf(stderr, \"Error: --sensor requires --sensor-name.\\n\");\n"
    "            return 1;\n"
    "        }\n"
    "        if (strcasecmp(iface, \"any\") == 0) {\n"
    "            fprintf(stderr, \"Error: --sensor requires an explicit SPAN/TAP interface via -i (not 'any').\\n\");\n"
    "            return 1;\n"
    "        }\n"
    "    }\n\n"
    "    if (filter_mode1.is_active && filter_mode2.is_active) {\n",
    "sensor validation",
)

# PACKET_AUXDATA recovers VLAN metadata stripped by NIC offload. If an outer
# QinQ tag was stripped, the on-frame tag is shifted to inner VLAN context.
replace_once(
    "            uint64_t pkt_usec = 0;\n"
    "            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {\n",
    "            uint64_t pkt_usec = 0;\n"
    "            uint16_t aux_vlan = 0;\n"
    "            int aux_vlan_valid = 0;\n"
    "            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {\n",
    "auxdata locals",
)
replace_once(
    "#endif\n            }\n            if (pkt_usec == 0) pkt_usec = get_current_usec();\n",
    "#endif\n"
    "                if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA &&\n"
    "                    c->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata))) {\n"
    "                    struct tpacket_auxdata aux;\n"
    "                    memcpy(&aux, CMSG_DATA(c), sizeof(aux));\n"
    "                    if (aux.tp_status & TP_STATUS_VLAN_VALID) {\n"
    "                        aux_vlan = (uint16_t)(aux.tp_vlan_tci & 0x0fffU);\n"
    "                        aux_vlan_valid = 1;\n"
    "                    }\n"
    "                }\n"
    "            }\n"
    "            if (pkt_usec == 0) pkt_usec = get_current_usec();\n",
    "auxdata parser",
)
replace_once(
    "            int l3_offset = strip_l2(pkt_type, buffer, (int)len, src_mac, dst_mac, &l3_proto);\n"
    "            if (l3_offset < 0) continue;\n\n"
    "            static const unsigned char zero_mac[6] = {0,0,0,0,0,0};\n",
    "            int l3_offset = strip_l2(pkt_type, buffer, (int)len, src_mac, dst_mac, &l3_proto);\n"
    "            if (l3_offset < 0) continue;\n\n"
    "            if (opt_sensor_mode) {\n"
    "                uint16_t outer = frame_outer_vlan;\n"
    "                uint16_t inner = frame_inner_vlan;\n"
    "                if (aux_vlan_valid) {\n"
    "                    if (outer == 0U) outer = aux_vlan;\n"
    "                    else if (aux_vlan != outer) { inner = outer; outer = aux_vlan; }\n"
    "                }\n"
    "                snprintf(sensor_observation_iface, sizeof(sensor_observation_iface), \"%s\", current_iface->name);\n"
    "                sensor_observation_outer_vlan = outer;\n"
    "                sensor_observation_inner_vlan = inner;\n"
    "            }\n\n"
    "            static const unsigned char zero_mac[6] = {0,0,0,0,0,0};\n",
    "observation context",
)

SRC.write_text(text, encoding="utf-8")
print("Applied SPAN sensor MVP to", SRC)
