from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

Path('src/argos_wireguard.h').write_text(r'''#ifndef ARGOS_WIREGUARD_H
#define ARGOS_WIREGUARD_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int emit;
    char detail[96];
} argos_wireguard_result_t;

/* WireGuard v1 messages start with a one-byte type and three reserved zero
 * bytes. We use only structural properties that are visible before crypto;
 * sender/receiver indices, keys, MACs, cookies and ciphertext stay opaque. */
static inline int argos_wireguard_parse(const unsigned char *p, size_t len,
                                        argos_wireguard_result_t *r) {
    if (!p || !r || len < 4U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[1] != 0U || p[2] != 0U || p[3] != 0U) return 0;

    const unsigned type = p[0];
    const char *kind = NULL;
    if (type == 1U) {
        if (len != 148U) return 0;
        kind = "handshake-initiation";
    } else if (type == 2U) {
        if (len != 92U) return 0;
        kind = "handshake-response";
    } else if (type == 3U) {
        if (len != 64U) return 0;
        kind = "cookie-reply";
    } else if (type == 4U) {
        /* 16-byte transport header + AEAD ciphertext/tag. Empty keepalive is
         * 32 bytes; encrypted transport packets remain 16-byte aligned. */
        if (len < 32U || (len & 15U) != 0U) return 0;
        kind = len == 32U ? "transport-keepalive" : "transport-data";
    } else {
        return 0;
    }

    r->emit = 1;
    snprintf(r->detail, sizeof(r->detail), "type=%s", kind);
    return 1;
}

#endif
''')

bp=Path('src/argos_bpf.h'); b=bp.read_text()
b=replace_once(b,
'''typedef struct {\n    uint8_t syn, multi, dhcp, netbios, dns, http, tls, l2, ipv6, enterprise;\n} argos_bpf_config_t;\n''',
'''typedef struct {\n    uint8_t syn, multi, dhcp, netbios, dns, http, tls, l2, ipv6, enterprise;\n    uint16_t wireguard_port;\n} argos_bpf_config_t;\n''','WireGuard BPF config port')
b=replace_once(b,
'''        for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i) {\n            if (ARGOS_ENTERPRISE_UDP_PORTS[i] == ARGOS_STUN_TURN_UDP_PORT) continue;\n            ADD(ud, ud_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n            ADD(us, us_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n        }\n''',
'''        for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i) {\n            if (ARGOS_ENTERPRISE_UDP_PORTS[i] == ARGOS_STUN_TURN_UDP_PORT) continue;\n            ADD(ud, ud_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n            ADD(us, us_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n        }\n        if (cfg->wireguard_port != 0U) {\n            ADD(ud, ud_n, cfg->wireguard_port);\n            ADD(us, us_n, cfg->wireguard_port);\n        }\n''','WireGuard BPF runtime admission')
bp.write_text(b)

sp=Path('src/argos-sniffer.c'); s=sp.read_text()
s=replace_once(s,
'''#include "argos_hsrp.h"\n#include "argos_multicast_membership.h"\n#include "argos_enterprise.h"\n''',
'''#include "argos_hsrp.h"\n#include "argos_multicast_membership.h"\n#include "argos_wireguard.h"\n#include "argos_enterprise.h"\n''','WireGuard include')
s=replace_once(s,
'''"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose]\\n"\n''',
'''"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose] [--wireguard-port port]\\n"\n''','WireGuard usage')
s=replace_once(s,
'''"  --enterprise-verbose  Enable enterprise fingerprints without telemetry deduplication.\\n"\n''',
'''"  --enterprise-verbose  Enable enterprise fingerprints without telemetry deduplication.\\n"\n"  --wireguard-port <port>  WireGuard UDP port for structural detection (default: 51820).\\n"\n"                          Requires --enterprise; packet structure is validated before emission.\\n"\n''','WireGuard help')
s=replace_once(s,
'''    int opt_enterprise = 0, opt_enterprise_rl = 1;\n    int opt;\n    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE, OPT_ENTERPRISE, OPT_ENTERPRISE_VERBOSE };\n''',
'''    int opt_enterprise = 0, opt_enterprise_rl = 1;\n    uint16_t opt_wireguard_port = 51820U;\n    int wireguard_port_explicit = 0;\n    int opt;\n    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE, OPT_ENTERPRISE, OPT_ENTERPRISE_VERBOSE, OPT_WIREGUARD_PORT };\n''','WireGuard CLI state')
s=replace_once(s,
'''        {"enterprise", no_argument, NULL, OPT_ENTERPRISE},\n        {"enterprise-verbose", no_argument, NULL, OPT_ENTERPRISE_VERBOSE},\n        {NULL, 0, NULL, 0}\n''',
'''        {"enterprise", no_argument, NULL, OPT_ENTERPRISE},\n        {"enterprise-verbose", no_argument, NULL, OPT_ENTERPRISE_VERBOSE},\n        {"wireguard-port", required_argument, NULL, OPT_WIREGUARD_PORT},\n        {NULL, 0, NULL, 0}\n''','WireGuard long option')
s=replace_once(s,
'''            case OPT_ENTERPRISE: opt_enterprise = 1; opt_enterprise_rl = 1; opt_v6 = 1; break;\n            case OPT_ENTERPRISE_VERBOSE: opt_enterprise = 1; opt_enterprise_rl = 0; opt_v6 = 1; break;\n            case 'E': opt_ext_metrics = 1; break;\n''',
'''            case OPT_ENTERPRISE: opt_enterprise = 1; opt_enterprise_rl = 1; opt_v6 = 1; break;\n            case OPT_ENTERPRISE_VERBOSE: opt_enterprise = 1; opt_enterprise_rl = 0; opt_v6 = 1; break;\n            case OPT_WIREGUARD_PORT: {\n                char *end = NULL; long v = strtol(optarg, &end, 10);\n                if (!end || *end || v < 1 || v > 65535) {\n                    fprintf(stderr, "Error: invalid --wireguard-port: %s\\n", optarg); return 1;\n                }\n                opt_wireguard_port = (uint16_t)v; wireguard_port_explicit = 1; break;\n            }\n            case 'E': opt_ext_metrics = 1; break;\n''','WireGuard option parser')
s=replace_once(s,
'''    if (filter_mode1.is_active && filter_mode2.is_active) {\n''',
'''    if (wireguard_port_explicit && !opt_enterprise) {\n        fprintf(stderr, "Error: --wireguard-port requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n\n    if (filter_mode1.is_active && filter_mode2.is_active) {\n''','WireGuard option dependency')
s=replace_once(s,
'''        .tls = (uint8_t)(opt_tls != 0), .l2 = (uint8_t)(opt_l2 != 0),\n        .ipv6 = (uint8_t)(opt_v6 != 0), .enterprise = (uint8_t)(opt_enterprise != 0)\n''',
'''        .tls = (uint8_t)(opt_tls != 0), .l2 = (uint8_t)(opt_l2 != 0),\n        .ipv6 = (uint8_t)(opt_v6 != 0), .enterprise = (uint8_t)(opt_enterprise != 0),\n        .wireguard_port = (uint16_t)(opt_enterprise ? opt_wireguard_port : 0U)\n''','WireGuard BPF config wiring')
s=replace_once(s,
'''                                   (opt_tls && dport == 443U) ||\n                                   (opt_enterprise && argos_enterprise_udp_port(sport, dport));\n''',
'''                                   (opt_tls && dport == 443U) ||\n                                   (opt_enterprise && (argos_enterprise_udp_port(sport, dport) ||\n                                                       sport == opt_wireguard_port || dport == opt_wireguard_port));\n''','WireGuard UDP relevance')
s=replace_once(s,
'''                if (opt_enterprise && argos_enterprise_udp_port(sport, dport)) {\n''',
'''                if (opt_enterprise && (sport == opt_wireguard_port || dport == opt_wireguard_port)) {\n                    argos_wireguard_result_t wg;\n                    if (argos_wireguard_parse(payload, (size_t)payload_len, &wg) && wg.emit) {\n                        char ent_mac[18], ent_sig[384];\n                        format_mac(src_mac, ent_mac);\n                        snprintf(ent_sig, sizeof(ent_sig), "%s|WireGuard|%s", src_ip_str, wg.detail);\n                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                            emit_telemetry("ENT|%s|%s|%s|WireGuard|%s%s\\n",\n                                           ent_mac, src_ip_str, dst_ip_str, wg.detail, routed_str);\n                    }\n                }\n                if (opt_enterprise && argos_enterprise_udp_port(sport, dport)) {\n''','WireGuard UDP parser dispatch')
sp.write_text(s)

Path('tests/test_wireguard.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_wireguard.h"

static void wg_header(unsigned char *p, size_t len, unsigned type) {
    memset(p, 0, len); p[0]=(unsigned char)type;
}

int main(void) {
    argos_wireguard_result_t r;
    unsigned char p[160];

    wg_header(p,148,1); memset(p+8,0xa5,32); assert(argos_wireguard_parse(p,148,&r));
    assert(r.emit && strcmp(r.detail,"type=handshake-initiation")==0);
    assert(strstr(r.detail,"a5")==NULL);

    wg_header(p,92,2); assert(argos_wireguard_parse(p,92,&r));
    assert(strcmp(r.detail,"type=handshake-response")==0);
    wg_header(p,64,3); assert(argos_wireguard_parse(p,64,&r));
    assert(strcmp(r.detail,"type=cookie-reply")==0);
    wg_header(p,32,4); assert(argos_wireguard_parse(p,32,&r));
    assert(strcmp(r.detail,"type=transport-keepalive")==0);
    wg_header(p,48,4); assert(argos_wireguard_parse(p,48,&r));
    assert(strcmp(r.detail,"type=transport-data")==0);

    wg_header(p,148,1); p[2]=1; assert(!argos_wireguard_parse(p,148,&r));
    wg_header(p,147,1); assert(!argos_wireguard_parse(p,147,&r));
    wg_header(p,93,2); assert(!argos_wireguard_parse(p,93,&r));
    wg_header(p,63,3); assert(!argos_wireguard_parse(p,63,&r));
    wg_header(p,40,4); assert(!argos_wireguard_parse(p,40,&r));
    wg_header(p,32,9); assert(!argos_wireguard_parse(p,32,&r));
    puts("WireGuard fixtures: PASS");
    return 0;
}
''')

tp=Path('tests/test_dynamic_bpf.c'); t=tp.read_text()
t=replace_once(t,
'''    memset(&c, 0, sizeof(c)); c.enterprise = 1; c.ipv6 = 1; expect(argos_bpf_build(&c, &p), "build enterprise");\n''',
'''    memset(&c, 0, sizeof(c)); c.enterprise = 1; c.ipv6 = 1; c.wireguard_port = 51821; expect(argos_bpf_build(&c, &p), "build enterprise");\n''','WireGuard custom BPF config')
t=replace_once(t,
'''    expect(pass(&p, pkt, udp4(pkt, 50000, 123, 48)), "NTP UDP/123 passes");\n''',
'''    expect(pass(&p, pkt, udp4(pkt, 50000, 123, 48)), "NTP UDP/123 passes");\n    expect(pass(&p, pkt, udp4(pkt, 50000, 51821, 148)), "custom WireGuard destination port passes");\n    expect(pass(&p, pkt, udp4(pkt, 51821, 50000, 92)), "custom WireGuard source port passes");\n    expect(!pass(&p, pkt, udp4(pkt, 50000, 51820, 148)), "default WireGuard port is not hard-coded when custom port is configured");\n''','WireGuard custom BPF fixtures')
tp.write_text(t)
