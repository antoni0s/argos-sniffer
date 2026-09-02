from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


server_h = r'''#ifndef ARGOS_TLS_SERVER_H
#define ARGOS_TLS_SERVER_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char version[3];
    uint16_t cipher;
    uint8_t extension_count;
    char alpn[32];
    uint64_t extension_signature;
    char fingerprint[96];
} argos_tls_server_result_t;

static inline uint16_t ats_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int ats_grease(uint16_t v) {
    return (v & 0x0f0fU) == 0x0a0aU && ((v >> 8) & 0xffU) == (v & 0xffU);
}

static inline const char *ats_version_code(uint16_t v) {
    switch (v) {
        case 0x0304U: return "13";
        case 0x0303U: return "12";
        case 0x0302U: return "11";
        case 0x0301U: return "10";
        default: return "00";
    }
}

static inline uint64_t ats_fnv_type(uint64_t h, uint16_t type) {
    const unsigned char b[2] = {(unsigned char)(type >> 8), (unsigned char)type};
    for (size_t i = 0; i < 2U; ++i) {
        h ^= (uint64_t)b[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static inline void ats_alpn_code(const unsigned char *p, size_t n, char out[32]) {
    strcpy(out, "none");
    if (!p || n < 3U) return;
    size_t list_len = ats_be16(p);
    if (list_len + 2U > n || list_len < 1U) return;
    size_t plen = p[2];
    if (plen == 0U || plen + 3U > n) return;
    size_t keep = plen < 31U ? plen : 31U;
    for (size_t i = 0; i < keep; ++i) {
        unsigned char c = p[3U + i];
        out[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|') ? c : '.');
    }
    out[keep] = '\0';
}

/* Argos TLS Server v1 (ats1) is intentionally NOT JA4S. It is an independent,
 * low-cost ServerHello fingerprint: negotiated version, selected cipher,
 * non-GREASE extension count/order signature, and visible ALPN. */
static inline int argos_tls_server_parse(const unsigned char *p, size_t n,
                                         argos_tls_server_result_t *out) {
    if (!p || !out || n < 49U) return 0;
    memset(out, 0, sizeof(*out));
    strcpy(out->alpn, "none");

    if (p[0] != 0x16U || p[5] != 0x02U) return 0; /* handshake / ServerHello */
    size_t record_len = ats_be16(p + 3);
    if (record_len < 44U || record_len + 5U > n) return 0;
    size_t hs_len = ((size_t)p[6] << 16) | ((size_t)p[7] << 8) | (size_t)p[8];
    if (hs_len < 40U || hs_len + 9U > n || hs_len + 4U > record_len) return 0;

    size_t end = 9U + hs_len;
    uint16_t negotiated = ats_be16(p + 9);
    size_t pos = 9U + 2U + 32U;
    if (pos >= end) return 0;
    size_t sid_len = p[pos++];
    if (sid_len > 32U || pos + sid_len + 3U > end) return 0;
    pos += sid_len;
    out->cipher = ats_be16(p + pos); pos += 2U;
    pos += 1U; /* compression */

    uint64_t ext_sig = UINT64_C(1469598103934665603);
    unsigned ext_count = 0U;
    if (pos < end) {
        if (pos + 2U > end) return 0;
        size_t ext_total = ats_be16(p + pos); pos += 2U;
        if (pos + ext_total > end) return 0;
        size_t ext_end = pos + ext_total;
        while (pos + 4U <= ext_end) {
            uint16_t type = ats_be16(p + pos);
            size_t elen = ats_be16(p + pos + 2U);
            pos += 4U;
            if (pos + elen > ext_end) return 0;
            if (!ats_grease(type)) {
                if (ext_count < 99U) ++ext_count;
                ext_sig = ats_fnv_type(ext_sig, type);
            }
            if (type == 0x002bU && elen == 2U) negotiated = ats_be16(p + pos);
            if (type == 0x0010U) ats_alpn_code(p + pos, elen, out->alpn);
            pos += elen;
        }
        if (pos != ext_end) return 0;
    }

    snprintf(out->version, sizeof(out->version), "%s", ats_version_code(negotiated));
    out->extension_count = (uint8_t)ext_count;
    out->extension_signature = ext_sig;
    snprintf(out->fingerprint, sizeof(out->fingerprint),
             "ats1_%s_%04x_%02u_%s_%016llx",
             out->version, (unsigned)out->cipher, ext_count, out->alpn,
             (unsigned long long)ext_sig);
    return 1;
}

#endif /* ARGOS_TLS_SERVER_H */
'''
Path('src/argos_tls_server.h').write_text(server_h)

# BPF must admit bounded server-direction payload on the same direct-TLS ports.
p = Path('src/argos_bpf.h')
s = p.read_text()
s = replace_once(s,
    '        for (size_t i = 0; i < ARGOS_TLS_TCP_PORT_COUNT; ++i) ADD(td, td_n, ARGOS_TLS_TCP_PORTS[i]);\n'
    '        ADD(ud, ud_n, ARGOS_QUIC_UDP_PORT);\n',
    '        for (size_t i = 0; i < ARGOS_TLS_TCP_PORT_COUNT; ++i) {\n'
    '            ADD(td, td_n, ARGOS_TLS_TCP_PORTS[i]);\n'
    '            ADD(ts, ts_n, ARGOS_TLS_TCP_PORTS[i]);\n'
    '        }\n'
    '        ADD(ud, ud_n, ARGOS_QUIC_UDP_PORT);\n',
    'BPF TLS server direction')
p.write_text(s)

p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_tls_ports.h"\n#include "argos_enterprise.h"\n',
    '#include "argos_tls_ports.h"\n#include "argos_tls_server.h"\n#include "argos_enterprise.h"\n',
    'TLS server include')

s = replace_once(s,
    'static int app_flow_payload_complete(uint16_t dport, const unsigned char *payload, int payload_len) {\n'
    '    if (!payload || payload_len <= 0) return 0;\n\n'
    '    if (argos_tls_tcp_port(dport)) {\n',
    'static int app_flow_payload_complete(uint16_t sport, uint16_t dport, const unsigned char *payload, int payload_len) {\n'
    '    if (!payload || payload_len <= 0) return 0;\n\n'
    '    if (argos_tls_tcp_port(sport)) {\n'
    '        argos_tls_server_result_t server;\n'
    '        return argos_tls_server_parse(payload, (size_t)payload_len, &server);\n'
    '    }\n\n'
    '    if (argos_tls_tcp_port(dport)) {\n',
    'app-flow server completion')

s = replace_once(s,
    '                                   (opt_tls && argos_tls_tcp_port(dport)) ||\n'
    '                                   (opt_enterprise && argos_enterprise_tcp_port(sport, dport));\n',
    '                                   (opt_tls && (argos_tls_tcp_port(dport) || argos_tls_tcp_port(sport))) ||\n'
    '                                   (opt_enterprise && argos_enterprise_tcp_port(sport, dport));\n',
    'TCP TLS server relevance')

s = replace_once(s,
    '                                ((opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                 (opt_tls && argos_tls_tcp_port(dport)) || enterprise_tcp);\n',
    '                                ((opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                 (opt_tls && (argos_tls_tcp_port(dport) || argos_tls_tcp_port(sport))) || enterprise_tcp);\n',
    'TLS server flow tracking')

s = replace_once(s,
    '                else if (opt_tls && argos_tls_tcp_port(dport) && payload_len > 44) {\n'
    '                    parse_tls_sni(buffer + payload_offset, payload_len, mac_str, src_ip_str, dst_ip_str, dport, routed_str, opt_tls_rl);\n'
    '                }\n\n'
    '                argos_enterprise_result_t ent_tcp;\n',
    '                else if (opt_tls && argos_tls_tcp_port(dport) && payload_len > 44) {\n'
    '                    parse_tls_sni(buffer + payload_offset, payload_len, mac_str, src_ip_str, dst_ip_str, dport, routed_str, opt_tls_rl);\n'
    '                }\n'
    '                else if (opt_tls && argos_tls_tcp_port(sport) && payload_len > 44) {\n'
    '                    argos_tls_server_result_t server;\n'
    '                    if (argos_tls_server_parse(buffer + payload_offset, (size_t)payload_len, &server)) {\n'
    '                        char srv_sig[256];\n'
    '                        source_dedup_signature(srv_sig, sizeof(srv_sig), src_ip_str, server.fingerprint, routed_str);\n'
    '                        if (!dedup_should_suppress(mac_str, "TLSSRV", srv_sig, opt_tls_rl))\n'
    '                            emit_telemetry("TLSSRV|%s|%s|%s|%u|%s|%s%s\\n", mac_str, src_ip_str, dst_ip_str, sport, server.fingerprint, server.alpn, routed_str);\n'
    '                    }\n'
    '                }\n\n'
    '                argos_enterprise_result_t ent_tcp;\n',
    'TLS server dispatch')

s = replace_once(s,
    '                    int fingerprint_complete = app_flow_payload_complete(\n'
    '                        dport, buffer + payload_offset, payload_len);\n',
    '                    int fingerprint_complete = app_flow_payload_complete(\n'
    '                        sport, dport, buffer + payload_offset, payload_len);\n',
    'app-flow completion call')

s = replace_once(s,
    '"  DOT|mac|src_ip|dst_ip|sni|ja4_fingerprint|alpn[|routed]\\n"\n'
    '"  QUIC|mac|src_ip|dst_ip|dst_port|sni|version[|routed]\\n"\n',
    '"  DOT|mac|src_ip|dst_ip|sni|ja4_fingerprint|alpn[|routed]\\n"\n'
    '"  TLSSRV|mac|server_ip|client_ip|server_port|ats1_fingerprint|alpn[|routed]\\n"\n'
    '"  QUIC|mac|src_ip|dst_ip|dst_port|sni|version[|routed]\\n"\n',
    'TLSSRV help')
p.write_text(s)

# Extend BPF regression for server direction.
p = Path('tests/test_dynamic_bpf.c')
s = p.read_text()
s = replace_once(s,
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 0x18, 20)), "alternate HTTPS port passes");\n'
    '    expect(!pass(&p, pkt, tcp4(pkt, 50000, 587, 0x18, 20)), "STARTTLS 587 stays out of direct-TLS policy");\n',
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 0x18, 20)), "alternate HTTPS port passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 443, 50000, 0x18, 80)), "TLS server-direction payload passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 853, 50000, 0x18, 80)), "DoT server-direction payload passes");\n'
    '    expect(!pass(&p, pkt, tcp4(pkt, 587, 50000, 0x18, 80)), "STARTTLS server direction stays out");\n'
    '    expect(!pass(&p, pkt, tcp4(pkt, 50000, 587, 0x18, 20)), "STARTTLS 587 stays out of direct-TLS policy");\n',
    'server-direction BPF fixture')
p.write_text(s)

# Pure parser fixtures: TLS 1.3 ServerHello (ALPN hidden) and TLS 1.2 with h2.
test = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_tls_server.h"

static void put16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void put24(unsigned char *p, uint32_t v) { p[0]=(unsigned char)(v>>16); p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)v; }
static void expect(int ok, const char *s) { if (!ok) { fprintf(stderr,"FAIL: %s\n",s); exit(1); } }

static size_t make13(unsigned char *p) {
    memset(p,0,128); size_t q=9; put16(p+q,0x0303); q+=2; q+=32; p[q++]=0; put16(p+q,0x1301); q+=2; p[q++]=0;
    size_t el=q; q+=2; put16(p+q,0x002b); put16(p+q+2,2); put16(p+q+4,0x0304); q+=6;
    put16(p+q,0x0033); put16(p+q+2,2); put16(p+q+4,0x001d); q+=6; put16(p+el,(uint16_t)(q-el-2));
    p[0]=0x16; put16(p+1,0x0303); put16(p+3,(uint16_t)(q-5)); p[5]=0x02; put24(p+6,(uint32_t)(q-9)); return q;
}
static size_t make12(unsigned char *p) {
    memset(p,0,128); size_t q=9; put16(p+q,0x0303); q+=2; q+=32; p[q++]=0; put16(p+q,0xc02f); q+=2; p[q++]=0;
    size_t el=q; q+=2; put16(p+q,0x0010); put16(p+q+2,5); put16(p+q+4,3); p[q+6]=2; p[q+7]='h'; p[q+8]='2'; q+=9; put16(p+el,(uint16_t)(q-el-2));
    p[0]=0x16; put16(p+1,0x0303); put16(p+3,(uint16_t)(q-5)); p[5]=0x02; put24(p+6,(uint32_t)(q-9)); return q;
}
int main(void) {
    unsigned char p[128]; argos_tls_server_result_t r; size_t n=make13(p);
    expect(argos_tls_server_parse(p,n,&r),"TLS1.3 parse"); expect(strcmp(r.version,"13")==0,"TLS1.3 version");
    expect(r.cipher==0x1301,"TLS1.3 cipher"); expect(r.extension_count==2,"TLS1.3 extension count");
    expect(strcmp(r.alpn,"none")==0,"TLS1.3 ALPN remains hidden");
    expect(strcmp(r.fingerprint,"ats1_13_1301_02_none_09e178a1014a5fc3")==0,"TLS1.3 golden fingerprint");
    n=make12(p); expect(argos_tls_server_parse(p,n,&r),"TLS1.2 parse"); expect(strcmp(r.version,"12")==0,"TLS1.2 version");
    expect(r.cipher==0xc02f,"TLS1.2 cipher"); expect(strcmp(r.alpn,"h2")==0,"TLS1.2 ALPN");
    expect(strcmp(r.fingerprint,"ats1_12_c02f_01_h2_9a690300c5489dcb")==0,"TLS1.2 golden fingerprint");
    p[5]=0x01; expect(!argos_tls_server_parse(p,n,&r),"ClientHello rejected");
    puts("Argos TLS ServerHello fingerprints: PASS"); return 0;
}
'''
Path('tests/test_tls_server.c').write_text(test)
print('step6 Argos TLS ServerHello patch applied')
