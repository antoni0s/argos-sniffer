from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

Path('src/argos_multicast_membership.h').write_text(r'''#ifndef ARGOS_MULTICAST_MEMBERSHIP_H
#define ARGOS_MULTICAST_MEMBERSHIP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int emit;
    char proto[8];
    char detail[192];
} argos_membership_result_t;

static inline uint16_t amm_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline int amm_zero16(const unsigned char *p) {
    unsigned char v = 0;
    for (unsigned i = 0; i < 16U; ++i) v |= p[i];
    return v == 0U;
}

static inline int argos_igmp_parse(const unsigned char *p, size_t len,
                                   argos_membership_result_t *r) {
    if (!p || !r || len < 8U) return 0;
    memset(r, 0, sizeof(*r));
    const unsigned type = p[0];
    unsigned version = 0U, records = 0U, sources = 0U, group_specific = 0U;
    const char *kind = NULL;

    if (type == 0x11U) {
        kind = "query";
        group_specific = (p[4] | p[5] | p[6] | p[7]) != 0U;
        if (len >= 12U) {
            version = 3U;
            sources = amm_be16(p + 10);
            if (12U + 4U * (size_t)sources > len) return 0;
        } else {
            version = p[1] == 0U ? 1U : 2U;
        }
    } else if (type == 0x12U) {
        version = 1U; kind = "report"; group_specific = 1U;
    } else if (type == 0x16U) {
        version = 2U; kind = "report"; group_specific = 1U;
    } else if (type == 0x17U) {
        version = 2U; kind = "leave"; group_specific = 1U;
    } else if (type == 0x22U) {
        version = 3U; kind = "report";
        records = amm_be16(p + 6);
        if (records > 64U) return 0;
        size_t pos = 8U;
        for (unsigned i = 0; i < records; ++i) {
            if (pos + 8U > len) return 0;
            unsigned aux_words = p[pos + 1];
            unsigned nsrc = amm_be16(p + pos + 2);
            if (nsrc > 1024U) return 0;
            size_t need = 8U + 4U * (size_t)nsrc + 4U * (size_t)aux_words;
            if (need > len - pos) return 0;
            if (sources > 65535U - nsrc) return 0;
            sources += nsrc;
            pos += need;
        }
        group_specific = records != 0U;
    } else {
        return 0;
    }

    r->emit = 1;
    snprintf(r->proto, sizeof(r->proto), "IGMP");
    snprintf(r->detail, sizeof(r->detail),
             "version=%u type=%s records=%u sources=%u group_specific=%u",
             version, kind, records, sources, group_specific);
    return 1;
}

static inline int argos_mld_parse(const unsigned char *p, size_t len,
                                  argos_membership_result_t *r) {
    if (!p || !r || len < 8U) return 0;
    memset(r, 0, sizeof(*r));
    const unsigned type = p[0];
    unsigned version = 0U, records = 0U, sources = 0U, group_specific = 0U;
    const char *kind = NULL;

    if (type == 130U) {
        if (len < 24U) return 0;
        kind = "query";
        group_specific = !amm_zero16(p + 8);
        if (len >= 28U) {
            version = 2U;
            sources = amm_be16(p + 26);
            if (28U + 16U * (size_t)sources > len) return 0;
        } else {
            version = 1U;
        }
    } else if (type == 131U) {
        if (len < 24U) return 0;
        version = 1U; kind = "report"; group_specific = 1U;
    } else if (type == 132U) {
        if (len < 24U) return 0;
        version = 1U; kind = "done"; group_specific = 1U;
    } else if (type == 143U) {
        version = 2U; kind = "report";
        records = amm_be16(p + 6);
        if (records > 64U) return 0;
        size_t pos = 8U;
        for (unsigned i = 0; i < records; ++i) {
            if (pos + 20U > len) return 0;
            unsigned aux_words = p[pos + 1];
            unsigned nsrc = amm_be16(p + pos + 2);
            if (nsrc > 1024U) return 0;
            size_t need = 20U + 16U * (size_t)nsrc + 4U * (size_t)aux_words;
            if (need > len - pos) return 0;
            if (sources > 65535U - nsrc) return 0;
            sources += nsrc;
            pos += need;
        }
        group_specific = records != 0U;
    } else {
        return 0;
    }

    r->emit = 1;
    snprintf(r->proto, sizeof(r->proto), "MLD");
    snprintf(r->detail, sizeof(r->detail),
             "version=%u type=%s records=%u sources=%u group_specific=%u",
             version, kind, records, sources, group_specific);
    return 1;
}

#endif
''')

sp = Path('src/argos-sniffer.c'); s = sp.read_text()
s = replace_once(s,
'''#include "argos_hsrp.h"\n#include "argos_enterprise.h"\n''',
'''#include "argos_hsrp.h"\n#include "argos_multicast_membership.h"\n#include "argos_enterprise.h"\n''', 'membership include')

old = '''            if (protocol == IPPROTO_ICMPV6 && is_ipv6_packet) {\n                if (opt_l2 && l4_offset >= 0 && l4_offset < l3_packet_end) {\n                    parse_ndp_vector(buffer + l4_offset, l3_packet_end - l4_offset, src_mac,\n                                     &src_ip6_addr, src_ip_str, packet_ifindex, opt_l2_rl);\n                }\n                continue;\n            }\n\n            if (opt_enterprise && protocol == 112U && ttl == 255U &&\n'''
new = '''            if (protocol == IPPROTO_ICMPV6 && is_ipv6_packet) {\n                if (opt_enterprise && ttl == 1U && l4_offset >= 0 && l4_offset < l3_packet_end) {\n                    argos_membership_result_t membership;\n                    if (argos_mld_parse(buffer + l4_offset, (size_t)(l3_packet_end - l4_offset), &membership) && membership.emit) {\n                        char ent_mac[18], ent_sig[384];\n                        format_mac(src_mac, ent_mac);\n                        snprintf(ent_sig, sizeof(ent_sig), "%s|MLD|%s", src_ip_str, membership.detail);\n                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                            emit_telemetry("ENT|%s|%s|%s|MLD|%s%s\\n", ent_mac, src_ip_str, dst_ip_str, membership.detail, routed_str);\n                    }\n                }\n                if (opt_l2 && l4_offset >= 0 && l4_offset < l3_packet_end) {\n                    parse_ndp_vector(buffer + l4_offset, l3_packet_end - l4_offset, src_mac,\n                                     &src_ip6_addr, src_ip_str, packet_ifindex, opt_l2_rl);\n                }\n                continue;\n            }\n\n            if (opt_enterprise && protocol == 2U && ttl == 1U &&\n                l4_offset >= 0 && l4_offset < l3_packet_end) {\n                argos_membership_result_t membership;\n                if (argos_igmp_parse(buffer + l4_offset, (size_t)(l3_packet_end - l4_offset), &membership) && membership.emit) {\n                    char ent_mac[18], ent_sig[384];\n                    format_mac(src_mac, ent_mac);\n                    snprintf(ent_sig, sizeof(ent_sig), "%s|IGMP|%s", src_ip_str, membership.detail);\n                    if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                        emit_telemetry("ENT|%s|%s|%s|IGMP|%s%s\\n", ent_mac, src_ip_str, dst_ip_str, membership.detail, routed_str);\n                }\n                continue;\n            }\n\n            if (opt_enterprise && protocol == 112U && ttl == 255U &&\n'''
s = replace_once(s, old, new, 'IGMP/MLD dispatch')
sp.write_text(s)

bp = Path('src/argos_bpf.h'); b = bp.read_text()
b = replace_once(b,
'''    if (cfg->enterprise) {\n        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 89, 0, 1));\n''',
'''    if (cfg->enterprise) {\n        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1)); /* IGMP */\n        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));\n        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 89, 0, 1));\n''', 'IGMP BPF admission')
bp.write_text(b)

Path('tests/test_igmp_mld.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_multicast_membership.h"

int main(void) {
    argos_membership_result_t r;

    unsigned char igmp2[] = {0x16,0,0,0,239,1,2,3};
    assert(argos_igmp_parse(igmp2,sizeof(igmp2),&r));
    assert(strcmp(r.proto,"IGMP")==0 && strstr(r.detail,"version=2") && strstr(r.detail,"type=report"));
    assert(strstr(r.detail,"239.1.2.3")==NULL);

    unsigned char igmp3q[16] = {0x11,100,0,0,239,1,1,1,0,0,0,1,10,0,0,1};
    assert(argos_igmp_parse(igmp3q,sizeof(igmp3q),&r));
    assert(strstr(r.detail,"version=3") && strstr(r.detail,"type=query") && strstr(r.detail,"sources=1"));

    unsigned char igmp3r[20] = {0x22,0,0,0,0,0,0,1,1,0,0,1,239,1,1,2,10,0,0,1};
    assert(argos_igmp_parse(igmp3r,sizeof(igmp3r),&r));
    assert(strstr(r.detail,"records=1") && strstr(r.detail,"sources=1"));

    unsigned char mld1[24] = {131,0,0,0,0,0,0,0};
    mld1[8]=0xff; mld1[9]=0x02; mld1[23]=1;
    assert(argos_mld_parse(mld1,sizeof(mld1),&r));
    assert(strcmp(r.proto,"MLD")==0 && strstr(r.detail,"version=1") && strstr(r.detail,"type=report"));

    unsigned char mld2q[44] = {130,0,0,0,0,100,0,0};
    mld2q[8]=0xff; mld2q[9]=0x02; mld2q[23]=1; mld2q[24]=2; mld2q[25]=125; mld2q[26]=0; mld2q[27]=1; mld2q[28]=0x20; mld2q[29]=1;
    assert(argos_mld_parse(mld2q,sizeof(mld2q),&r));
    assert(strstr(r.detail,"version=2") && strstr(r.detail,"type=query") && strstr(r.detail,"sources=1"));

    unsigned char mld2r[44] = {143,0,0,0,0,0,0,1,1,0,0,1};
    mld2r[12]=0xff; mld2r[13]=0x02; mld2r[27]=2; mld2r[28]=0x20; mld2r[29]=1;
    assert(argos_mld_parse(mld2r,sizeof(mld2r),&r));
    assert(strstr(r.detail,"records=1") && strstr(r.detail,"sources=1"));

    igmp3r[7]=2; assert(!argos_igmp_parse(igmp3r,sizeof(igmp3r),&r));
    mld2r[7]=2; assert(!argos_mld_parse(mld2r,sizeof(mld2r),&r));
    puts("IGMP/MLD fixtures: PASS");
    return 0;
}
''')

tp = Path('tests/test_dynamic_bpf.c'); t = tp.read_text()
t = replace_once(t,
'''    expect(pass(&p, pkt, proto4(pkt, 89)), "OSPF passes");\n''',
'''    expect(pass(&p, pkt, proto4(pkt, 2)), "IGMP passes");\n    expect(pass(&p, pkt, proto4(pkt, 89)), "OSPF passes");\n''', 'IGMP BPF fixture')
tp.write_text(t)
