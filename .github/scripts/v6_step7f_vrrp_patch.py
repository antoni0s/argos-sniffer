from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one match, found {n}")
    return text.replace(old, new, 1)

vrrp_h = r'''#ifndef ARGOS_VRRP_H
#define ARGOS_VRRP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t vrid;
    uint8_t priority;
    uint8_t address_count;
    uint8_t auth_type;
    uint16_t advert_interval;
    uint8_t interval_unit_cs;
    uint8_t owner;
    uint8_t relinquish;
    char detail[256];
} argos_vrrp_result_t;

static inline uint16_t avrrp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* RFC 3768 VRRPv2 (IPv4) and RFC 5798 VRRPv3 (IPv4/IPv6).
 * Virtual IP addresses and v2 authentication data are intentionally not
 * emitted: VRID/priority/count/interval are sufficient HA fingerprints. */
static inline int argos_vrrp_parse(const unsigned char *p, size_t n,
                                   uint8_t ip_version,
                                   argos_vrrp_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));
    r->version = (uint8_t)(p[0] >> 4);
    r->type = (uint8_t)(p[0] & 0x0fU);
    if (r->type != 1U) return 0; /* Advertisement */
    r->vrid = p[1];
    r->priority = p[2];
    r->address_count = p[3];
    if (r->vrid == 0U || r->address_count == 0U) return 0;
    r->owner = (uint8_t)(r->priority == 255U);
    r->relinquish = (uint8_t)(r->priority == 0U);

    if (r->version == 2U) {
        if (ip_version != 4U) return 0;
        size_t need = 8U + (size_t)r->address_count * 4U + 8U;
        if (n < need) return 0;
        r->auth_type = p[4];
        r->advert_interval = p[5];
        r->interval_unit_cs = 0U;
        (void)snprintf(r->detail, sizeof(r->detail),
            "version=2;vrid=%u;priority=%u;count=%u;auth_type=%u;interval_s=%u;owner=%u;relinquish=%u",
            (unsigned)r->vrid, (unsigned)r->priority, (unsigned)r->address_count,
            (unsigned)r->auth_type, (unsigned)r->advert_interval,
            (unsigned)r->owner, (unsigned)r->relinquish);
        return 1;
    }

    if (r->version == 3U) {
        if (ip_version != 4U && ip_version != 6U) return 0;
        size_t addr_len = ip_version == 6U ? 16U : 4U;
        size_t need = 8U + (size_t)r->address_count * addr_len;
        if (n < need) return 0;
        uint16_t interval_word = avrrp_be16(p + 4);
        r->advert_interval = (uint16_t)(interval_word & 0x0fffU);
        r->interval_unit_cs = 1U;
        (void)snprintf(r->detail, sizeof(r->detail),
            "version=3;family=ipv%u;vrid=%u;priority=%u;count=%u;interval_cs=%u;owner=%u;relinquish=%u",
            (unsigned)ip_version, (unsigned)r->vrid, (unsigned)r->priority,
            (unsigned)r->address_count, (unsigned)r->advert_interval,
            (unsigned)r->owner, (unsigned)r->relinquish);
        return 1;
    }
    return 0;
}

#endif /* ARGOS_VRRP_H */
'''
Path('src/argos_vrrp.h').write_text(vrrp_h)

p = Path('src/argos_bpf.h')
s = p.read_text()
s = replace_once(s,
    '''    if (cfg->enterprise) {\n        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 89, 0, 1));\n        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));\n    }\n''',
    '''    if (cfg->enterprise) {\n        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 89, 0, 1));\n        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));\n        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 112, 0, 1)); /* VRRP */\n        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));\n    }\n''',
    'VRRP BPF IP protocol')
p.write_text(s)

p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_stp.h"\n#include "argos_enterprise.h"\n',
    '#include "argos_stp.h"\n#include "argos_vrrp.h"\n#include "argos_enterprise.h"\n',
    'VRRP include')
marker = '''            if (opt_enterprise && protocol == 89U && l4_offset >= 0 && l4_offset < l3_packet_end) {'''
insert = '''            if (opt_enterprise && protocol == 112U && ttl == 255U &&
                l4_offset >= 0 && l4_offset < l3_packet_end) {
                argos_vrrp_result_t vrrp;
                if (argos_vrrp_parse(buffer + l4_offset, (size_t)(l3_packet_end - l4_offset),
                                     flow_ip_version, &vrrp)) {
                    char ent_mac[18], ent_sig[384];
                    if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);
                    else format_mac(src_mac, ent_mac);
                    snprintf(ent_sig, sizeof(ent_sig), "%s|VRRP|%s", src_ip_str, vrrp.detail);
                    if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|%s|%s|VRRP|%s%s\\n",
                                       ent_mac, src_ip_str, dst_ip_str, vrrp.detail, routed_str);
                }
                continue;
            }

'''
s = replace_once(s, marker, insert + marker, 'VRRP dispatch')
p.write_text(s)

# Extend dynamic BPF interpreter matrix with protocol 112 admission.
p = Path('tests/test_dynamic_bpf.c')
s = p.read_text()
marker = '    expect(pass(&p, pkt, proto4(pkt, 89)), "OSPF passes");'
s = replace_once(s, marker, marker + '\n    expect(pass(&p, pkt, proto4(pkt, 112)), "VRRP passes");', 'VRRP BPF fixture')
p.write_text(s)

fixture = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_vrrp.h"
static void put16(unsigned char *p,uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
    argos_vrrp_result_t r;
    unsigned char v2[32]={0};
    v2[0]=0x21; v2[1]=42; v2[2]=100; v2[3]=2; v2[4]=0; v2[5]=1;
    expect(argos_vrrp_parse(v2,24,4,&r),"VRRPv2 IPv4 advertisement");
    expect(r.version==2 && r.vrid==42 && r.priority==100 && r.address_count==2,"v2 identity");
    expect(strstr(r.detail,"interval_s=1")!=NULL && strstr(r.detail,"auth_type=0")!=NULL,"v2 interval/auth");
    expect(!argos_vrrp_parse(v2,24,6,&r),"VRRPv2 rejected on IPv6");

    unsigned char v3[40]={0};
    v3[0]=0x31; v3[1]=7; v3[2]=255; v3[3]=1; put16(v3+4,25);
    expect(argos_vrrp_parse(v3,12,4,&r),"VRRPv3 IPv4 advertisement");
    expect(r.version==3 && r.owner==1 && r.advert_interval==25,"v3 owner/interval");
    expect(strstr(r.detail,"family=ipv4")!=NULL && strstr(r.detail,"interval_cs=25")!=NULL,"v3 IPv4 detail");

    v3[2]=0; v3[3]=1; put16(v3+4,100);
    expect(argos_vrrp_parse(v3,24,6,&r),"VRRPv3 IPv6 advertisement");
    expect(r.relinquish==1 && strstr(r.detail,"family=ipv6")!=NULL,"v3 IPv6 relinquish");

    v3[0]=0x32; expect(!argos_vrrp_parse(v3,24,6,&r),"unknown VRRP type rejected");
    v3[0]=0x31; v3[1]=0; expect(!argos_vrrp_parse(v3,24,6,&r),"VRID zero rejected");
    v3[1]=7; v3[3]=0; expect(!argos_vrrp_parse(v3,24,6,&r),"zero address count rejected");
    puts("VRRP fixtures: PASS");
    return 0;
}
'''
Path('tests/test_vrrp.c').write_text(fixture)
print('step7f VRRP patch applied')
