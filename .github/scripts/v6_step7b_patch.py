from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


lacp_h = r'''#ifndef ARGOS_LACP_H
#define ARGOS_LACP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint16_t actor_system_priority;
    unsigned char actor_system[6];
    uint16_t actor_key;
    uint16_t actor_port_priority;
    uint16_t actor_port;
    uint8_t actor_state;
    uint16_t partner_system_priority;
    unsigned char partner_system[6];
    uint16_t partner_key;
    uint16_t partner_port_priority;
    uint16_t partner_port;
    uint8_t partner_state;
    char detail[512];
} argos_lacp_result_t;

static inline uint16_t alacp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void alacp_mac(char out[18], const unsigned char mac[6]) {
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline void alacp_state(char out[80], uint8_t s) {
    size_t used = 0U;
#define FLAG(bit,name) do { \
    if (s & (bit)) { \
        int n = snprintf(out + used, 80U - used, "%s%s", used ? "," : "", (name)); \
        if (n > 0) used += (size_t)n < 80U - used ? (size_t)n : 80U - used - 1U; \
    } \
} while (0)
    out[0] = '\0';
    FLAG(0x01U, "active");
    FLAG(0x02U, "short");
    FLAG(0x04U, "agg");
    FLAG(0x08U, "sync");
    FLAG(0x10U, "collect");
    FLAG(0x20U, "dist");
    FLAG(0x40U, "defaulted");
    FLAG(0x80U, "expired");
#undef FLAG
    if (!out[0]) strcpy(out, "none");
}

/* IEEE 802.1AX LACPDU on Slow Protocols EtherType 0x8809.
 * Payload begins with Subtype=1, Version, Actor TLV(type=1,len=20), then
 * Partner TLV(type=2,len=20). Only fixed control-plane identity/state is kept. */
static inline int argos_lacp_parse(const unsigned char *p, size_t n,
                                   argos_lacp_result_t *r) {
    if (!p || !r || n < 42U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x01U || (p[1] != 0x01U && p[1] != 0x02U)) return 0;
    if (p[2] != 0x01U || p[3] != 0x14U) return 0;
    if (p[22] != 0x02U || p[23] != 0x14U) return 0;

    r->version = p[1];
    r->actor_system_priority = alacp_be16(p + 4);
    memcpy(r->actor_system, p + 6, 6);
    r->actor_key = alacp_be16(p + 12);
    r->actor_port_priority = alacp_be16(p + 14);
    r->actor_port = alacp_be16(p + 16);
    r->actor_state = p[18];

    r->partner_system_priority = alacp_be16(p + 24);
    memcpy(r->partner_system, p + 26, 6);
    r->partner_key = alacp_be16(p + 32);
    r->partner_port_priority = alacp_be16(p + 34);
    r->partner_port = alacp_be16(p + 36);
    r->partner_state = p[38];

    char amac[18], pmac[18], ast[80], pst[80];
    alacp_mac(amac, r->actor_system);
    alacp_mac(pmac, r->partner_system);
    alacp_state(ast, r->actor_state);
    alacp_state(pst, r->partner_state);
    (void)snprintf(r->detail, sizeof(r->detail),
        "v=%u;actor=%s;sys_prio=%u;key=%u;port_prio=%u;port=%u;state=0x%02x(%s);"
        "partner=%s;partner_prio=%u;partner_key=%u;partner_port_prio=%u;partner_port=%u;partner_state=0x%02x(%s)",
        (unsigned)r->version, amac, (unsigned)r->actor_system_priority,
        (unsigned)r->actor_key, (unsigned)r->actor_port_priority, (unsigned)r->actor_port,
        (unsigned)r->actor_state, ast, pmac, (unsigned)r->partner_system_priority,
        (unsigned)r->partner_key, (unsigned)r->partner_port_priority,
        (unsigned)r->partner_port, (unsigned)r->partner_state, pst);
    return 1;
}

#endif /* ARGOS_LACP_H */
'''
Path('src/argos_lacp.h').write_text(lacp_h)

p = Path('src/argos_bpf.h')
s = p.read_text()
s = replace_once(s,
    '        EMIT(abpf_pass_ethertype(p, 0x88cc)); /* LLDP / LLDP-MED */\n'
    '        EMIT(abpf_pass_ethertype(p, 0x888e)); /* EAPoL */\n',
    '        EMIT(abpf_pass_ethertype(p, 0x88cc)); /* LLDP / LLDP-MED */\n'
    '        EMIT(abpf_pass_ethertype(p, 0x8809)); /* Slow Protocols / LACP */\n'
    '        EMIT(abpf_pass_ethertype(p, 0x888e)); /* EAPoL */\n',
    'LACP BPF EtherType')
p.write_text(s)

p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_lldp_med.h"\n#include "argos_enterprise.h"\n',
    '#include "argos_lldp_med.h"\n#include "argos_lacp.h"\n#include "argos_enterprise.h"\n',
    'LACP include')

old = '''(opt_enterprise && (l3_proto == 0x888eU || l3_proto == 0x8892U ||
                                           l3_proto == 0x2000U || l3_proto == 0x00feU ||
                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
new = '''(opt_enterprise && (l3_proto == 0x8809U || l3_proto == 0x888eU || l3_proto == 0x8892U ||
                                           l3_proto == 0x2000U || l3_proto == 0x00feU ||
                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
s = replace_once(s, old, new, 'LACP L2 admission')

old = '''(opt_enterprise && (l3_proto == 0x888eU || l3_proto == 0x8892U ||
                                    l3_proto == 0x2000U || l3_proto == 0x00feU ||
                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
new = '''(opt_enterprise && (l3_proto == 0x8809U || l3_proto == 0x888eU || l3_proto == 0x8892U ||
                                    l3_proto == 0x2000U || l3_proto == 0x00feU ||
                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
s = replace_once(s, old, new, 'LACP device identity')

marker = '''            if (opt_enterprise && (l3_proto == 0x888eU || l3_proto == 0x8892U ||
                                   l3_proto == 0x2000U || l3_proto == 0x00feU ||
                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)) {'''
insert = '''            if (opt_enterprise && l3_proto == 0x8809U) {
                argos_lacp_result_t lacp;
                if (argos_lacp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &lacp)) {
                    if (!dedup_should_suppress(mac_str, "ENT", lacp.detail, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|-|-|LACP|%s\\n", mac_str, lacp.detail);
                }
                continue;
            }
'''
s = replace_once(s, marker, insert + marker, 'LACP dispatch')
p.write_text(s)

# Add enterprise-only EtherType regression alongside LLDP-MED, without relying
# on newline escaping in the staging script itself.
p = Path('tests/test_dynamic_bpf.c')
s = p.read_text()
marker = '    expect(pass(&p, pkt, 64), "enterprise-only admits LLDP-MED EtherType");'
addition = marker + '\n    expect(pass(&p, pkt, eth(pkt, 0x8809)), "enterprise-only admits Slow Protocols/LACP EtherType");'
s = replace_once(s, marker, addition, 'LACP BPF fixture')
p.write_text(s)

fixture = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_lacp.h"

static void put16(unsigned char *p, uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
    unsigned char p[64]={0};
    p[0]=1; p[1]=1;
    p[2]=1; p[3]=20; put16(p+4,32768);
    const unsigned char a[6]={0x00,0x11,0x22,0x33,0x44,0x55}; memcpy(p+6,a,6);
    put16(p+12,7); put16(p+14,128); put16(p+16,3); p[18]=0x3f;
    p[22]=2; p[23]=20; put16(p+24,4096);
    const unsigned char b[6]={0xaa,0xbb,0xcc,0xdd,0xee,0xff}; memcpy(p+26,b,6);
    put16(p+32,7); put16(p+34,64); put16(p+36,9); p[38]=0x0d;
    p[42]=3; p[43]=16;
    argos_lacp_result_t r;
    expect(argos_lacp_parse(p,sizeof(p),&r),"valid LACPDU");
    expect(r.version==1 && r.actor_system_priority==32768 && r.actor_key==7,"actor identity");
    expect(r.actor_port_priority==128 && r.actor_port==3 && r.actor_state==0x3f,"actor port/state");
    expect(r.partner_system_priority==4096 && r.partner_key==7 && r.partner_port==9,"partner identity");
    expect(strstr(r.detail,"actor=00:11:22:33:44:55")!=NULL,"actor MAC detail");
    expect(strstr(r.detail,"state=0x3f(active,short,agg,sync,collect,dist)")!=NULL,"actor state detail");
    expect(strstr(r.detail,"partner=aa:bb:cc:dd:ee:ff")!=NULL,"partner MAC detail");
    p[0]=2; expect(!argos_lacp_parse(p,sizeof(p),&r),"non-LACP slow subtype rejected");
    p[0]=1; p[3]=19; expect(!argos_lacp_parse(p,sizeof(p),&r),"bad actor TLV length rejected");
    puts("LACP fingerprint fixtures: PASS");
    return 0;
}
'''
Path('tests/test_lacp.c').write_text(fixture)
print('step7b LACP patch applied')
