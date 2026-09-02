from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one match, found {n}")
    return text.replace(old, new, 1)

stp_h = r'''#ifndef ARGOS_STP_H
#define ARGOS_STP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint16_t root_priority;
    unsigned char root_mac[6];
    uint32_t root_cost;
    uint16_t bridge_priority;
    unsigned char bridge_mac[6];
    uint16_t port_id;
    uint16_t message_age;
    uint16_t max_age;
    uint16_t hello_time;
    uint16_t forward_delay;
    char detail[512];
} argos_stp_result_t;

static inline uint16_t astp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t astp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void astp_mac(char out[18], const unsigned char mac[6]) {
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Classic IEEE 802.1D BPDU over 802.3 LLC: DSAP=0x42, SSAP=0x42, UI=0x03.
 * Version 0 is intentionally handled here; RSTP/MSTP are separate gates. */
static inline int argos_stp_parse(const unsigned char *p, size_t n,
                                  argos_stp_result_t *r) {
    if (!p || !r || n < 7U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x42U || p[1] != 0x42U || p[2] != 0x03U) return 0;
    if (p[3] != 0x00U || p[4] != 0x00U) return 0; /* protocol id */
    r->version = p[5];
    r->type = p[6];
    if (r->version != 0U) return 0;

    if (r->type == 0x80U) {
        (void)snprintf(r->detail, sizeof(r->detail), "version=0;type=tcn");
        return 1;
    }
    if (r->type != 0x00U || n < 38U) return 0;

    r->flags = p[7];
    r->root_priority = astp_be16(p + 8);
    memcpy(r->root_mac, p + 10, 6);
    r->root_cost = astp_be32(p + 16);
    r->bridge_priority = astp_be16(p + 20);
    memcpy(r->bridge_mac, p + 22, 6);
    r->port_id = astp_be16(p + 28);
    r->message_age = astp_be16(p + 30);
    r->max_age = astp_be16(p + 32);
    r->hello_time = astp_be16(p + 34);
    r->forward_delay = astp_be16(p + 36);

    char root[18], bridge[18];
    astp_mac(root, r->root_mac);
    astp_mac(bridge, r->bridge_mac);
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=0;type=config;flags=0x%02x;root_prio=%u;root=%s;cost=%u;"
        "bridge_prio=%u;bridge=%s;port=0x%04x;age=%u;max=%u;hello=%u;fwd=%u",
        (unsigned)r->flags, (unsigned)r->root_priority, root, (unsigned)r->root_cost,
        (unsigned)r->bridge_priority, bridge, (unsigned)r->port_id,
        (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
}

#endif /* ARGOS_STP_H */
'''
Path('src/argos_stp.h').write_text(stp_h)

p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_lacp.h"\n#include "argos_enterprise.h"\n',
    '#include "argos_lacp.h"\n#include "argos_stp.h"\n#include "argos_enterprise.h"\n',
    'STP include')

old = '''(opt_enterprise && (l3_proto == 0x8809U || l3_proto == 0x888eU || l3_proto == 0x8892U ||\n                                           l3_proto == 0x2000U || l3_proto == 0x00feU ||\n                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
new = '''(opt_enterprise && (l3_proto <= 1500U || l3_proto == 0x8809U || l3_proto == 0x888eU || l3_proto == 0x8892U ||\n                                           l3_proto == 0x2000U || l3_proto == 0x00feU ||\n                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
s = replace_once(s, old, new, 'STP L2 admission')

old = '''(opt_enterprise && (l3_proto == 0x8809U || l3_proto == 0x888eU || l3_proto == 0x8892U ||\n                                    l3_proto == 0x2000U || l3_proto == 0x00feU ||\n                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
new = '''(opt_enterprise && (l3_proto <= 1500U || l3_proto == 0x8809U || l3_proto == 0x888eU || l3_proto == 0x8892U ||\n                                    l3_proto == 0x2000U || l3_proto == 0x00feU ||\n                                    l3_proto == 0x00bbU || l3_proto == 0xf200U)))'''
s = replace_once(s, old, new, 'STP device identity')

marker = '''            if (opt_enterprise && l3_proto == 0x8809U) {'''
insert = '''            if (opt_enterprise && l3_proto <= 1500U) {
                argos_stp_result_t stp;
                if (argos_stp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &stp)) {
                    if (!dedup_should_suppress(mac_str, "ENT", stp.detail, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|-|-|STP|%s\\n", mac_str, stp.detail);
                    continue;
                }
            }
'''
s = replace_once(s, marker, insert + marker, 'STP dispatch')
p.write_text(s)

fixture = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_stp.h"
static void put16(unsigned char *p, uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p, uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
    unsigned char p[64]={0x42,0x42,0x03,0x00,0x00,0x00,0x00,0x01};
    put16(p+8,32768); const unsigned char root[6]={0,1,2,3,4,5}; memcpy(p+10,root,6);
    put32(p+16,4); put16(p+20,32768); const unsigned char br[6]={0,0xaa,0xbb,0xcc,0xdd,0xee}; memcpy(p+22,br,6);
    put16(p+28,0x8001); put16(p+30,0x0100); put16(p+32,0x1400); put16(p+34,0x0200); put16(p+36,0x0f00);
    argos_stp_result_t r;
    expect(argos_stp_parse(p,38,&r),"classic config BPDU");
    expect(r.version==0 && r.type==0 && r.root_priority==32768 && r.root_cost==4,"root fields");
    expect(r.bridge_priority==32768 && r.port_id==0x8001,"bridge/port fields");
    expect(strstr(r.detail,"root=00:01:02:03:04:05")!=NULL,"root MAC detail");
    expect(strstr(r.detail,"bridge=00:aa:bb:cc:dd:ee")!=NULL,"bridge MAC detail");
    p[6]=0x80; expect(argos_stp_parse(p,7,&r) && strstr(r.detail,"type=tcn")!=NULL,"TCN BPDU");
    p[5]=2; expect(!argos_stp_parse(p,38,&r),"RSTP rejected by classic parser");
    p[5]=0; p[0]=0xaa; expect(!argos_stp_parse(p,38,&r),"non-STP LLC rejected");
    puts("classic STP fixtures: PASS");
    return 0;
}
'''
Path('tests/test_stp.c').write_text(fixture)
print('step7c classic STP patch applied')
