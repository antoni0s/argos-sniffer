from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n=text.count(old)
    if n!=1: raise SystemExit(f"{label}: expected one match, found {n}")
    return text.replace(old,new,1)

hsrp_h=r'''#ifndef ARGOS_HSRP_H
#define ARGOS_HSRP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t wire_version;
    uint8_t opcode;
    uint8_t state;
    uint8_t hello_time;
    uint8_t hold_time;
    uint8_t priority;
    uint8_t group;
    uint8_t auth_nonzero;
    char detail[256];
} argos_hsrp1_result_t;

static inline const char *ahsrp_opcode(uint8_t v) {
    return v==0U ? "hello" : v==1U ? "coup" : v==2U ? "resign" : "unknown";
}
static inline const char *ahsrp_state(uint8_t v) {
    switch(v) {
        case 0U: return "initial"; case 1U: return "learn"; case 2U: return "listen";
        case 4U: return "speak"; case 8U: return "standby"; case 16U: return "active";
        default: return "unknown";
    }
}

/* Classic HSRP (commonly called HSRPv1) uses wire Version=0 and a fixed
 * 20-byte UDP/1985 payload. The 8-byte cleartext authentication field and
 * virtual IPv4 address are deliberately not emitted. */
static inline int argos_hsrp1_parse(const unsigned char *p, size_t n,
                                    argos_hsrp1_result_t *r) {
    if (!p || !r || n < 20U) return 0;
    memset(r,0,sizeof(*r));
    if (p[0] != 0U || p[1] > 2U) return 0;
    r->wire_version=p[0]; r->opcode=p[1]; r->state=p[2];
    r->hello_time=p[3]; r->hold_time=p[4]; r->priority=p[5]; r->group=p[6];
    for (size_t i=8U;i<16U;i++) if (p[i] != 0U) { r->auth_nonzero=1U; break; }
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=1;wire_version=0;opcode=%s;state=%s;hello_s=%u;hold_s=%u;priority=%u;group=%u;auth_present=%u",
        ahsrp_opcode(r->opcode), ahsrp_state(r->state), (unsigned)r->hello_time,
        (unsigned)r->hold_time, (unsigned)r->priority, (unsigned)r->group,
        (unsigned)r->auth_nonzero);
    return 1;
}

#endif /* ARGOS_HSRP_H */
'''
Path('src/argos_hsrp.h').write_text(hsrp_h)

p=Path('src/argos_enterprise_ports.h'); s=p.read_text()
s=replace_once(s,
    '    88, 111, 161, 162, 389, 427, 623, 2049, 5060, 5678, 47808, 44818\n',
    '    88, 111, 161, 162, 389, 427, 623, 1985, 2049, 5060, 5678, 47808, 44818\n',
    'HSRP UDP port')
p.write_text(s)

p=Path('src/argos-sniffer.c'); s=p.read_text()
s=replace_once(s,
    '#include "argos_vrrp.h"\n#include "argos_enterprise.h"\n',
    '#include "argos_vrrp.h"\n#include "argos_hsrp.h"\n#include "argos_enterprise.h"\n',
    'HSRP include')
marker='''                if (opt_enterprise && argos_enterprise_udp_port(sport, dport)) {
'''
insert='''                if (opt_enterprise && ttl == 1U && (sport == 1985U || dport == 1985U)) {
                    argos_hsrp1_result_t hsrp;
                    if (argos_hsrp1_parse(payload, (size_t)payload_len, &hsrp)) {
                        char ent_mac[18], ent_sig[384];
                        if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);
                        else format_mac(src_mac, ent_mac);
                        snprintf(ent_sig, sizeof(ent_sig), "%s|HSRP|%s", src_ip_str, hsrp.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))
                            emit_telemetry("ENT|%s|%s|%s|HSRP|%s%s\\n",
                                           ent_mac, src_ip_str, dst_ip_str, hsrp.detail, routed_str);
                    }
                }
'''
s=replace_once(s,marker,insert+marker,'HSRP dispatch'); p.write_text(s)

fixture=r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_hsrp.h"
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
 unsigned char p[20]={0,0,16,3,10,105,1,0,'c','i','s','c','o',0,0,0,172,28,230,1};
 argos_hsrp1_result_t r;
 expect(argos_hsrp1_parse(p,sizeof(p),&r),"valid HSRPv1 hello");
 expect(r.wire_version==0 && r.opcode==0 && r.state==16 && r.priority==105 && r.group==1,"HSRP identity");
 expect(strstr(r.detail,"opcode=hello")!=NULL && strstr(r.detail,"state=active")!=NULL,"opcode/state detail");
 expect(strstr(r.detail,"auth_present=1")!=NULL,"auth presence only");
 expect(strstr(r.detail,"cisco")==NULL && strstr(r.detail,"172.28.230.1")==NULL,"auth and VIP not emitted");
 p[1]=1; expect(argos_hsrp1_parse(p,sizeof(p),&r) && strstr(r.detail,"opcode=coup")!=NULL,"coup");
 p[1]=2; expect(argos_hsrp1_parse(p,sizeof(p),&r) && strstr(r.detail,"opcode=resign")!=NULL,"resign");
 p[0]=1; expect(!argos_hsrp1_parse(p,sizeof(p),&r),"non-v1 wire version rejected");
 p[0]=0; p[1]=3; expect(!argos_hsrp1_parse(p,sizeof(p),&r),"unknown opcode rejected");
 expect(!argos_hsrp1_parse(p,19,&r),"short payload rejected");
 puts("HSRPv1 fixtures: PASS"); return 0;
}
'''
Path('tests/test_hsrp1.c').write_text(fixture)
print('step7g HSRPv1 patch applied')
