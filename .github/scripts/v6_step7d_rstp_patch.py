from pathlib import Path


def replace_once(text, old, new, label):
    n=text.count(old)
    if n!=1: raise SystemExit(f"{label}: expected one match, found {n}")
    return text.replace(old,new,1)

p=Path('src/argos_stp.h')
s=p.read_text()
insert=r'''
static inline const char *arstp_role(uint8_t flags) {
    switch ((flags >> 2) & 0x03U) {
        case 1U: return "alternate-backup";
        case 2U: return "root";
        case 3U: return "designated";
        default: return "unknown";
    }
}

/* IEEE 802.1w RSTP BPDU: version 2, type 0x02, same common bridge fields
 * as configuration BPDUs plus Version 1 Length (normally zero). */
static inline int argos_rstp_parse(const unsigned char *p, size_t n,
                                   argos_stp_result_t *r) {
    if (!p || !r || n < 39U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x42U || p[1] != 0x42U || p[2] != 0x03U) return 0;
    if (p[3] != 0x00U || p[4] != 0x00U || p[5] != 0x02U || p[6] != 0x02U) return 0;
    if (p[38] != 0x00U) return 0;
    r->version=2U; r->type=0x02U; r->flags=p[7];
    r->root_priority=astp_be16(p+8); memcpy(r->root_mac,p+10,6);
    r->root_cost=astp_be32(p+16);
    r->bridge_priority=astp_be16(p+20); memcpy(r->bridge_mac,p+22,6);
    r->port_id=astp_be16(p+28);
    r->message_age=astp_be16(p+30); r->max_age=astp_be16(p+32);
    r->hello_time=astp_be16(p+34); r->forward_delay=astp_be16(p+36);
    char root[18], bridge[18]; astp_mac(root,r->root_mac); astp_mac(bridge,r->bridge_mac);
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=2;type=rstp;flags=0x%02x;role=%s;proposal=%u;learning=%u;forwarding=%u;agreement=%u;"
        "root_prio=%u;root=%s;cost=%u;bridge_prio=%u;bridge=%s;port=0x%04x;age=%u;max=%u;hello=%u;fwd=%u",
        (unsigned)r->flags, arstp_role(r->flags), (unsigned)((r->flags>>1)&1U),
        (unsigned)((r->flags>>4)&1U), (unsigned)((r->flags>>5)&1U), (unsigned)((r->flags>>6)&1U),
        (unsigned)r->root_priority, root, (unsigned)r->root_cost, (unsigned)r->bridge_priority,
        bridge, (unsigned)r->port_id, (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
}
'''
s=replace_once(s,'\n#endif /* ARGOS_STP_H */\n',insert+'\n#endif /* ARGOS_STP_H */\n','RSTP parser insert')
p.write_text(s)

p=Path('src/argos-sniffer.c'); s=p.read_text()
old='''                if (argos_stp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &stp)) {
                    if (!dedup_should_suppress(mac_str, "ENT", stp.detail, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|-|-|STP|%s\\n", mac_str, stp.detail);
                    continue;
                }
'''
new=old+'''                if (argos_rstp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &stp)) {
                    if (!dedup_should_suppress(mac_str, "ENT", stp.detail, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|-|-|RSTP|%s\\n", mac_str, stp.detail);
                    continue;
                }
'''
s=replace_once(s,old,new,'RSTP dispatch'); p.write_text(s)

fixture=r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_stp.h"
static void put16(unsigned char *p,uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p,uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
 unsigned char p[64]={0x42,0x42,0x03,0,0,2,2,0x7e};
 put16(p+8,4096); const unsigned char rmac[6]={0,1,2,3,4,5}; memcpy(p+10,rmac,6); put32(p+16,19);
 put16(p+20,32768); const unsigned char bmac[6]={0x10,0x11,0x12,0x13,0x14,0x15}; memcpy(p+22,bmac,6);
 put16(p+28,0x8002); put16(p+30,0x0100); put16(p+32,0x1400); put16(p+34,0x0200); put16(p+36,0x0f00); p[38]=0;
 argos_stp_result_t r;
 expect(argos_rstp_parse(p,39,&r),"valid RSTP BPDU");
 expect(r.version==2 && r.type==2 && r.root_cost==19,"RSTP common fields");
 expect(strstr(r.detail,"role=designated")!=NULL,"RSTP designated role");
 expect(strstr(r.detail,"proposal=1")!=NULL && strstr(r.detail,"agreement=1")!=NULL,"RSTP flags");
 expect(!argos_stp_parse(p,39,&r),"classic STP parser rejects RSTP");
 p[38]=1; expect(!argos_rstp_parse(p,39,&r),"nonzero version1 length rejected");
 p[38]=0; p[5]=3; expect(!argos_rstp_parse(p,39,&r),"MSTP rejected by RSTP parser");
 puts("RSTP fixtures: PASS"); return 0;
}
'''
Path('tests/test_rstp.c').write_text(fixture)
print('step7d RSTP patch applied')
