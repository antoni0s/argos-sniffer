from pathlib import Path

def replace_once(text, old, new, label):
    n=text.count(old)
    if n!=1: raise SystemExit(f"{label}: expected one match, found {n}")
    return text.replace(old,new,1)

p=Path('src/argos_stp.h'); s=p.read_text()
insert=r'''
typedef struct {
    uint16_t version3_length;
    uint16_t config_revision;
    unsigned char config_digest[16];
    uint32_t cist_internal_root_cost;
    uint16_t cist_bridge_priority;
    unsigned char cist_bridge_mac[6];
    uint8_t cist_remaining_hops;
    uint16_t msti_count;
    uint8_t first_msti_flags;
    uint16_t first_msti_root_priority;
    unsigned char first_msti_root_mac[6];
    uint32_t first_msti_root_cost;
    uint8_t first_msti_bridge_priority;
    uint8_t first_msti_port_priority;
    uint8_t first_msti_remaining_hops;
    char detail[640];
} argos_mstp_result_t;

static inline void amstp_digest_hex(char out[33], const unsigned char d[16]) {
    static const char hex[]="0123456789abcdef";
    for (size_t i=0;i<16U;i++) { out[i*2U]=hex[d[i]>>4]; out[i*2U+1U]=hex[d[i]&0x0fU]; }
    out[32]='\0';
}

/* IEEE 802.1s/802.1Q MSTP: version 3, type 0x02. Privacy note: the raw
 * 32-byte MST configuration name is intentionally not emitted. The revision
 * and standardized 16-byte configuration digest identify the region without
 * leaking an internal site/organization label. */
static inline int argos_mstp_parse(const unsigned char *p, size_t n,
                                   argos_mstp_result_t *r) {
    if (!p || !r || n < 105U) return 0;
    memset(r,0,sizeof(*r));
    if (p[0]!=0x42U || p[1]!=0x42U || p[2]!=0x03U) return 0;
    if (p[3]!=0x00U || p[4]!=0x00U || p[5]!=0x03U || p[6]!=0x02U) return 0;
    if (p[38]!=0x00U) return 0;
    r->version3_length=astp_be16(p+39);
    if (r->version3_length < 64U) return 0;
    if ((size_t)r->version3_length > n-41U) return 0;
    if (((r->version3_length-64U) % 16U) != 0U) return 0;
    if (p[41] != 0x00U) return 0; /* MST config format selector */
    r->config_revision=astp_be16(p+74);
    memcpy(r->config_digest,p+76,16);
    r->cist_internal_root_cost=astp_be32(p+92);
    r->cist_bridge_priority=astp_be16(p+96);
    memcpy(r->cist_bridge_mac,p+98,6);
    r->cist_remaining_hops=p[104];
    r->msti_count=(uint16_t)((r->version3_length-64U)/16U);

    if (r->msti_count>0U) {
        const unsigned char *m=p+105;
        r->first_msti_flags=m[0];
        r->first_msti_root_priority=astp_be16(m+1);
        memcpy(r->first_msti_root_mac,m+3,6);
        r->first_msti_root_cost=astp_be32(m+9);
        r->first_msti_bridge_priority=m[13];
        r->first_msti_port_priority=m[14];
        r->first_msti_remaining_hops=m[15];
    }

    char dig[33], cist[18], mroot[18];
    amstp_digest_hex(dig,r->config_digest); astp_mac(cist,r->cist_bridge_mac);
    if (r->msti_count>0U) astp_mac(mroot,r->first_msti_root_mac); else strcpy(mroot,"none");
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=3;v3len=%u;revision=%u;digest=%s;cist_cost=%u;cist_bridge_prio=%u;cist_bridge=%s;cist_hops=%u;msti_count=%u;"
        "msti1_flags=0x%02x;msti1_root_prio=%u;msti1_root=%s;msti1_cost=%u;msti1_bridge_prio=%u;msti1_port_prio=%u;msti1_hops=%u",
        (unsigned)r->version3_length,(unsigned)r->config_revision,dig,(unsigned)r->cist_internal_root_cost,
        (unsigned)r->cist_bridge_priority,cist,(unsigned)r->cist_remaining_hops,(unsigned)r->msti_count,
        (unsigned)r->first_msti_flags,(unsigned)r->first_msti_root_priority,mroot,(unsigned)r->first_msti_root_cost,
        (unsigned)r->first_msti_bridge_priority,(unsigned)r->first_msti_port_priority,(unsigned)r->first_msti_remaining_hops);
    return 1;
}
'''
s=replace_once(s,'\n#endif /* ARGOS_STP_H */\n',insert+'\n#endif /* ARGOS_STP_H */\n','MSTP parser insert'); p.write_text(s)

p=Path('src/argos-sniffer.c'); s=p.read_text()
old='''                if (argos_rstp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &stp)) {
                    if (!dedup_should_suppress(mac_str, "ENT", stp.detail, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|-|-|RSTP|%s\\n", mac_str, stp.detail);
                    continue;
                }
'''
new=old+'''                argos_mstp_result_t mstp;
                if (argos_mstp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &mstp)) {
                    if (!dedup_should_suppress(mac_str, "ENT", mstp.detail, opt_enterprise_rl))
                        emit_telemetry("ENT|%s|-|-|MSTP|%s\\n", mac_str, mstp.detail);
                    continue;
                }
'''
s=replace_once(s,old,new,'MSTP dispatch'); p.write_text(s)

fixture=r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_stp.h"
static void put16(unsigned char *p,uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p,uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
 unsigned char p[140]={0x42,0x42,0x03,0,0,3,2,0x3c};
 p[38]=0; put16(p+39,80); p[41]=0;
 memcpy(p+42,"INTERNAL-REGION-NAME-SHOULD-HIDE",31); put16(p+74,7);
 for(int i=0;i<16;i++) p[76+i]=(unsigned char)i;
 put32(p+92,1234); put16(p+96,32768); const unsigned char cb[6]={0,0xaa,0xbb,0xcc,0xdd,0xee}; memcpy(p+98,cb,6); p[104]=19;
 unsigned char *m=p+105; m[0]=0x3c; put16(m+1,4096); const unsigned char rm[6]={0,1,2,3,4,5}; memcpy(m+3,rm,6); put32(m+9,55); m[13]=0x80; m[14]=0x80; m[15]=18;
 argos_mstp_result_t r;
 expect(argos_mstp_parse(p,121,&r),"valid MSTP with one MSTI");
 expect(r.version3_length==80 && r.config_revision==7 && r.msti_count==1,"MST config fields");
 expect(r.cist_internal_root_cost==1234 && r.cist_remaining_hops==19,"CIST fields");
 expect(r.first_msti_root_cost==55 && r.first_msti_remaining_hops==18,"MSTI fields");
 expect(strstr(r.detail,"digest=000102030405060708090a0b0c0d0e0f")!=NULL,"config digest detail");
 expect(strstr(r.detail,"INTERNAL-REGION") == NULL,"raw config name not emitted");
 p[39]=0; p[40]=65; expect(!argos_mstp_parse(p,121,&r),"misaligned MSTI payload rejected");
 p[40]=80; p[41]=1; expect(!argos_mstp_parse(p,121,&r),"nonzero format selector rejected");
 puts("MSTP fixtures: PASS"); return 0;
}
'''
Path('tests/test_mstp.c').write_text(fixture)
print('step7e MSTP patch applied')
