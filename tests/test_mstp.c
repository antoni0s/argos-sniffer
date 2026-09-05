#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_l2.h"
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
 expect(strcmp(r.detail,"type=mstp version=3 flags=0x3c root_id=0000.00:00:00:00:00:00 root_cost=0 "
        "bridge_id=0000.00:00:00:00:00:00 port_id=0x0000 message_age=0 max_age=0 "
        "hello_time=0 forward_delay=0 mst_revision=7 mst_digest=000102030405060708090a0b0c0d0e0f")==0,
        "frozen MSTP detail");
 expect(strstr(r.detail,"INTERNAL-REGION") == NULL,"raw config name not emitted");
 p[39]=0; p[40]=65; expect(!argos_mstp_parse(p,121,&r),"misaligned MSTI payload rejected");
 p[40]=80; p[41]=1; expect(!argos_mstp_parse(p,121,&r),"nonzero format selector rejected");
 p[41]=0; expect(!argos_mstp_parse(p,104,&r),"truncated MSTP rejected");
 puts("MSTP fixtures: PASS"); return 0;
}
