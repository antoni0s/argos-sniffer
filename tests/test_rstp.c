#include <stdint.h>
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
