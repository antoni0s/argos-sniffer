#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_l2.h"
static void put16(unsigned char *p,uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p,uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
 unsigned char p[64]={0x42,0x42,0x03,0,0,2,2,0x7e};
 put16(p+8,4096); const unsigned char rmac[6]={0,1,2,3,4,5}; memcpy(p+10,rmac,6); put32(p+16,19);
 put16(p+20,32768); const unsigned char bmac[6]={0x10,0x11,0x12,0x13,0x14,0x15}; memcpy(p+22,bmac,6);
 put16(p+28,0x8001); put16(p+30,0x0100); put16(p+32,0x1400); put16(p+34,0x0200); put16(p+36,0x0f00);
 argos_stp_result_t r; expect(argos_rstp_parse(p,sizeof(p),&r),"parse");
 expect(strcmp(r.proto,"RSTP")==0,"proto"); expect(r.version==2,"version"); expect(r.type==2,"type"); expect(r.flags==0x7e,"flags");
 expect(r.root_priority==4096,"root-priority"); expect(r.root_cost==19,"root-cost"); expect(r.bridge_priority==32768,"bridge-priority");
 expect(r.port_id==0x8001,"port-id"); expect(r.message_age==0x0100,"message-age"); expect(r.max_age==0x1400,"max-age");
 expect(r.hello_time==0x0200,"hello"); expect(r.forward_delay==0x0f00,"forward-delay");
 puts("RSTP fixtures: PASS"); return 0;
}
