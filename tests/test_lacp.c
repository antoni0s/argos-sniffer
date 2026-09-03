#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_l2.h"

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
