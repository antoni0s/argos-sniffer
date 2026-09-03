#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_l2.h"
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
