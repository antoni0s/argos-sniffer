#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_l2.h"

static void put16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void put32(unsigned char *p, uint32_t v) { p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v; }
static size_t tlv(unsigned char *p, unsigned type, const unsigned char *v, size_t n) { put16(p,(uint16_t)((type<<9)|n)); memcpy(p+2,v,n); return n+2; }
static size_t med(unsigned char *p, uint8_t subtype, const unsigned char *v, size_t n) { unsigned char b[128]={0x00,0x12,0xbb,0}; b[3]=subtype; memcpy(b+4,v,n); return tlv(p,127,b,n+4); }
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
  unsigned char p[512]={0}; size_t n=0; unsigned char caps[3]={0x00,0x23,0x03};
  n+=med(p+n,1,caps,sizeof(caps));
  unsigned char pol[4]; uint32_t w=(1U<<24)|(1U<<22)|(200U<<9)|(5U<<6)|46U; put32(pol,w); n+=med(p+n,2,pol,4);
  const unsigned char loc[]="SECRET-ROOM-42"; n+=med(p+n,3,loc,sizeof(loc)-1);
  const unsigned char vendor[]="Cisco"; n+=med(p+n,9,vendor,sizeof(vendor)-1);
  const unsigned char model[]="CP-8841"; n+=med(p+n,10,model,sizeof(model)-1);
  const unsigned char fw[]="14.2.1"; n+=med(p+n,6,fw,sizeof(fw)-1);
  put16(p+n,0); n+=2;
  argos_lldp_med_result_t r; expect(argos_lldp_med_parse(p,n,&r),"parse");
  expect(r.device_class==3,"endpoint class III"); expect(r.capabilities==0x0023,"capabilities bitmap");
  expect(r.have_policy && r.app_type==1 && r.policy_tagged && r.vlan==200 && r.priority==5 && r.dscp==46,"voice policy fields");
  expect(strcmp(r.manufacturer,"Cisco")==0 && strcmp(r.model,"CP-8841")==0,"inventory");
  expect(strstr(r.detail,"class=endpoint3")!=NULL,"class detail");
  expect(strstr(r.detail,"policy=voice,defined,tagged,vlan=200,prio=5,dscp=46")!=NULL,"policy detail");
  expect(strstr(r.detail,"SECRET-ROOM-42")==NULL,"location privacy");
  unsigned char bad[8]={0}; put16(bad,(uint16_t)((127U<<9)|6U)); bad[2]=0;bad[3]=0x12;bad[4]=0xbb;bad[5]=2;bad[6]=1;bad[7]=2;
  expect(!argos_lldp_med_parse(bad,sizeof(bad),&r),"truncated MED rejected");
  puts("LLDP-MED fingerprint fixtures: PASS"); return 0;
}
