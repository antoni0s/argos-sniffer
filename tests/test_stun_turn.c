#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void put16(unsigned char *p, uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p, uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static size_t attr(unsigned char *p,size_t pos,uint16_t type,const unsigned char *v,size_t n){
    put16(p+pos,type); put16(p+pos+2,(uint16_t)n); if(n) memcpy(p+pos+4,v,n);
    size_t pad=(n+3U)&~3U; if(pad>n) memset(p+pos+4+n,0,pad-n); return pos+4U+pad;
}
static void header(unsigned char *p,uint16_t type,size_t end){
    put16(p,type); put16(p+2,(uint16_t)(end-20U)); put32(p+4,0x2112a442U);
    for(int i=8;i<20;i++) p[i]=(unsigned char)(0xa0+i); /* transaction ID: must stay opaque */
}

int main(void){
    unsigned char p[512]={0}; size_t pos=20; argos_enterprise_result_t r;
    const unsigned char sw[]="libwebrtc/126"; pos=attr(p,pos,0x8022,sw,sizeof(sw)-1);
    unsigned char pr[4]; put32(pr,0x6e0001ffU); pos=attr(p,pos,0x0024,pr,4);
    pos=attr(p,pos,0x0025,NULL,0);
    unsigned char role[8]={1,2,3,4,5,6,7,8}; pos=attr(p,pos,0x802a,role,8);
    unsigned char mi[20]={0}; pos=attr(p,pos,0x0008,mi,20);
    unsigned char fp[4]={0}; pos=attr(p,pos,0x8028,fp,4);
    header(p,0x0001,(size_t)pos);
    assert(ae_stun_turn(p,(int)pos,&r)==1 && r.emit && strcmp(r.proto,"stun")==0);
    assert(strstr(r.detail,"method=Binding class=request"));
    assert(strstr(r.detail,"software=libwebrtc/126"));
    assert(strstr(r.detail,"priority=1845494271") && strstr(r.detail,"use_candidate=1"));
    assert(strstr(r.detail,"ice=controlling") && strstr(r.detail,"integrity=1") && strstr(r.detail,"fingerprint=1"));
    assert(strstr(r.detail,"a8a9aa")==NULL);

    memset(p,0,sizeof(p)); pos=20;
    unsigned char rt[4]={17,0,0,0}; pos=attr(p,pos,0x0019,rt,4);
    unsigned char life[4]; put32(life,600); pos=attr(p,pos,0x000d,life,4);
    unsigned char fam[4]={1,0,0,0}; pos=attr(p,pos,0x0017,fam,4);
    const unsigned char user[]="secret-user"; pos=attr(p,pos,0x0006,user,sizeof(user)-1);
    const unsigned char realm[]="internal.example"; pos=attr(p,pos,0x0014,realm,sizeof(realm)-1);
    const unsigned char nonce[]="private-nonce"; pos=attr(p,pos,0x0015,nonce,sizeof(nonce)-1);
    header(p,0x0003,pos);
    assert(ae_stun_turn(p,(int)pos,&r)==1 && strcmp(r.proto,"turn")==0);
    assert(strstr(r.detail,"method=Allocate class=request"));
    assert(strstr(r.detail,"requested_transport=17") && strstr(r.detail,"lifetime=600") && strstr(r.detail,"address_family=1"));
    assert(strstr(r.detail,"secret-user")==NULL && strstr(r.detail,"internal.example")==NULL && strstr(r.detail,"private-nonce")==NULL);

    /* Relay-data forms are intentionally not fingerprints. */
    memset(p,0,sizeof(p)); header(p,0x0016,20); assert(ae_stun_turn(p,20,&r)==0);
    memset(p,0,sizeof(p)); header(p,0x0017,20); assert(ae_stun_turn(p,20,&r)==0);
    memset(p,0,sizeof(p)); p[0]=0x40; assert(ae_stun_turn(p,20,&r)==0);

    /* Malformed attribute length must fail closed. */
    memset(p,0,sizeof(p)); pos=20; unsigned char x[4]={0}; pos=attr(p,pos,0x0024,x,4); header(p,0x0001,pos);
    p[22]=0xff; p[23]=0xff; assert(ae_stun_turn(p,(int)pos,&r)==0);
    puts("STUN/TURN control fixtures: PASS");
    return 0;
}
