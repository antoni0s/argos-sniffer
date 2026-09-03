#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static size_t tlv(unsigned char *o,size_t p,unsigned t,const unsigned char *v,size_t n){assert(n<128);o[p++]=(unsigned char)t;o[p++]=(unsigned char)n;memcpy(o+p,v,n);return p+n;}
static size_t integer(unsigned char *o,size_t p,unsigned v){unsigned char b[4];size_t n=1;if(v>0xffffff)n=4;else if(v>0xffff)n=3;else if(v>0xff)n=2;for(size_t i=0;i<n;i++)b[n-1-i]=(unsigned char)(v>>(8*i));if(b[0]&0x80){unsigned char z[5]={0};memcpy(z+1,b,n);return tlv(o,p,0x02,z,n+1);}return tlv(o,p,0x02,b,n);}

int main(void){
    unsigned char usm_body[128]={0};size_t u=0;
    unsigned char engine[]={0x80,0x00,0x02,0xb8,0x03,0x00,0x11,0x22,0x33,0x44,0x55};
    u=tlv(usm_body,u,0x04,engine,sizeof(engine));u=integer(usm_body,u,7);u=integer(usm_body,u,321);
    u=tlv(usm_body,u,0x04,(const unsigned char*)"private-user",12);
    unsigned char auth[12]={1,2,3};u=tlv(usm_body,u,0x04,auth,sizeof(auth));
    unsigned char priv[8]={4,5,6};u=tlv(usm_body,u,0x04,priv,sizeof(priv));
    unsigned char usm_seq[160];size_t us=tlv(usm_seq,0,0x30,usm_body,u);

    unsigned char hdr_body[64]={0};size_t h=0;h=integer(hdr_body,h,123);h=integer(hdr_body,h,65535);
    unsigned char flags=0x07;h=tlv(hdr_body,h,0x04,&flags,1);h=integer(hdr_body,h,3);
    unsigned char hdr[80];size_t hs=tlv(hdr,0,0x30,hdr_body,h);

    unsigned char body[320]={0};size_t b=0;b=integer(body,b,3);memcpy(body+b,hdr,hs);b+=hs;b=tlv(body,b,0x04,usm_seq,us);
    unsigned char msg[360];size_t m=tlv(msg,0,0x30,body,b);

    argos_enterprise_result_t r;
    assert(ae_snmp(msg,(int)m,&r)==1 && r.emit);
    assert(strcmp(r.proto,"snmpv3-usm")==0);
    assert(strstr(r.detail,"engine_len=11") && strstr(r.detail,"enterprise=696") && strstr(r.detail,"format=3"));
    assert(strstr(r.detail,"boots=7") && strstr(r.detail,"time=321"));
    assert(strstr(r.detail,"auth=1") && strstr(r.detail,"priv=1") && strstr(r.detail,"reportable=1"));
    assert(strstr(r.detail,"user_present=1"));
    assert(strstr(r.detail,"private-user")==NULL);
    assert(strstr(r.detail,"800002b8")==NULL);

    /* standalone USM parser must reject an empty EngineID discovery request */
    unsigned char empty_usm[64]={0};size_t e=0;e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);e=integer(empty_usm,e,0);e=integer(empty_usm,e,0);e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);
    unsigned char empty_seq[80];size_t es=tlv(empty_seq,0,0x30,empty_usm,e);
    unsigned char body2[160]={0};size_t b2=0;b2=integer(body2,b2,3);memcpy(body2+b2,hdr,hs);b2+=hs;b2=tlv(body2,b2,0x04,empty_seq,es);unsigned char msg2[200];size_t m2=tlv(msg2,0,0x30,body2,b2);
    assert(ae_snmp_v3_usm(msg2,m2,&r)==0);
    puts("SNMPv3 EngineID fixtures: PASS");
    return 0;
}
