#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void le16(unsigned char *p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);}
static void le32(unsigned char *p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);}
static size_t dns(unsigned char *p,size_t pos,const char *s){
    const char *q=s;
    while(*q){const char *dot=strchr(q,'.');size_t l=dot?(size_t)(dot-q):strlen(q);assert(l<=63);p[pos++]=(unsigned char)l;memcpy(p+pos,q,l);pos+=l;if(!dot)break;q=dot+1;}
    p[pos++]=0;return pos;
}
static size_t putlen(unsigned char *p,size_t pos,size_t n){if(n<128){p[pos++]=(unsigned char)n;}else{assert(n<256);p[pos++]=0x81;p[pos++]=(unsigned char)n;}return pos;}
static size_t tlv(unsigned char *out,size_t pos,unsigned tag,const unsigned char *v,size_t n){out[pos++]=(unsigned char)tag;pos=putlen(out,pos,n);memcpy(out+pos,v,n);return pos+n;}

int main(void){
    unsigned char nl[512]={0}; size_t np=24;
    le16(nl,23); le16(nl+2,0); le32(nl+4,0x000003fdU);
    np=dns(nl,np,"forest.example"); np=dns(nl,np,"corp.example"); np=dns(nl,np,"dc01.corp.example");
    np=dns(nl,np,"CORP"); np=dns(nl,np,"DC01"); np=dns(nl,np,"alice");
    np=dns(nl,np,"Site-A"); np=dns(nl,np,"Branch-1");
    le32(nl+np,0x00000005U); np+=4; le16(nl+np,0xffff);np+=2;le16(nl+np,0xffff);np+=2;

    argos_enterprise_result_t r;
    assert(ae_cldap_netlogon_ex(nl,np,&r)==1 && r.emit);
    assert(strstr(r.detail,"response_ex opcode=23"));
    assert(strstr(r.detail,"flags=0x000003fd") && strstr(r.detail,"ntver=0x00000005"));
    assert(strstr(r.detail,"site_relation=different"));
    assert(strstr(r.detail,"Site-A")==NULL && strstr(r.detail,"Branch-1")==NULL);
    assert(strstr(r.detail,"alice")==NULL && strstr(r.detail,"dc01")==NULL && strstr(r.detail,"corp.example")==NULL);

    unsigned char valset[640], pa[700], attrs[740], entry[800], outer[900]; size_t n;
    n=0; n=tlv(valset,n,0x04,nl,np);
    size_t ppos=0; ppos=tlv(pa,ppos,0x04,(const unsigned char*)"netlogon",8); ppos=tlv(pa,ppos,0x31,valset,n);
    size_t alen=0; alen=tlv(attrs,alen,0x30,pa,ppos);
    size_t elen=0; elen=tlv(entry,elen,0x04,(const unsigned char*)"",0); elen=tlv(entry,elen,0x30,attrs,alen);
    unsigned char body[850]; size_t blen=0; unsigned char mid[3]={0x02,0x01,0x01}; memcpy(body+blen,mid,3);blen+=3; blen=tlv(body,blen,0x64,entry,elen);
    size_t olen=0; olen=tlv(outer,olen,0x30,body,blen);
    assert(ae_cldap(outer,(int)olen,&r)==1);
    assert(strstr(r.detail,"response_ex opcode=23") && strstr(r.detail,"dc_site_hash="));

    nl[np-1]=0; nl[np-2]=0; assert(ae_cldap_netlogon_ex(nl,np,&r)==0);
    puts("CLDAP Netlogon fixtures: PASS");
    return 0;
}
