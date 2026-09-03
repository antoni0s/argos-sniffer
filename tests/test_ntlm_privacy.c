#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void check(int ok,const char *msg){ if(!ok){fprintf(stderr,"FAIL: %s\n",msg);exit(1);} }
static void put16(unsigned char *p,unsigned v){p[0]=(unsigned char)(v&255U);p[1]=(unsigned char)((v>>8)&255U);}
static void put32(unsigned char *p,unsigned v){p[0]=(unsigned char)(v&255U);p[1]=(unsigned char)((v>>8)&255U);p[2]=(unsigned char)((v>>16)&255U);p[3]=(unsigned char)((v>>24)&255U);}
static size_t put_utf16(unsigned char *p,const char *s){size_t n=0;while(*s){p[n++]=(unsigned char)*s++;p[n++]=0;}return n;}

int main(void){
    unsigned char p[256]={0};
    argos_enterprise_result_t r;
    p[0]=0xfe;p[1]='S';p[2]='M';p[3]='B';put16(p+12,1U);
    unsigned char *n=p+64;
    memcpy(n,"NTLMSSP\0",8);put32(n+8,3U);
    const char *domain="SECRET-CORP";
    const char *workstation="ALICE-PC";
    size_t dl=put_utf16(n+80,domain), wl=put_utf16(n+112,workstation);
    put16(n+28,(unsigned)dl);put16(n+30,(unsigned)dl);put32(n+32,80U);
    put16(n+44,(unsigned)wl);put16(n+46,(unsigned)wl);put32(n+48,112U);
    n[64]=10;n[65]=0;put16(n+66,19045U);
    int len=(int)(64U+112U+wl);

    check(argos_enterprise_parse_tcp(51000,445,p,len,&r)==1,"SMB2 NTLM type3 parsed");
    check(r.emit&&r.complete&&strcmp(r.proto,"smb2-ntlm")==0,"NTLM fingerprint emitted");
    check(strstr(r.detail,"domain_present=1")!=NULL,"domain presence retained");
    check(strstr(r.detail,"workstation_present=1")!=NULL,"workstation presence retained");
    check(strstr(r.detail,"domain_hash=")!=NULL&&strstr(r.detail,"workstation_hash=")!=NULL,"identity hashes retained");
    check(strstr(r.detail,domain)==NULL,"raw NTLM domain not emitted");
    check(strstr(r.detail,workstation)==NULL,"raw NTLM workstation not emitted");
    check(strstr(r.detail," domain=")==NULL&&strstr(r.detail," workstation=")==NULL,"legacy raw fields removed");
    puts("NTLM privacy fixtures: PASS");
    return 0;
}
