from pathlib import Path

src=Path('src/argos_enterprise.h')
test=Path('tests/test_ntlm_privacy.c')

s=src.read_text()
old=r'''    ae_set(r, "smb2-ntlm", 1,
           "message=%u windows=%u.%u build=%u domain=%s workstation=%s",
           mt, maj, min, build, domain[0] ? domain : "-", workstation[0] ? workstation : "-");
    return 1;
}
'''
new=r'''    unsigned domain_present = domain[0] ? 1U : 0U;
    unsigned workstation_present = workstation[0] ? 1U : 0U;
    unsigned domain_len = domain_present ? (unsigned)strlen(domain) : 0U;
    unsigned workstation_len = workstation_present ? (unsigned)strlen(workstation) : 0U;
    uint32_t domain_hash = 0U, workstation_hash = 0U;
    if (domain_present) {
        domain_hash = 2166136261U;
        for (unsigned i = 0; i < domain_len; ++i) {
            domain_hash ^= (unsigned char)domain[i];
            domain_hash *= 16777619U;
        }
    }
    if (workstation_present) {
        workstation_hash = 2166136261U;
        for (unsigned i = 0; i < workstation_len; ++i) {
            workstation_hash ^= (unsigned char)workstation[i];
            workstation_hash *= 16777619U;
        }
    }
    ae_set(r, "smb2-ntlm", 1,
           "message=%u windows=%u.%u build=%u domain_present=%u domain_len=%u domain_hash=%08x workstation_present=%u workstation_len=%u workstation_hash=%08x",
           mt, maj, min, build,
           domain_present, domain_len, domain_hash,
           workstation_present, workstation_len, workstation_hash);
    return 1;
}
'''
if s.count(old)!=1:
    raise SystemExit(f'NTLM privacy source anchor count={s.count(old)}')
src.write_text(s.replace(old,new,1))

test.write_text(r'''#include <stdio.h>
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
''')
print('staged SMB NTLM privacy hardening')
