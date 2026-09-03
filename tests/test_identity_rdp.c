#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_identity.h"

static void check(int ok, const char *msg) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); }
}

static size_t make_rdp(unsigned char *p, size_t cap, const char *cookie, unsigned x224) {
    const char pre[] = "Cookie: mstshash=";
    size_t n = strlen(cookie);
    size_t need = 11U + sizeof(pre)-1U + n + 2U;
    if (cap < need) return 0U;
    memset(p,0,cap); p[0]=0x03; p[1]=0x00; p[5]=(unsigned char)x224;
    memcpy(p+11,pre,sizeof(pre)-1U);
    memcpy(p+11+sizeof(pre)-1U,cookie,n);
    memcpy(p+11+sizeof(pre)-1U+n,"\r\n",2U);
    return need;
}

int main(void) {
    unsigned char p[320];
    const char *secret="alice.enterprise";
    size_t n=make_rdp(p,sizeof(p),secret,0xe0U);
    argos_identity_result_t hashed, raw;
    check(n>0,"fixture built");
    check(argos_identity_rdp_mstshash(p,n,0,&hashed),"RDP mstshash hash evidence");
    check(strcmp(hashed.protocol,"rdp")==0 && strcmp(hashed.type,"mstshash")==0,"RDP identity labels");
    check(strstr(hashed.value,"hash=")==hashed.value && strstr(hashed.value,secret)==NULL,"hash mode hides raw identity");
    check(argos_identity_rdp_mstshash(p,n,1,&raw),"RDP mstshash raw evidence");
    check(strcmp(raw.value,secret)==0,"raw opt-in returns bounded value");
    check(raw.hash==hashed.hash && raw.value_len==hashed.value_len,"same identity correlation across modes");

    n=make_rdp(p,sizeof(p),"alice|corp\\admin",0xe0U);
    check(argos_identity_rdp_mstshash(p,n,1,&raw),"sanitized raw evidence");
    check(strcmp(raw.value,"alice/corp/admin")==0,"raw telemetry delimiters sanitized");

    n=make_rdp(p,sizeof(p),secret,0xd0U);
    check(!argos_identity_rdp_mstshash(p,n,0,&hashed),"server X224 confirm is not identity evidence");
    n=make_rdp(p,sizeof(p),secret,0xe0U);
    p[0]=0x04;
    check(!argos_identity_rdp_mstshash(p,n,0,&hashed),"non-TPKT rejected");

    memset(p,0,sizeof(p)); p[0]=0x03; p[1]=0x00; p[5]=0xe0;
    check(!argos_identity_rdp_mstshash(p,32,0,&hashed),"no cookie means no identity");

    char long_cookie[200]; memset(long_cookie,'x',sizeof(long_cookie)-1U); long_cookie[sizeof(long_cookie)-1U]='\0';
    n=make_rdp(p,sizeof(p),long_cookie,0xe0U);
    check(argos_identity_rdp_mstshash(p,n,0,&hashed),"long cookie accepted boundedly");
    check(hashed.value_len==120U,"RDP identity bounded to 120 bytes");

    puts("RDP identity fixtures: PASS");
    return 0;
}
