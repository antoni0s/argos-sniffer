#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

int main(void) {
    static const unsigned char asreq[] = {
        0x6a,0x1d, 0x30,0x1b,
        0xa1,0x03,0x02,0x01,0x05,
        0xa2,0x03,0x02,0x01,0x0a,
        0xa4,0x0f,0x30,0x0d,0xa8,0x0b,0x30,0x09,
        0x02,0x01,0x12, 0x02,0x01,0x11, 0x02,0x01,0x17
    };
    argos_enterprise_result_t r;
    assert(ae_kerberos(asreq, (int)sizeof(asreq), &r) == 1 && r.emit);
    assert(strstr(r.detail, "request=AS-REQ"));
    assert(strstr(r.detail, "etype_count=3"));
    assert(strstr(r.detail, "etypes=18,17,23"));

    unsigned char tcp[4 + sizeof(asreq)];
    unsigned n=(unsigned)sizeof(asreq);
    tcp[0]=(unsigned char)(n>>24); tcp[1]=(unsigned char)(n>>16); tcp[2]=(unsigned char)(n>>8); tcp[3]=(unsigned char)n;
    memcpy(tcp+4,asreq,sizeof(asreq)); tcp[4]=0x6c; tcp[4+13]=0x0c;
    assert(ae_kerberos(tcp, (int)sizeof(tcp), &r) == 1);
    assert(strstr(r.detail, "request=TGS-REQ") && strstr(r.detail, "etypes=18,17,23"));

    unsigned char bad[sizeof(asreq)]; memcpy(bad,asreq,sizeof(bad));
    bad[18]=0xa7; /* no [8] etype: request still recognized, no false e-types */
    assert(ae_kerberos(bad,(int)sizeof(bad),&r)==1);
    assert(strstr(r.detail,"etype_count=0") && strstr(r.detail,"etypes=-"));

    char out[32]; unsigned count=0;
    assert(ae_kerberos_etypes(asreq,sizeof(asreq),0,out,sizeof(out),&count)==1);
    assert(count==3 && strcmp(out,"18,17,23")==0);
    puts("Kerberos etype fixtures: PASS");
    return 0;
}
