#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

int main(void) {
    argos_enterprise_result_t r;
    unsigned char client[48]={0};
    client[0]=(4U<<3)|3U; /* v4 client */
    assert(ae_ntp(client,sizeof(client),&r)==1 && r.emit);
    assert(strcmp(r.proto,"ntp")==0);
    assert(strstr(r.detail,"version=4") && strstr(r.detail,"mode=client"));
    assert(strstr(r.detail,"stratum=0") && strstr(r.detail,"extra_bytes=0"));

    unsigned char server[68]={0};
    server[0]=(3U<<6)|(4U<<3)|4U; /* alarm, v4 server */
    server[1]=2; server[2]=6; server[3]=(unsigned char)-20;
    memcpy(server+12,"PRIV",4);                 /* Reference ID: must stay opaque */
    memcpy(server+16,"REF-TIME",8);             /* timestamps: must stay opaque */
    assert(ae_ntp(server,sizeof(server),&r)==1);
    assert(strstr(r.detail,"mode=server") && strstr(r.detail,"li=3"));
    assert(strstr(r.detail,"stratum=2") && strstr(r.detail,"poll=6"));
    assert(strstr(r.detail,"precision=-20") && strstr(r.detail,"extra_bytes=20"));
    assert(strstr(r.detail,"PRIV")==NULL && strstr(r.detail,"REF-TIME")==NULL);

    client[0]=(4U<<3)|6U; assert(ae_ntp(client,sizeof(client),&r)==0); /* control mode */
    client[0]=(5U<<3)|3U; assert(ae_ntp(client,sizeof(client),&r)==0); /* unsupported version */
    assert(ae_ntp(server,47,&r)==0);
    puts("NTP fixtures: PASS");
    return 0;
}
