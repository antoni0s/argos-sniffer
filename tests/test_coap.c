#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

int main(void){
    argos_enterprise_result_t r;
    /* CON GET, TKL=2, token opaque, Uri-Path "sensors"/"temp", Content-Format=50, payload. */
    unsigned char p[]={0x42,0x01,0x12,0x34,0xaa,0xbb,
                       0xb7,'s','e','n','s','o','r','s',
                       0x04,'t','e','m','p',
                       0x11,50,
                       0xff,'S','E','C','R','E','T'};
    assert(ae_coap(p,(int)sizeof(p),&r)==1 && r.emit);
    assert(strcmp(r.proto,"coap")==0);
    assert(strstr(r.detail,"type=CON") && strstr(r.detail,"code=0.01") && strstr(r.detail,"method=GET"));
    assert(strstr(r.detail,"token_len=2") && strstr(r.detail,"uri_path_segments=2"));
    assert(strstr(r.detail,"content_format=50") && strstr(r.detail,"payload=1"));
    assert(strstr(r.detail,"sensors")==NULL && strstr(r.detail,"temp")==NULL && strstr(r.detail,"SECRET")==NULL);

    unsigned char q[]={0x50,0x45,0x00,0x01}; /* NON 2.05 response */
    assert(ae_coap(q,(int)sizeof(q),&r)==1 && strstr(r.detail,"type=NON") && strstr(r.detail,"code=2.05"));
    assert(strstr(r.detail,"content_format=-") && strstr(r.detail,"accept=-"));

    p[0]=0x02; assert(ae_coap(p,(int)sizeof(p),&r)==0); /* wrong version */
    p[0]=0x49; assert(ae_coap(p,(int)sizeof(p),&r)==0); /* reserved TKL */
    puts("CoAP fixtures: PASS"); return 0;
}
