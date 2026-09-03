#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static size_t putstr(unsigned char *p,size_t pos,const char *s){size_t n=strlen(s);p[pos++]=(unsigned char)(n>>8);p[pos++]=(unsigned char)n;memcpy(p+pos,s,n);return pos+n;}

int main(void){
    unsigned char p[256]={0}; size_t pos=2;
    pos=putstr(p,pos,"MQTT"); p[pos++]=4; p[pos++]=0xc2; p[pos++]=0; p[pos++]=60;
    pos=putstr(p,pos,"device-secret-123");
    /* username/password bytes are private and parser should not inspect them */
    pos=putstr(p,pos,"alice@example.org"); pos=putstr(p,pos,"super-secret");
    p[0]=0x10; p[1]=(unsigned char)(pos-2);
    argos_enterprise_result_t r;
    assert(ae_mqtt(p,(int)pos,&r)==1 && r.emit && r.complete);
    assert(strcmp(r.proto,"mqtt")==0);
    assert(strstr(r.detail,"version=3.1.1") && strstr(r.detail,"clean=1") && strstr(r.detail,"keepalive=60"));
    assert(strstr(r.detail,"username_present=1") && strstr(r.detail,"password_present=1"));
    assert(strstr(r.detail,"client_id_len=17") && strstr(r.detail,"client_id_hash="));
    assert(strstr(r.detail,"device-secret")==NULL && strstr(r.detail,"alice")==NULL && strstr(r.detail,"super-secret")==NULL);

    memset(p,0,sizeof(p)); pos=2; pos=putstr(p,pos,"MQTT"); p[pos++]=5; p[pos++]=0x02; p[pos++]=0; p[pos++]=30;
    p[pos++]=0; /* v5 property length */ pos=putstr(p,pos,"sensor-01"); p[0]=0x10; p[1]=(unsigned char)(pos-2);
    assert(ae_mqtt(p,(int)pos,&r)==1 && strstr(r.detail,"version=5.0") && strstr(r.detail,"properties_len=0"));
    assert(strstr(r.detail,"sensor-01")==NULL);

    p[0]=0x30; assert(ae_mqtt(p,(int)pos,&r)==0); /* PUBLISH ignored */
    p[0]=0x10; p[1]=0xff; assert(ae_mqtt(p,(int)pos,&r)==0); /* truncated varint/remaining length */
    puts("MQTT CONNECT fixtures: PASS");
    return 0;
}
