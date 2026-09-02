#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_tls_server.h"

static void put16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void put24(unsigned char *p, uint32_t v) { p[0]=(unsigned char)(v>>16); p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)v; }
static void expect(int ok, const char *s) { if (!ok) { fprintf(stderr,"FAIL: %s\n",s); exit(1); } }

static size_t make13(unsigned char *p) {
    memset(p,0,128); size_t q=9; put16(p+q,0x0303); q+=2; q+=32; p[q++]=0; put16(p+q,0x1301); q+=2; p[q++]=0;
    size_t el=q; q+=2; put16(p+q,0x002b); put16(p+q+2,2); put16(p+q+4,0x0304); q+=6;
    put16(p+q,0x0033); put16(p+q+2,2); put16(p+q+4,0x001d); q+=6; put16(p+el,(uint16_t)(q-el-2));
    p[0]=0x16; put16(p+1,0x0303); put16(p+3,(uint16_t)(q-5)); p[5]=0x02; put24(p+6,(uint32_t)(q-9)); return q;
}
static size_t make12(unsigned char *p) {
    memset(p,0,128); size_t q=9; put16(p+q,0x0303); q+=2; q+=32; p[q++]=0; put16(p+q,0xc02f); q+=2; p[q++]=0;
    size_t el=q; q+=2; put16(p+q,0x0010); put16(p+q+2,5); put16(p+q+4,3); p[q+6]=2; p[q+7]='h'; p[q+8]='2'; q+=9; put16(p+el,(uint16_t)(q-el-2));
    p[0]=0x16; put16(p+1,0x0303); put16(p+3,(uint16_t)(q-5)); p[5]=0x02; put24(p+6,(uint32_t)(q-9)); return q;
}
int main(void) {
    unsigned char p[128]; argos_tls_server_result_t r; size_t n=make13(p);
    expect(argos_tls_server_parse(p,n,&r),"TLS1.3 parse"); expect(strcmp(r.version,"13")==0,"TLS1.3 version");
    expect(r.cipher==0x1301,"TLS1.3 cipher"); expect(r.extension_count==2,"TLS1.3 extension count");
    expect(strcmp(r.alpn,"none")==0,"TLS1.3 ALPN remains hidden");
    expect(strcmp(r.fingerprint,"ats1_13_1301_02_none_09e178a1014a5fc3")==0,"TLS1.3 golden fingerprint");
    n=make12(p); expect(argos_tls_server_parse(p,n,&r),"TLS1.2 parse"); expect(strcmp(r.version,"12")==0,"TLS1.2 version");
    expect(r.cipher==0xc02f,"TLS1.2 cipher"); expect(strcmp(r.alpn,"h2")==0,"TLS1.2 ALPN");
    expect(strcmp(r.fingerprint,"ats1_12_c02f_01_h2_9a690300c5489dcb")==0,"TLS1.2 golden fingerprint");
    p[5]=0x01; expect(!argos_tls_server_parse(p,n,&r),"ClientHello rejected");
    puts("Argos TLS ServerHello fingerprints: PASS"); return 0;
}
