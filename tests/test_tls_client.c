#include <stdio.h>
#include <string.h>
#include "../src/argos_tls.h"

static size_t build_client_hello(unsigned char *b, size_t cap) {
    if (cap < 128U) return 0U;
    size_t p = 0U;
    b[p++]=0x16; b[p++]=0x03; b[p++]=0x01; b[p++]=0; b[p++]=0;
    b[p++]=0x01; b[p++]=0; b[p++]=0; b[p++]=0;
    b[p++]=0x03; b[p++]=0x03;
    memset(b+p, 0x11, 32U); p += 32U;
    b[p++]=0;
    b[p++]=0; b[p++]=4; b[p++]=0x13; b[p++]=0x01; b[p++]=0x13; b[p++]=0x02;
    b[p++]=1; b[p++]=0;
    size_t ext_len_pos=p; b[p++]=0; b[p++]=0;
    const char *host="example.com";
    b[p++]=0; b[p++]=0; b[p++]=0; b[p++]=16;
    b[p++]=0; b[p++]=14; b[p++]=0; b[p++]=0; b[p++]=11;
    memcpy(b+p, host, 11U); p += 11U;
    b[p++]=0; b[p++]=16; b[p++]=0; b[p++]=5;
    b[p++]=0; b[p++]=3; b[p++]=2; b[p++]='h'; b[p++]='2';
    b[p++]=0; b[p++]=0x2b; b[p++]=0; b[p++]=5;
    b[p++]=4; b[p++]=0x03; b[p++]=0x04; b[p++]=0x03; b[p++]=0x03;
    size_t ext_len = p - (ext_len_pos + 2U);
    b[ext_len_pos]=(unsigned char)(ext_len>>8); b[ext_len_pos+1]=(unsigned char)ext_len;
    size_t hs_len=p-9U;
    b[6]=(unsigned char)(hs_len>>16); b[7]=(unsigned char)(hs_len>>8); b[8]=(unsigned char)hs_len;
    size_t rec_len=p-5U;
    b[3]=(unsigned char)(rec_len>>8); b[4]=(unsigned char)rec_len;
    return p;
}

int main(void) {
    unsigned char b[256]={0};
    size_t n=build_client_hello(b,sizeof(b));
    argos_tls_client_result_t r1,r2;
    if (!n || !argos_tls_client_parse(b,(int)n,&r1)) return 1;
    if (strcmp(r1.sni,"example.com") != 0) return 2;
    if (strcmp(r1.alpn,"h2") != 0) return 3;
    if (strncmp(r1.ja4,"t13d0201h2_",11) != 0) return 4;
    if (strlen(r1.ja4) != 36U) return 5;
    if (!argos_tls_client_parse(b,(int)n,&r2)) return 6;
    if (strcmp(r1.ja4,r2.ja4) != 0) return 7;
    b[5]=0x02;
    if (argos_tls_client_parse(b,(int)n,&r2)) return 8;
    puts("TLS ClientHello engine fixture: PASS");
    return 0;
}
