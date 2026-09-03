#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_wireguard.h"

static void wg_header(unsigned char *p, size_t len, unsigned type) {
    memset(p, 0, len); p[0]=(unsigned char)type;
}

int main(void) {
    argos_wireguard_result_t r;
    unsigned char p[160];

    wg_header(p,148,1); memset(p+8,0xa5,32); assert(argos_wireguard_parse(p,148,&r));
    assert(r.emit && strcmp(r.detail,"type=handshake-initiation")==0);
    assert(strstr(r.detail,"a5")==NULL);

    wg_header(p,92,2); assert(argos_wireguard_parse(p,92,&r));
    assert(strcmp(r.detail,"type=handshake-response")==0);
    wg_header(p,64,3); assert(argos_wireguard_parse(p,64,&r));
    assert(strcmp(r.detail,"type=cookie-reply")==0);
    wg_header(p,32,4); assert(argos_wireguard_parse(p,32,&r));
    assert(strcmp(r.detail,"type=transport-keepalive")==0);
    wg_header(p,48,4); assert(argos_wireguard_parse(p,48,&r));
    assert(strcmp(r.detail,"type=transport-data")==0);

    wg_header(p,148,1); p[2]=1; assert(!argos_wireguard_parse(p,148,&r));
    wg_header(p,147,1); assert(!argos_wireguard_parse(p,147,&r));
    wg_header(p,93,2); assert(!argos_wireguard_parse(p,93,&r));
    wg_header(p,63,3); assert(!argos_wireguard_parse(p,63,&r));
    wg_header(p,40,4); assert(!argos_wireguard_parse(p,40,&r));
    wg_header(p,32,9); assert(!argos_wireguard_parse(p,32,&r));
    puts("WireGuard fixtures: PASS");
    return 0;
}
