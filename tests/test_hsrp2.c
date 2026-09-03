#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_hsrp.h"

static void put32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16);
    p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v;
}

int main(void) {
    unsigned char p[46] = {0};
    p[0]=1; p[1]=40;              /* Group State TLV */
    p[2]=2; p[3]=0; p[4]=16; p[5]=4; /* v2, hello, active, IPv4 */
    p[6]=0x0f; p[7]=0xff;         /* group 4095 */
    p[8]=0x00; p[9]=0x11; p[10]=0x22; p[11]=0x33; p[12]=0x44; p[13]=0x55;
    put32(p+14, 150); put32(p+18, 3000); put32(p+22, 10000);
    p[26]=192; p[27]=0; p[28]=2; p[29]=254; /* virtual IP: must never be emitted */
    p[42]=4; p[43]=2; p[44]=0xde; p[45]=0xad; /* opaque/auth-like extra TLV */

    argos_hsrp2_result_t r;
    assert(argos_hsrp2_parse(p, sizeof(p), &r) == 1);
    assert(r.wire_version == 2 && r.opcode == 0 && r.state == 16 && r.ip_version == 4);
    assert(r.group == 4095 && r.priority == 150 && r.hello_ms == 3000 && r.hold_ms == 10000);
    assert(r.extra_tlvs == 1);
    assert(strstr(r.detail, "version=2") && strstr(r.detail, "state=active"));
    assert(strstr(r.detail, "group=4095") && strstr(r.detail, "hello_ms=3000"));
    assert(strstr(r.detail, "001122334455"));
    assert(strstr(r.detail, "192.0.2.254") == NULL);
    assert(strstr(r.detail, "dead") == NULL);

    p[2]=1; assert(argos_hsrp2_parse(p, sizeof(p), &r) == 0); p[2]=2;
    p[5]=5; assert(argos_hsrp2_parse(p, sizeof(p), &r) == 0); p[5]=4;
    p[6]=0x10; p[7]=0x00; assert(argos_hsrp2_parse(p, sizeof(p), &r) == 0);
    assert(argos_hsrp2_parse(p, 41, &r) == 0);
    puts("HSRPv2 fixtures: PASS");
    return 0;
}
