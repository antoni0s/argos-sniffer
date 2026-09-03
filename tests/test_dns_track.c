#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_dns_track.h"

static void v4(uint8_t out[16], unsigned a, unsigned b, unsigned c, unsigned d) {
    memset(out,0,16); out[0]=(uint8_t)a; out[1]=(uint8_t)b; out[2]=(uint8_t)c; out[3]=(uint8_t)d;
}

int main(void) {
    argos_dns_track_t t[32]; memset(t,0,sizeof(t));
    uint8_t c1[16],c2[16],s1[16],s2[16],m1[6]={0,1,2,3,4,5},m2[6]={6,7,8,9,10,11};
    v4(c1,10,0,0,10); v4(c2,10,0,0,11); v4(s1,1,1,1,1); v4(s2,8,8,8,8);
    const uint64_t now=10000000ULL;

    assert(argos_dns_track_put(t,32,4,c1,s1,53000,53,0x1234,1,"example.com",now,m1,0));
    argos_dns_track_t *e=argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,1,"example.com",now+1000);
    assert(e && strcmp(e->domain,"example.com")==0 && memcmp(e->mac,m1,6)==0);

    /* Same TXID must not cross client, server, client port, qtype or qname. */
    assert(!argos_dns_track_find_response(t,32,4,c2,s1,53000,53,0x1234,1,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s2,53000,53,0x1234,1,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53001,53,0x1234,1,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,28,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,1,"other.example",now+1000));

    /* Two simultaneous same-TXID requests coexist instead of overwriting one slot. */
    assert(argos_dns_track_put(t,32,4,c2,s1,53000,53,0x1234,1,"example.com",now+10,m2,1));
    assert(argos_dns_track_put(t,32,4,c1,s2,53000,53,0x1234,1,"example.net",now+20,m1,0));
    assert(argos_dns_track_find_response(t,32,4,c2,s1,53000,53,0x1234,1,"example.com",now+1000));
    assert(argos_dns_track_find_response(t,32,4,c1,s2,53000,53,0x1234,1,"example.net",now+1000));

    /* Stale and clock-regressed replies cannot match. */
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,1,"example.com",now+ARGOS_DNS_TRACK_TTL_USEC));
    assert(argos_dns_track_put(t,32,4,c1,s1,53002,53,0x2222,1,"clock.test",now,m1,0));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53002,53,0x2222,1,"clock.test",now-1));

    /* Full IPv6 addresses, not a 32-bit address hint, establish identity. */
    uint8_t v61[16]={0x20,0x01,0x0d,0xb8}, v62[16]={0x20,0x01,0x0d,0xb8}, v6s[16]={0x26,0x06,0x47,0x00};
    v61[15]=1; v62[15]=2; v6s[15]=53;
    assert(argos_dns_track_put(t,32,6,v61,v6s,54000,53,0xabcd,28,"ipv6.example",now,m1,0));
    assert(argos_dns_track_find_response(t,32,6,v61,v6s,54000,53,0xabcd,28,"ipv6.example",now+500));
    assert(!argos_dns_track_find_response(t,32,6,v62,v6s,54000,53,0xabcd,28,"ipv6.example",now+500));

    /* Collision handling: find two distinct tuples sharing the same base slot. */
    argos_dns_track_t small[8]; memset(small,0,sizeof(small));
    char n1[32],n2[32]; uint64_t first_key=0; int found=0;
    snprintf(n1,sizeof(n1),"collision-%d.test",0);
    first_key=argos_dns_track_key(4,c1,s1,55000,53,0x4444,1,argos_dns_name_hash(n1));
    for(int i=1;i<10000;i++) {
        snprintf(n2,sizeof(n2),"collision-%d.test",i);
        uint64_t k=argos_dns_track_key(4,c1,s1,55000,53,0x4444,1,argos_dns_name_hash(n2));
        if ((k & 7U)==(first_key & 7U) && k!=first_key) { found=1; break; }
    }
    assert(found);
    assert(argos_dns_track_put(small,8,4,c1,s1,55000,53,0x4444,1,n1,now,m1,0));
    assert(argos_dns_track_put(small,8,4,c1,s1,55000,53,0x4444,1,n2,now+1,m1,0));
    assert(argos_dns_track_find_response(small,8,4,c1,s1,55000,53,0x4444,1,n1,now+100));
    assert(argos_dns_track_find_response(small,8,4,c1,s1,55000,53,0x4444,1,n2,now+100));

    puts("DNSEXT correlation fixtures: PASS");
    return 0;
}
