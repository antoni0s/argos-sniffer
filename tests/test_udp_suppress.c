#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_flow_state.h"
#include "../src/argos_wireguard.h"

int main(void) {
    argos_udp_suppress_entry_t tab[ARGOS_UDP_SUPPRESS_SLOTS];
    memset(tab,0,sizeof(tab));
    uint8_t a[16]={10,0,0,1}, b[16]={10,0,0,2};

    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,100)==0);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,101)==1);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,105)==1);
    /* Suppressed hits do not refresh the epoch: revalidate after 5 seconds. */
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,106)==0);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,107)==1);

    /* Reverse direction and a different message class are independent. */
    assert(argos_udp_suppress_recent(tab,4,b,a,51820,50000,4,107)==0);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,3,107)==0);

    uint8_t a6[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t b6[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
    assert(argos_udp_suppress_recent(tab,6,a6,b6,50001,51820,4,200)==0);
    assert(argos_udp_suppress_recent(tab,6,a6,b6,50001,51820,4,201)==1);

    unsigned char keepalive[32]={4,0,0,0};
    unsigned char data[48]={4,0,0,0};
    unsigned char bad[48]={4,1,0,0};
    assert(argos_wireguard_transport_kind(keepalive,sizeof(keepalive))==1);
    assert(argos_wireguard_transport_kind(data,sizeof(data))==2);
    assert(argos_wireguard_transport_kind(bad,sizeof(bad))==0);
    assert(argos_wireguard_transport_kind(data,47)==0);

    puts("Bounded UDP class suppression fixtures: PASS");
    return 0;
}
