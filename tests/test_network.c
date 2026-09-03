#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_network.h"

static struct in6_addr ip6(const char *text) {
    struct in6_addr out;
    assert(inet_pton(AF_INET6, text, &out) == 1);
    return out;
}

int main(void) {
    argos_network_state_t state;
    argos_network_init(&state);
    assert(state.owner4 == NULL && state.owner6 == NULL);

    const uint8_t mac_a[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
    const uint8_t mac_b[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const uint8_t multicast[6] = {0x01,0,0,0,0,1};
    uint32_t host4;
    assert(inet_pton(AF_INET, "10.0.0.1", &host4) == 1);
    assert(argos_network_owner4_mismatch(&state, host4, mac_a) == 0);
    assert(state.owner4 == NULL);
    argos_network_owner4_note(&state, host4, mac_a);
    assert(state.owner4 != NULL);
    assert(argos_network_owner4_mismatch(&state, host4, mac_a) == 0);
    assert(argos_network_owner4_mismatch(&state, host4, mac_b) == 1);
    argos_network_owner4_note(&state, host4, multicast);
    assert(argos_network_owner4_mismatch(&state, host4, mac_b) == 1);

    struct in6_addr host6 = ip6("2001:db8:1::10");
    assert(argos_network_owner6_mismatch(&state, &host6, mac_a) == 0);
    assert(state.owner6 == NULL);
    argos_network_owner6_note(&state, &host6, mac_a);
    assert(argos_network_owner6_mismatch(&state, &host6, mac_b) == 1);

    assert(argos_network_add_inside(&state, "192.0.2.0/24"));
    assert(argos_network_add_inside(&state, "2001:db8:99::/48"));
    assert(!argos_network_add_inside(&state, "192.0.2.0/33"));
    assert(!argos_network_add_inside(&state, "2001:db8::/129"));
    assert(!argos_network_add_inside(&state, "10.0.0.0/+8"));
    uint32_t configured4, public4;
    assert(inet_pton(AF_INET, "192.0.2.42", &configured4) == 1);
    assert(inet_pton(AF_INET, "8.8.8.8", &public4) == 1);
    assert(argos_network_is_lan4(&state, configured4));
    assert(!argos_network_is_lan4(&state, public4));
    struct in6_addr configured6 = ip6("2001:db8:99::abcd");
    assert(argos_network_is_lan6(&state, &configured6));

    argos_network_prefix_t *p4 = &state.learned[state.learned_count++];
    memset(p4, 0, sizeof(*p4)); p4->family = AF_INET; p4->ifindex = 7;
    assert(inet_pton(AF_INET, "10.0.0.0", &p4->v4) == 1);
    assert(inet_pton(AF_INET, "255.255.255.0", &p4->v4mask) == 1);
    uint32_t direct4, routed4;
    assert(inet_pton(AF_INET, "10.0.0.9", &direct4) == 1);
    assert(inet_pton(AF_INET, "10.1.0.9", &routed4) == 1);
    assert(!argos_network_routed4(&state, direct4, 7));
    assert(argos_network_routed4(&state, routed4, 7));
    assert(!argos_network_routed4(&state, routed4, 8));

    argos_network_prefix_t *p6 = &state.learned[state.learned_count++];
    memset(p6, 0, sizeof(*p6)); p6->family = AF_INET6; p6->ifindex = 7;
    p6->v6 = ip6("2001:db8:1234:1::");
    memset(p6->v6mask.s6_addr, 0xff, 8);
    struct in6_addr direct6 = ip6("2001:db8:1234:1::2");
    struct in6_addr routed6 = ip6("2001:db8:1234:2::2");
    struct in6_addr unrelated6 = ip6("2001:db8:9999::2");
    assert(!argos_network_routed6(&state, &direct6, 7));
    assert(argos_network_routed6(&state, &routed6, 7));
    assert(!argos_network_routed6(&state, &unrelated6, 7));
    assert(argos_network_prefix_context(4, 9) == 4);
    assert(argos_network_prefix_context(0, 9) == 9);

    argos_network_destroy(&state);
    assert(state.owner4 == NULL && state.owner6 == NULL);
    puts("network context engine fixtures: PASS");
    return 0;
}
