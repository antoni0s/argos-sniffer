#include <arpa/inet.h>
#include <assert.h>
#include "network_context_legacy.h"

int main(void) {
    const char *v4[] = {"0.0.0.0", "10.0.0.1", "10.1.0.1", "172.16.0.1", "172.32.0.1",
        "192.168.1.1", "100.64.0.1", "100.128.0.1", "169.254.1.1", "127.0.0.1", "8.8.8.8",
        "192.0.2.1", "224.0.0.1", "255.255.255.255"};
    const char *v6[] = {"::", "::1", "fe80::1", "fc00::1", "fd00::1", "ff02::1", "2001:db8:1:1::1",
        "2001:db8:1:2::1", "2001:db8:99::1", "2001:db8:2::1", "4000::1", "::ffff:10.0.0.1"};
    argos_network_state_t s;
    argos_network_init(&s);
    assert(argos_network_add_inside(&s, "192.0.2.0/24"));
    assert(argos_network_add_inside(&s, "2001:db8:99::/48"));
    for (int i = 0; i < ARGOS_NETWORK_MAX_PREFIXES; ++i) {
        argos_network_prefix_t *p = &s.learned[i];
        p->family = i & 1 ? AF_INET : AF_INET6;
        p->ifindex = i % 3 + 1;
        p->v4 = htonl(0x0a000000U + ((uint32_t)i << 16)); p->v4mask = htonl(0xffffff00U);
        assert(inet_pton(AF_INET6, "2001:db8:1:1::", &p->v6) == 1);
        memset(p->v6mask.s6_addr, 0xff, 8);
    }
    /* Last-entry direct match must win over earlier same-/48 evidence. */
    s.learned[63] = s.learned[0];
    assert(inet_pton(AF_INET6, "2001:db8:1:2::", &s.learned[63].v6) == 1);
    for (int count = 0; count <= ARGOS_NETWORK_MAX_PREFIXES; ++count) {
        s.learned_count = count;
        argos_network_state_t before = s;
        for (int iface = -1; iface <= 4; ++iface) {
            for (size_t a = 0; a < sizeof(v4)/sizeof(*v4); ++a)
            for (size_t b = 0; b < sizeof(v4)/sizeof(*v4); ++b) {
                uint32_t src, dst;
                assert(inet_pton(AF_INET, v4[a], &src) == 1);
                assert(inet_pton(AF_INET, v4[b], &dst) == 1);
                int sl = argos_network_is_lan4(&s, src), dl = argos_network_is_lan4(&s, dst);
                int routed = legacy_routed4(&s, src, iface);
                argos_network_packet_context_t ctx = {99,99};
                assert(argos_network_routed4(&s, src, iface) == routed);
                assert(argos_network_context4(&s, src, dst, iface, &ctx) == (sl || dl || routed));
                assert(ctx.source_side == (sl || routed) && ctx.routed == routed);
            }
            for (size_t a = 0; a < sizeof(v6)/sizeof(*v6); ++a)
            for (size_t b = 0; b < sizeof(v6)/sizeof(*v6); ++b) {
                struct in6_addr src, dst;
                assert(inet_pton(AF_INET6, v6[a], &src) == 1);
                assert(inet_pton(AF_INET6, v6[b], &dst) == 1);
                int sl = argos_network_is_lan6(&s, &src), dl = argos_network_is_lan6(&s, &dst);
                int routed = legacy_routed6(&s, &src, iface);
                argos_network_packet_context_t ctx = {99,99};
                assert(argos_network_routed6(&s, &src, iface) == routed);
                assert(argos_network_context6(&s, &src, &dst, iface, &ctx) == (sl || dl || routed));
                assert(ctx.source_side == (sl || routed) && ctx.routed == routed);
            }
        }
        assert(memcmp(&s, &before, sizeof(s)) == 0);
    }
    assert(s.owner4 == NULL && s.owner6 == NULL);
    assert(!argos_network_routed4(NULL, htonl(0x0a000001U), 1));
    assert(!argos_network_routed6(NULL, &s.learned[0].v6, 1));
    assert(!argos_network_routed6(&s, NULL, 1));
    puts("Network policy: 132600 source/destination/interface/capacity cases PASS");
    return 0;
}
