#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "../src/argos_packet.h"
#include "../src/argos_network.h"

static void put16(unsigned char *p, unsigned n) {
    p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n;
}
/* Test-only previous main predicates, with independent aligned header copies. */
static int previous(uint8_t protocol, const unsigned char *p, int ip_len,
                    int captured_len, int source_side) {
    if (protocol == IPPROTO_UDP && captured_len >= 8) {
        struct udphdr h; memcpy(&h, p, sizeof(h));
        if (ntohs(h.source) == 53) return 1;
    }
    if (!source_side && protocol == IPPROTO_TCP && ip_len >= 20) {
        struct tcphdr h; memcpy(&h, p, sizeof(h));
        if (h.syn && h.ack) return 1;
    }
    return 0;
}

int main(void) {
    const unsigned ports[] = {0, 53, 54, 0x3500, 65535};
    const uint8_t protocols[] = {1, 6, 17, 50, 58, 112};
    for (int align = 0; align < 2; ++align)
    for (int ip6 = 0; ip6 < 2; ++ip6)
    for (size_t proto = 0; proto < sizeof(protocols); ++proto)
    for (int n = 0; n <= 32; ++n) {
        unsigned char storage[97] = {0}, *p = storage + align;
        int off = ip6 ? 48 : 24;
        argos_packet_view_t v; argos_transport_view_t t;
        p[0] = ip6 ? 0x60 : 0x46;
        put16(p + (ip6 ? 4 : 2), (unsigned)(ip6 ? 8 + n : off + n));
        p[ip6 ? 6 : 9] = ip6 ? 0 : protocols[proto];
        if (ip6) p[40] = protocols[proto]; /* Hop-by-hop, eight bytes. */
        assert(argos_packet_decode(LINK_RAW_IP, p, off + 40, 1, &v));
        assert(v.l4_offset == off && v.packet_end == off + n);
        put16(p + off + 4, 8); /* UDP length; TCP doff deliberately zero. */
        for (size_t port = 0; port < sizeof(ports)/sizeof(ports[0]); ++port)
        for (unsigned flags = 0; flags <= 255; ++flags)
        for (int side = 0; side < 2; ++side) {
            put16(p + off, ports[port]); p[off + 13] = (unsigned char)flags;
            int old = previous(v.ip_protocol, p + off, n, 40, side);
            int now = argos_network_router_exception(v.ip_protocol, p + off,
                                                     v.packet_end - v.l4_offset, side);
            int padding_only = v.ip_protocol == 17 && n < 8 && ports[port] == 53;
            assert(now == (padding_only ? 0 : old));
            if (padding_only) {
                assert(old == 1);
                assert(!argos_packet_transport(&v, &t));
            }
        }
    }
    assert(!argos_network_router_exception(17, NULL, 0, 0));
    assert(!argos_network_router_exception(6, NULL, 0, 0));
    /* Router admission never implies fragment/transport success. */
    unsigned char p[48] = {0}; argos_packet_view_t v; argos_transport_view_t t;
    p[0] = 0x45; p[9] = 17; put16(p + 2, 28); put16(p + 6, 1);
    put16(p + 20, 53); put16(p + 24, 8);
    assert(argos_packet_decode(LINK_RAW_IP, p, sizeof(p), 1, &v));
    assert(argos_network_router_exception(v.ip_protocol, p + v.l4_offset, 8, 1));
    assert(!argos_packet_transport(&v, &t));
    puts("Router exception equivalence/padding boundaries: PASS");
    return 0;
}
