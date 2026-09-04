#include <assert.h>
#include <stdio.h>
#include "../src/argos_packet.h"

static void put16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}

int main(void) {
    unsigned char raw[128] = {0};
    argos_packet_view_t v;
    argos_transport_view_t t;
    assert(sizeof(t) <= 24U);
    /* Compare all TCP header sizes and UDP declared lengths against the
     * previous main-loop validity predicates; backing storage includes padding. */
    for (int ipv6 = 0; ipv6 <= 1; ++ipv6) {
        int offset = ipv6 ? 40 : 20;
        for (int proto = 6; proto <= 17; proto += 11) {
            for (int n = 0; n <= 64; ++n) {
                memset(raw, 0, sizeof(raw));
                raw[0] = ipv6 ? 0x60 : 0x45;
                put16(raw + (ipv6 ? 4 : 2), (unsigned)(ipv6 ? n : offset + n));
                raw[ipv6 ? 6 : 9] = (unsigned char)proto;
                assert(argos_packet_decode(LINK_RAW_IP, raw, offset + n, 1, &v));
                put16(raw + offset, 1234); put16(raw + offset + 2, 443);
                for (unsigned h = 0; h <= 80; ++h) {
                    if (proto == 6) raw[offset + 12] = (unsigned char)((h & 15U) << 4);
                    else put16(raw + offset + 4, h);
                    int expected = proto == 6 ? n >= 20 && (h & 15U) >= 5 && (int)(h & 15U)*4 <= n :
                                               n >= 8 && h >= 8 && h <= (unsigned)n;
                    assert(argos_packet_transport(&v, &t) == expected);
                    if (expected) {
                        assert(t.has_ports && t.sport == 1234 && t.dport == 443);
                        assert(t.payload_offset == offset + t.header_len);
                        assert(t.payload_len == (proto == 6 ? n : (int)h) - t.header_len);
                        assert(t.payload_offset + t.payload_len <= v.packet_end);
                    } else assert(t.has_ports == 0 && t.payload_len == 0);
                }
            }
        }
    }
    /* No-port protocols: no parsing of ESP/AH/ICMP internals, no fabricated ports. */
    memset(raw, 0, sizeof(raw)); raw[0] = 0x45; put16(raw + 2, 28);
    const unsigned protocols[] = {1, 2, 50, 51, 89, 112};
    for (size_t i = 0; i < sizeof(protocols)/sizeof(protocols[0]); ++i) {
        raw[9] = (unsigned char)protocols[i];
        assert(argos_packet_decode(LINK_RAW_IP, raw, 32, 1, &v));
        assert(argos_packet_transport(&v, &t));
        assert(!t.has_ports && !t.sport && !t.dport && !t.header_len);
        assert(t.payload_offset == 20 && t.payload_len == 8);
    }
    v.nonfirst_fragment = 1; assert(!argos_packet_transport(&v, &t));
    v.nonfirst_fragment = 0; v.is_ip = 0; assert(!argos_packet_transport(&v, &t));
    v.is_ip = 1; v.l4_offset = -1; assert(!argos_packet_transport(&v, &t));
    v.l4_offset = 129; assert(!argos_packet_transport(&v, &t));
    v.l4_offset = 20; v.packet_end = 129; assert(!argos_packet_transport(&v, &t));
    assert(!argos_packet_transport(NULL, &t));
    assert(!argos_packet_transport(&v, NULL));
    puts("Bounded transport view equivalence: PASS");
    return 0;
}
