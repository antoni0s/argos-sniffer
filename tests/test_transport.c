#include <assert.h>
#include <stdio.h>
#include "../src/argos_packet.h"

static void put16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}

static void frame_paths(void) {
    for (int ip6 = 0; ip6 < 2; ++ip6) for (int proto = 6; proto <= 17; proto += 11)
    for (int link = 0; link < 6; ++link) for (int align = 0; align < 2; ++align) {
        unsigned char storage[257] = {0}, *p = storage + align;
        int l3 = link == 0 ? 0 : link == 1 ? 14 : link == 2 ? 18 : link == 5 ? 16 : 22;
        unsigned ether = ip6 ? 0x86ddU : 0x0800U;
        if (link == 1) put16(p+12, ether);
        if (link == 2 || link == 3) {
            put16(p+12, 0x8100); put16(p+14, 7);
            put16(p+16, link == 2 ? ether : 0x8100);
            if (link == 3) { put16(p+18, 8); put16(p+20, ether); }
        }
        if (link == 4) { put16(p+12, 0x8864); p[14] = 0x11; put16(p+20, ip6 ? 0x57 : 0x21); }
        if (link == 5) put16(p+14, ether);
        int ihl = ip6 ? 48 : 24, thl = proto == 6 ? 24 : 8;
        int end = l3 + ihl + thl + 4, off = l3 + ihl;
        p[l3] = ip6 ? 0x60 : 0x46;
        if (ip6) {
            put16(p+l3+4, (unsigned)(end-l3-40));
            p[l3+6] = 0; p[l3+40] = (unsigned char)proto;
        } else { put16(p+l3+2, (unsigned)(end-l3)); p[l3+9] = (unsigned char)proto; }
        put16(p+off, 1234); put16(p+off+2, 443);
        if (proto == 6) p[off+12] = 0x60;
        else put16(p+off+4, 12);
        memcpy(p+off+thl, "DATA", 4);
        if (link == 4) put16(p+18, (unsigned)(end-l3+2));
        argos_packet_view_t v; argos_transport_view_t t;
        link_type_t type = link == 0 ? LINK_RAW_IP : link == 5 ? LINK_COOKED : LINK_ETHERNET;
        assert(argos_packet_decode(type, p, end+12, 1, &v));
        assert(argos_packet_transport_normalized(&v, (uint8_t)proto, &t));
        assert(t.payload_offset == off+thl && t.payload_len == 4);
        assert(t.sport == 1234 && t.dport == 443 && t.header_len == thl);
        assert(memcmp(v.frame+t.payload_offset, "DATA", 4) == 0);
        for (int n = 0; n < end; ++n) assert(!argos_packet_decode(type, p, n, 1, &v));
    }
}

int main(void) {
    frame_paths();
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
                    argos_transport_view_t fast;
                    assert(argos_packet_transport_normalized(&v, (uint8_t)proto, &fast) == expected);
                    if (expected) {
                        assert(fast.payload_offset == t.payload_offset && fast.payload_len == t.payload_len);
                        assert(fast.header_len == t.header_len && fast.has_ports == t.has_ports);
                        assert(fast.sport == t.sport && fast.dport == t.dport);
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
