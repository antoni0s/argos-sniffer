#include <assert.h>
#include <stdio.h>
#include "../src/argos_packet.h"
#include "../src/argos_enterprise.h"

static void put16(unsigned char *p, unsigned n) {
    p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n;
}

static int envelope(unsigned char *p, int tags, unsigned type) {
    int off = 14;
    put16(p + 12, tags ? 0x8100U : type);
    for (int i = 0; i < tags; ++i) {
        put16(p + off, (unsigned)i + 1U);
        put16(p + off + 2, i + 1 == tags ? type : 0x8100U);
        off += 4;
    }
    return off;
}

int main(void) {
    unsigned long cases = 0;
    for (int tags = 0; tags <= 2; ++tags) for (int align = 0; align < 2; ++align) {
        unsigned char storage[257], *p = storage + align;
        argos_packet_view_t v;
        for (int ip6 = 0; ip6 < 2; ++ip6) {
            memset(storage, 0, sizeof(storage));
            int off = envelope(p, tags, 0x8864U), ip = off + 8;
            int ih = ip6 ? 40 : 20, total = ih + 8;
            p[off] = 0x11; put16(p + off + 2, 1);
            put16(p + off + 6, ip6 ? 0x57U : 0x21U);
            p[ip] = ip6 ? 0x60 : 0x45;
            put16(p + ip + (ip6 ? 4 : 2), ip6 ? 8U : (unsigned)total);
            p[ip + (ip6 ? 6 : 9)] = 17;
            put16(p + ip + ih + 4, 8);
            for (unsigned declared = 0; declared <= 65535U; ++declared) {
                put16(p + off + 4, declared);
                int cap = ip + total + 16;
                int expected = declared >= (unsigned)total + 2U && declared <= (unsigned)(cap - off - 6);
                assert(argos_packet_decode(LINK_ETHERNET, p, cap, 1, &v) == expected);
                if (expected) {
                    argos_transport_view_t t;
                    assert(v.packet_end == ip + total && v.captured_len == cap);
                    assert(argos_packet_transport(&v, &t) && t.payload_len == 0);
                }
                ++cases;
            }
            put16(p + off + 4, (unsigned)total + 2U);
            for (int cap = 0; cap <= ip + total + 16; ++cap) {
                assert(argos_packet_decode(LINK_ETHERNET, p, cap, 1, &v) == (cap >= ip + total));
                ++cases;
            }
        }
        /* Existing SNAP discriminators plus IS-IS and STP. */
        static const unsigned char prefixes[5][8] = {
            {0xaa,0xaa,3,0,0,0x0c,0x20,0},
            {0xaa,0xaa,3,0,0xe0,0x52,0x20,0},
            {0xaa,0xaa,3,0,0xe0,0x2b,0,0xbb},
            {0xfe,0xfe,3}, {0x42,0x42,3}
        };
        for (int kind = 0; kind < 5; ++kind) {
            memset(storage, 0, sizeof(storage));
            int off = envelope(p, tags, 32), prefix = kind < 3 ? 8 : 3;
            memcpy(p + off, prefixes[kind], (size_t)prefix);
            for (unsigned declared = 0; declared <= 1500U; ++declared) {
                put16(p + off - 2, declared);
                for (int cap = 0; cap <= off + 40; ++cap) {
                    int expected = declared >= (unsigned)prefix && cap >= off + (int)declared;
                    assert(argos_packet_decode(LINK_ETHERNET, p, cap, 1, &v) == expected);
                    if (expected) {
                        assert(v.packet_end == off + (int)declared);
                        assert(v.l3_offset == off + (kind == 4 ? 0 : prefix));
                    }
                    ++cases;
                }
            }
        }
        /* A valid-looking device-name TLV in Ethernet padding must not become evidence. */
        for (int kind = 0; kind < 3; ++kind) {
            memset(storage, 0, sizeof(storage));
            int base = kind == 2 ? 16 : 4;
            int off = envelope(p, tags, (unsigned)(8 + base));
            memcpy(p + off, prefixes[kind], 8);
            int tlv = off + 8 + base;
            p[tlv + 1] = 1; put16(p + tlv + 2, 10);
            memcpy(p + tlv + 4, "POISON", 6);
            assert(argos_packet_decode(LINK_ETHERNET, p, tlv + 10, 1, &v));
            argos_enterprise_result_t bounded, padded;
            assert(argos_enterprise_parse_l2(v.l3_proto, p + v.l3_offset,
                                            v.packet_end - v.l3_offset, &bounded));
            assert(argos_enterprise_parse_l2(v.l3_proto, p + v.l3_offset,
                                            v.captured_len - v.l3_offset, &padded));
            assert(!strstr(bounded.detail, "POISON") && strstr(padded.detail, "POISON"));
        }
    }
    printf("Encapsulation bounds: %lu cases PASS\n", cases);
    return 0;
}
