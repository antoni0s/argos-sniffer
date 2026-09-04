#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include "../src/argos_capture.h"

static void put16(unsigned char *p, unsigned n) {
    p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n;
}

static void cooked(void) {
    const unsigned char mac[6] = {2, 3, 4, 5, 6, 7}, zero[6] = {0};
    for (int align = 0; align < 2; ++align)
    for (int ip6 = 0; ip6 < 2; ++ip6) {
        unsigned char storage[97] = {0}, *p = storage + align;
        int end = 16 + (ip6 ? 40 : 20) + 8;
        argos_packet_view_t v; argos_transport_view_t t;
        put16(p + 2, ARPHRD_ETHER); memcpy(p + 6, mac, 6);
        put16(p + 14, ip6 ? 0x86dd : 0x0800);
        p[16] = ip6 ? 0x60 : 0x45;
        put16(p + 16 + (ip6 ? 4 : 2), ip6 ? 8 : 28);
        p[16 + (ip6 ? 6 : 9)] = 17;
        put16(p + end - 8, 1234); put16(p + end - 6, 443);
        put16(p + end - 4, 8);
        /* SLL v1 layout: libpcap pcap/sll.h; all scalar fields are BE.
         * Only a complete six-byte address belongs in our MAC field. */
        for (unsigned length = 0; length <= 65535; ++length) {
            put16(p + 4, length);
            memset(&v, 0xa5, sizeof(v));
            assert(argos_packet_decode(LINK_COOKED, p, end + 8, 1, &v));
            assert(!memcmp(v.src_mac, length == 6 ? mac : zero, 6));
            assert(!memcmp(v.dst_mac, zero, 6));
            assert(v.l3_offset == 16 && v.packet_end == end);
            assert(argos_packet_transport(&v, &t));
            assert(t.sport == 1234 && t.dport == 443 && t.payload_len == 0);
        }
        put16(p + 4, 6);
        for (int n = 0; n < end; ++n)
            assert(!argos_packet_decode(LINK_COOKED, p, n, 1, &v));
    }
}

static void live_types(void) {
    /* Independent list: no implicit cooked/SLL or unsupported-link fallback. */
    const unsigned raw[] = {ARPHRD_NONE, ARPHRD_PPP, ARPHRD_TUNNEL,
                           ARPHRD_TUNNEL6, ARPHRD_SIT, ARPHRD_IPGRE};
    unsigned char frame[96] = {0};
    argos_packet_view_t v;
    for (unsigned h = 0; h <= 65535; ++h) {
        link_type_t expected = LINK_UNSUPPORTED;
        if (h == ARPHRD_ETHER || h == ARPHRD_IEEE802) expected = LINK_ETHERNET;
        for (size_t i = 0; i < sizeof(raw)/sizeof(raw[0]); ++i)
            if (h == raw[i]) expected = LINK_RAW_IP;
        link_type_t actual = argos_capture_hatype((unsigned short)h);
        assert(actual == expected);
        assert(actual != LINK_COOKED && actual != LINK_PER_PACKET);
        for (int ip6 = 0; ip6 < 2; ++ip6) {
            memset(frame, 0, sizeof(frame));
            int l3 = actual == LINK_ETHERNET ? 14 : 0;
            int end = l3 + (ip6 ? 40 : 20);
            if (l3) put16(frame + 12, ip6 ? 0x86dd : 0x0800);
            frame[l3] = ip6 ? 0x60 : 0x45;
            put16(frame + l3 + (ip6 ? 4 : 2), ip6 ? 0 : 20);
            frame[l3 + (ip6 ? 6 : 9)] = 50; /* Opaque, no-port span only. */
            assert(argos_packet_decode(actual, frame, end, 1, &v) ==
                   (expected != LINK_UNSUPPORTED));
            if (expected == LINK_RAW_IP) {
                const unsigned char zero[6] = {0};
                assert(v.l3_offset == 0 && v.packet_end == end);
                assert(!memcmp(v.src_mac, zero, 6) && !memcmp(v.dst_mac, zero, 6));
            }
        }
    }
    assert(!argos_packet_decode(LINK_PER_PACKET, frame, sizeof(frame), 1, &v));
    assert(!argos_packet_decode((link_type_t)99, frame, sizeof(frame), 1, &v));
    for (unsigned version = 0; version < 16; ++version) {
        if (version == 4 || version == 6) continue;
        frame[0] = (unsigned char)(version << 4);
        assert(!argos_packet_decode(LINK_RAW_IP, frame, sizeof(frame), 1, &v));
    }
}

int main(void) {
    cooked(); live_types();
    puts("Live link ownership and SLL address boundaries: PASS");
    return 0;
}
