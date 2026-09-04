#include <assert.h>
#include <stdio.h>
#include "../src/argos_packet.h"

/* Decoder/transport boundaries, not IP semantic validation or reassembly.
 * Checksums, reserved flags and extension ordering retain existing policy. */
static void put16(unsigned char *p, unsigned value) {
    p[0] = (unsigned char)(value >> 8); p[1] = (unsigned char)value;
}

static void check_transport(const argos_packet_view_t *v, int expected,
                            int header, int payload) {
    argos_transport_view_t t, fast;
    memset(&t, 0xa5, sizeof(t));
    assert(argos_packet_transport(v, &t) == expected);
    if (!expected) {
        const unsigned char *bytes = (const unsigned char *)&t;
        for (size_t i = 0; i < sizeof(t); ++i) assert(bytes[i] == 0);
        return;
    }
    assert(argos_packet_transport_normalized(v, v->ip_protocol, &fast));
    assert(t.header_len == header && fast.header_len == header);
    assert(t.payload_offset == v->l4_offset + header);
    assert(fast.payload_offset == t.payload_offset);
    assert(t.payload_len == payload && fast.payload_len == payload);
    assert(t.payload_offset + t.payload_len <= v->packet_end);
    assert(t.has_ports == (header != 0) && fast.has_ports == t.has_ports);
    assert(t.sport == (header ? 1234 : 0) && fast.sport == t.sport);
    assert(t.dport == (header ? 443 : 0) && fast.dport == t.dport);
}

static void fragments(void) {
    for (int ip6 = 0; ip6 < 2; ++ip6)
    for (int ethernet = 0; ethernet < 2; ++ethernet)
    for (int align = 0; align < 2; ++align)
    for (int proto = 6; proto <= 17; proto += 11) {
        unsigned char storage[129] = {0}, *p = storage + align;
        int l3 = ethernet ? 14 : 0, l4 = l3 + (ip6 ? 48 : 24);
        int header = proto == 6 ? 24 : 8, length = header + 4;
        link_type_t link = ethernet ? LINK_ETHERNET : LINK_RAW_IP;
        argos_packet_view_t v;
        if (ethernet) put16(p + 12, ip6 ? 0x86dd : 0x0800);
        p[l3] = ip6 ? 0x60 : 0x46; /* IPv4 includes four option bytes. */
        p[l3 + (ip6 ? 6 : 9)] = (unsigned char)(ip6 ? 44 : proto);
        if (ip6) p[l3 + 40] = (unsigned char)proto;
        put16(p + l4, 1234); put16(p + l4 + 2, 443);
        if (proto == 6) p[l4 + 12] = 0x60;
        else put16(p + l4 + 4, (unsigned)length);
        memcpy(p + l4 + header, "DATA", 4);
        put16(p + l3 + (ip6 ? 4 : 2), (unsigned)(ip6 ? 8 + length : 24 + length));

        /* Exhaust the wire field: all offsets, M/MF, DF and reserved bits.
         * IPv4 keeps a nonfirst view but transport rejects it; IPv6 rejects
         * nonfirst at normalization. Zero-offset/atomic/first are bounded. */
        for (unsigned field = 0; field <= 65535; ++field) {
            put16(p + l3 + (ip6 ? 42 : 6), field);
            int nonfirst = (field & (ip6 ? 0xfff8U : 0x1fffU)) != 0;
            int decoded = argos_packet_decode(link, p, l4 + length + 12, 1, &v);
            assert(decoded == !(ip6 && nonfirst));
            if (!decoded) continue; /* Failed decode fields are not a view. */
            assert(v.nonfirst_fragment == (!ip6 && nonfirst));
            assert(v.l4_offset == l4 && v.packet_end == l4 + length);
            check_transport(&v, !nonfirst, header, 4);
        }

        /* Partial first fragment: TCP accepts a complete header; UDP requires
         * its entire declared datagram. Capture padding cannot complete either. */
        put16(p + l3 + (ip6 ? 42 : 6), ip6 ? 1 : 0x2000);
        for (int n = 0; n <= length; ++n) {
            put16(p + l3 + (ip6 ? 4 : 2), (unsigned)(ip6 ? 8 + n : 24 + n));
            assert(argos_packet_decode(link, p, l4 + length + 12, 1, &v));
            assert(v.packet_end == l4 + n);
            check_transport(&v, proto == 6 ? n >= header : n == length,
                            header, n - header);
            for (int captured = 0; captured < l4 + n; ++captured)
                assert(!argos_packet_decode(link, p, captured, 1, &v));
        }
    }
}

static void extension_lengths(void) {
    const unsigned char types[] = {0, 43, 60, 51, 44};
    for (int align = 0; align < 2; ++align)
    for (size_t kind = 0; kind < sizeof(types); ++kind)
    for (unsigned value = 0; value <= (types[kind] == 44 ? 0U : 255U); ++value) {
        unsigned char storage[2129] = {0}, *p = storage + align;
        int length = types[kind] == 44 ? 8 : types[kind] == 51 ?
                     ((int)value + 2) * 4 : ((int)value + 1) * 8;
        argos_packet_view_t v;
        p[0] = 0x60; p[6] = types[kind]; p[40] = 17;
        p[41] = (unsigned char)value;
        put16(p + 40 + length, 1234); put16(p + 42 + length, 443);
        put16(p + 44 + length, 12);
        /* Declared IP end truncates each byte of the extension, even when
         * the full header exists in capture padding. AH uses legacy formula;
         * this does not validate its RFC minimum or preserve its own offset. */
        for (int n = 0; n < length; ++n) {
            put16(p + 4, (unsigned)n);
            assert(!argos_packet_decode(LINK_RAW_IP, p, 40 + length + 24, 1, &v));
        }
        put16(p + 4, (unsigned)length);
        assert(argos_packet_decode(LINK_RAW_IP, p, 40 + length + 24, 1, &v));
        check_transport(&v, 0, 8, 4);
        put16(p + 4, (unsigned)(length + 12));
        assert(argos_packet_decode(LINK_RAW_IP, p, 40 + length + 24, 1, &v));
        assert(v.l4_offset == 40 + length && v.ip_protocol == 17);
        check_transport(&v, 1, 8, 4);
        for (int n = 0; n < 40 + length + 12; ++n)
            assert(!argos_packet_decode(LINK_RAW_IP, p, n, 1, &v));
    }
}

static void extension_depth(void) {
    const unsigned char chain[] = {0, 43, 60, 51, 44, 60, 43, 60, 0};
    const unsigned char terminals[] = {6, 17, 50, 58, 59};
    for (int align = 0; align < 2; ++align)
    for (int depth = 0; depth <= 9; ++depth)
    for (size_t terminal = 0; terminal < sizeof(terminals); ++terminal) {
        unsigned char storage[193] = {0}, *p = storage + align;
        argos_packet_view_t v;
        unsigned char proto = terminals[terminal];
        int off = 40;
        p[0] = 0x60; p[6] = depth ? chain[0] : proto;
        for (int i = 0; i < depth; ++i) {
            p[off] = i + 1 == depth ? proto : chain[i + 1];
            if (chain[i] == 51) p[off + 1] = 1; /* Twelve-byte AH. */
            off += chain[i] == 51 ? 12 : 8;
        }
        put16(p + off, 1234); put16(p + off + 2, 443);
        put16(p + off + 4, 12); p[off + 12] = 0x50;
        put16(p + 4, (unsigned)(off - 40 + 24));
        /* Eight loop iterations include the terminal-header visit: seven
         * extensions accepted, eight rejected. This is the current budget,
         * not a promise to accept arbitrary RFC-valid chains. */
        int expected = depth <= 7 && proto != 59;
        assert(argos_packet_decode(LINK_RAW_IP, p, off + 36, 1, &v) == expected);
        if (expected) {
            assert(v.ip_protocol == proto && v.l4_offset == off);
            check_transport(&v, 1, proto == 6 ? 20 : proto == 17 ? 8 : 0,
                            proto == 6 || proto == 17 ? 4 : 24);
        }
        if (depth >= 5) { /* Nonfirst fragment behind options/routing/AH. */
            put16(p + 40 + 8 + 8 + 8 + 12 + 2, 8);
            assert(!argos_packet_decode(LINK_RAW_IP, p, off + 36, 1, &v));
        }
        assert(argos_packet_decode(LINK_RAW_IP, p, off + 36, 0, &v));
        assert(!v.is_ip);
        check_transport(&v, 0, 0, 0);
    }
}

int main(void) {
    fragments();
    extension_lengths();
    extension_depth();
    puts("IPv4/IPv6 fragment and extension boundaries: PASS");
    return 0;
}
