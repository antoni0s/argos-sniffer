/* Exercise the actual static printer, without opening capture or running main.
 * Redirect printf only; production formatting and IP conversion are unchanged. */
#define main argos_unused_program_main
#define printf(...) inspector_printf(__VA_ARGS__)
#define ARGOS_QUIC_STUB
#include "../src/argos-sniffer.c"
#undef printf
#undef main
#include <assert.h>

static char printed[512];
int inspector_printf(const char *format, ...) {
    va_list ap; va_start(ap, format);
    int n = vsnprintf(printed, sizeof(printed), format, ap);
    va_end(ap); assert(n >= 0 && (size_t)n < sizeof(printed)); return n;
}
static void put16(unsigned char *p, unsigned n) {
    p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n;
}
static void expect(const argos_packet_view_t *v, const char *want) {
    printed[0] = 0;
    dump_target_packet(v);
    /* Timestamp is intentionally live; compare the complete remaining line. */
    assert(!strcmp(printed[0] ? printed + 16 : printed, want));
}
int main(void) {
    for (int align = 0; align < 2; ++align)
    for (int vlan = 0; vlan <= 2; ++vlan)
    for (int fragment = 0; fragment < 3; ++fragment) {
        unsigned char storage[161] = {0}, *p = storage + align;
        int l3 = 14 + 4 * vlan, l4 = l3 + 24;
        argos_packet_view_t v;
        put16(p + 12, vlan ? 0x8100 : 0x0800);
        if (vlan) { put16(p + 14, 7); put16(p + 16, vlan == 2 ? 0x8100 : 0x0800); }
        if (vlan == 2) { put16(p + 18, 8); put16(p + 20, 0x0800); }
        p[l3] = 0x46; p[l3 + 9] = 6;
        put16(p + l3 + 6, fragment == 1 ? 0x2000 : fragment == 2 ? 1 : 0);
        p[l3 + 12] = 192; p[l3 + 13] = 0; p[l3 + 14] = 2; p[l3 + 15] = 1;
        p[l3 + 16] = 198; p[l3 + 17] = 51; p[l3 + 18] = 100; p[l3 + 19] = 2;
        put16(p + l4, 1234); put16(p + l4 + 2, 443);
        p[l4 + 7] = 7; p[l4 + 13] = 0x1f; put16(p + l4 + 14, 4096);
        for (int n = 0; n <= 64; ++n)
        for (unsigned doff = 0; doff < 16; ++doff) {
            p[l4 + 12] = (unsigned char)(doff << 4);
            put16(p + l3 + 2, (unsigned)(24 + n));
            assert(argos_packet_decode(LINK_ETHERNET, p, l4 + 80, 1, &v));
            char want[256];
            if (n < 20) snprintf(want, sizeof(want), "IP 192.0.2.1 > 198.51.100.2: proto 6, length %d\n", 24 + n);
            else if (doff < 5 || doff * 4 > (unsigned)n) want[0] = 0;
            else snprintf(want, sizeof(want), "IP 192.0.2.1.1234 > 198.51.100.2.443: Flags [S.PFR], seq 7, win 4096, length %d\n", n - (int)doff * 4);
            expect(&v, want);
        }
        /* Best-effort UDP prints invalid declared lengths too, but never
         * treats capture padding as a complete header. Nonfirst behavior stays. */
        p[l3 + 9] = 17;
        for (int n = 0; n <= 12; ++n)
        for (unsigned len = 0; len <= 16; ++len) {
            put16(p + l3 + 2, (unsigned)(24 + n)); put16(p + l4 + 4, len);
            assert(argos_packet_decode(LINK_ETHERNET, p, l4 + 80, 1, &v));
            char want[256];
            if (n < 8) snprintf(want, sizeof(want), "IP 192.0.2.1 > 198.51.100.2: proto 17, length %d\n", 24 + n);
            else snprintf(want, sizeof(want), "IP 192.0.2.1.1234 > 198.51.100.2.443: UDP, length %u\n", len);
            expect(&v, want);
        }
        p[l3 + 9] = 1;
        assert(argos_packet_decode(LINK_ETHERNET, p, l4 + 80, 1, &v));
        expect(&v, "IP 192.0.2.1 > 198.51.100.2: ICMP, length 12\n");
    }
    unsigned char p[80] = {0}; argos_packet_view_t v;
    p[0] = 0x60; put16(p + 4, 16); p[6] = 0; p[40] = 17;
    p[8] = 0x20; p[9] = 1; p[10] = 0x0d; p[11] = 0xb8; p[23] = 1;
    memcpy(p + 24, p + 8, 16); p[39] = 2;
    assert(argos_packet_decode(LINK_RAW_IP, p, sizeof(p), 1, &v));
    expect(&v, "IP6 2001:db8::1 > 2001:db8::2: next-hdr 0, length 16\n");
    memset(p, 0, sizeof(p)); put16(p + 12, 0x0806);
    assert(argos_packet_decode(LINK_ETHERNET, p, 60, 1, &v));
    expect(&v, "ARP, length 46\n");
    put16(p + 12, 0x88cc);
    assert(argos_packet_decode(LINK_ETHERNET, p, 60, 1, &v));
    expect(&v, "ethertype 0x88cc, length 60\n");
    puts("Actual inspector output/boundary matrix: PASS");
    return 0;
}
