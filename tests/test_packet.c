#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/argos_packet.h"

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void put16(unsigned char *p, uint16_t value) {
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static void ipv4_header(unsigned char *p, uint8_t protocol, uint16_t total_len) {
    memset(p, 0, total_len);
    p[0] = 0x45U;
    put16(p + 2, total_len);
    p[8] = 64U;
    p[9] = protocol;
    p[12] = 192U; p[13] = 0U; p[14] = 2U; p[15] = 10U;
    p[16] = 198U; p[17] = 51U; p[18] = 100U; p[19] = 20U;
}

static void ethernet(unsigned char *p, uint16_t protocol) {
    static const unsigned char dst[6] = {0, 1, 2, 3, 4, 5};
    static const unsigned char src[6] = {6, 7, 8, 9, 10, 11};
    memcpy(p, dst, sizeof(dst));
    memcpy(p + 6, src, sizeof(src));
    put16(p + 12, protocol);
}

int main(void) {
    argos_packet_view_t v;
    check(sizeof(v) <= 128U, "packet view remains bounded");

    unsigned char frame[256];
    memset(frame, 0xa5, sizeof(frame));
    ethernet(frame, 0x0800U);
    ipv4_header(frame + 14, 17U, 28U);
    check(argos_packet_decode(LINK_ETHERNET, frame, 14 + 28 + 12, 1, &v),
          "Ethernet IPv4 decoded");
    check(v.l3_offset == 14 && v.l4_offset == 34 && v.packet_end == 42,
          "IPv4 offsets exclude Ethernet padding");
    check(v.ip_version == 4U && v.ip_protocol == 17U && v.ip_ttl == 64U,
          "IPv4 metadata normalized");
    check(v.src_addr[0] == 192U && v.dst_addr[0] == 198U,
          "IPv4 endpoints normalized");

    memset(frame, 0, sizeof(frame));
    ethernet(frame, 0x8100U);
    put16(frame + 14, 123U);
    put16(frame + 16, 0x0800U);
    ipv4_header(frame + 18, 6U, 40U);
    check(argos_packet_decode(LINK_ETHERNET, frame, 58, 1, &v), "802.1Q decoded");
    check(v.outer_vlan == 123U && v.inner_vlan == 0U && v.l3_offset == 18,
          "single VLAN context normalized");

    memset(frame, 0, sizeof(frame));
    ethernet(frame, 0x88a8U);
    put16(frame + 14, 200U);
    put16(frame + 16, 0x8100U);
    put16(frame + 18, 300U);
    put16(frame + 20, 0x0800U);
    ipv4_header(frame + 22, 6U, 40U);
    check(argos_packet_decode(LINK_ETHERNET, frame, 62, 1, &v), "QinQ decoded");
    check(v.outer_vlan == 200U && v.inner_vlan == 300U && v.l3_offset == 22,
          "QinQ context normalized");

    memset(frame, 0, sizeof(frame));
    ethernet(frame, 0x8864U);
    put16(frame + 20, 0x0021U);
    ipv4_header(frame + 22, 6U, 40U);
    check(argos_packet_decode(LINK_ETHERNET, frame, 62, 1, &v), "PPPoE IPv4 decoded");
    check(v.l3_proto == 0x0800U && v.l3_offset == 22, "PPPoE protocol mapped");

    unsigned char raw4[28];
    ipv4_header(raw4, 17U, sizeof(raw4));
    check(argos_packet_decode(LINK_RAW_IP, raw4, sizeof(raw4), 1, &v), "raw IPv4 decoded");
    check(v.l3_offset == 0 && v.l4_offset == 20 && v.src_mac[0] == 0U,
          "raw IPv4 has no invented L2 identity");

    unsigned char ip6[88];
    memset(ip6, 0, sizeof(ip6));
    ip6[0] = 0x60U;
    put16(ip6 + 4, 48U);
    ip6[6] = 0U;  /* Hop-by-Hop. */
    ip6[7] = 63U;
    ip6[8] = 0x20U; ip6[24] = 0x20U;
    ip6[40] = 17U;
    ip6[41] = 0U; /* Eight-byte extension header. */
    check(argos_packet_decode(LINK_RAW_IP, ip6, sizeof(ip6), 1, &v),
          "IPv6 extension chain decoded");
    check(v.ip_version == 6U && v.ip_protocol == 17U && v.l4_offset == 48 &&
          v.packet_end == 88 && v.ip_ttl == 63U,
          "IPv6 metadata and L4 offset normalized");

    ip6[6] = 44U;
    ip6[40] = 17U;
    put16(ip6 + 42, 0x0008U);
    check(!argos_packet_decode(LINK_RAW_IP, ip6, sizeof(ip6), 1, &v),
          "non-first IPv6 fragment rejected");

    ip6[6] = 59U;
    check(!argos_packet_decode(LINK_RAW_IP, ip6, sizeof(ip6), 1, &v),
          "IPv6 no-next-header rejected");
    check(argos_packet_decode(LINK_RAW_IP, ip6, sizeof(ip6), 0, &v) && !v.is_ip,
          "disabled IPv6 remains an unclassified L2 view");

    memset(frame, 0, sizeof(frame));
    ethernet(frame, 100U);
    frame[14] = 0xaaU; frame[15] = 0xaaU; frame[16] = 0x03U;
    frame[17] = 0x00U; frame[18] = 0x00U; frame[19] = 0x0cU;
    put16(frame + 20, 0x2000U);
    check(argos_packet_decode(LINK_ETHERNET, frame, 32, 1, &v), "CDP SNAP decoded");
    check(v.l3_proto == 0x2000U && v.l3_offset == 22, "CDP discriminator preserved");

    check(!argos_packet_decode(LINK_ETHERNET, frame, 10, 1, &v),
          "truncated Ethernet rejected");
    check(!argos_packet_decode(LINK_RAW_IP, raw4, 19, 1, &v),
          "truncated IPv4 rejected");
    check(!argos_packet_decode(LINK_UNSUPPORTED, frame, sizeof(frame), 1, &v),
          "unsupported link type rejected");

    puts("Packet normalization fixtures: PASS");
    return 0;
}
