/* Characterize CURRENT reachability, not a proposed runtime dispatcher. */
#define main argos_bpf_fixture_main
#include "test_dynamic_bpf.c"
#undef main
#include "../src/argos_packet.h"
#include "../src/argos_ah.h"
#include "../src/argos_esp.h"
#include "../src/argos_ptp.h"

static unsigned long cases;
#define CHECK(x, s) do { expect((x), (s)); ++cases; } while (0)

static void bpf_matrix(void) {
    unsigned char p[256];
    for (unsigned mask = 0; mask < 1024U; ++mask) {
        argos_bpf_config_t c = {0}; argos_bpf_program_t b;
        c.syn = mask & 1U; c.multi = (mask >> 1) & 1U;
        c.dhcp = (mask >> 2) & 1U; c.netbios = (mask >> 3) & 1U;
        c.dns = (mask >> 4) & 1U; c.http = (mask >> 5) & 1U;
        c.tls = (mask >> 6) & 1U; c.l2 = (mask >> 7) & 1U;
        c.ipv6 = (mask >> 8) & 1U; c.enterprise = (mask >> 9) & 1U;
        CHECK(argos_bpf_build(&c, &b), "all legacy flag combinations fit BPF capacity");
        for (unsigned proto = 0; proto < 256U; ++proto) {
            if (proto == 6U || proto == 17U) continue;
            size_t n = proto4(p, (uint8_t)proto);
            int wanted = c.enterprise && (proto == 2U || proto == 89U || proto == 112U);
            CHECK(pass(&b, p, n) == wanted, "exact current non-port IPv4 whitelist");
        }
        size_t n = eth(p, 0x88f7);
        CHECK(!pass(&b, p, n), "native untagged PTP has no BPF gate");
        for (unsigned port = 319; port <= 320; ++port) for (int reverse = 0; reverse < 2; ++reverse) {
            n = udp4(p, reverse ? (uint16_t)port : 50000, reverse ? 50000 : (uint16_t)port, 34);
            CHECK(!pass(&b, p, n), "PTP-only UDP tuple has no legacy BPF gate");
        }
        n = eth(p, 0x86dd);
        CHECK(pass(&b, p, n) == c.ipv6, "IPv6 conservative gate follows ipv6 flag");
        const uint16_t types[] = {0x8100, 0x88a8, 0x8864};
        for (unsigned i = 0; i < 3U; ++i) {
            n = eth(p, types[i]);
            CHECK(pass(&b, p, n), "encapsulation admission is not protocol enablement");
        }
    }
    /* Coincident configuration is admission, NOT a PTP parser/CLI bit. */
    argos_bpf_config_t c = {0}; argos_bpf_program_t b;
    c.enterprise = 1; c.wireguard_port = 319;
    CHECK(argos_bpf_build(&c, &b), "custom WireGuard BPF");
    size_t n = udp4(p, 50000, 319, 34);
    CHECK(pass(&b, p, n), "custom WireGuard port can coincide with PTP");
    c.syn = c.multi = c.dhcp = c.netbios = c.dns = c.http = c.tls = c.l2 = c.ipv6 = 1;
    c.wireguard_port = 51820;
    CHECK(argos_bpf_build(&c, &b), "all-enabled plus default WireGuard fits capacity");
}

/* Fixture construction records offsets; never scan the packet again to find AH.
 * link 0=raw, 1=Ethernet, 2=VLAN, 3=QinQ, 4=PPPoE, 5=SLL compatibility. */
static int frame(unsigned char *p, int link, int ip6, unsigned proto, int bytes) {
    int ip = link == 0 ? 0 : link == 1 ? 14 : link == 2 ? 18 : link == 5 ? 16 : 22;
    uint16_t type = ip6 ? 0x86dd : 0x0800;
    memset(p, 0, 1200);
    if (link == 1) put16(p + 12, type);
    if (link == 2 || link == 3) {
        put16(p + 12, 0x8100); put16(p + 14, 7);
        put16(p + 16, link == 2 ? type : 0x8100);
        if (link == 3) { put16(p + 18, 8); put16(p + 20, type); }
    }
    if (link == 4) {
        put16(p + 12, 0x8864); p[14] = 0x11; put16(p + 16, 1);
        put16(p + 18, (uint16_t)((ip6 ? 40 : 20) + bytes + 2));
        put16(p + 20, ip6 ? 0x57 : 0x21);
    }
    if (link == 5) { put16(p + 4, 6); put16(p + 14, type); }
    p[ip] = ip6 ? 0x60 : 0x45;
    put16(p + ip + (ip6 ? 4 : 2), (uint16_t)(bytes + (ip6 ? 0 : 20)));
    p[ip + (ip6 ? 6 : 9)] = (unsigned char)proto;
    return ip + (ip6 ? 40 : 20);
}

static link_type_t link_type(int link) {
    return link == 0 ? LINK_RAW_IP : link == 5 ? LINK_COOKED : LINK_ETHERNET;
}

static void ipsec_views(void) {
    for (int link = 0; link < 6; ++link) for (int align = 0; align < 2; ++align)
    for (int ip6 = 0; ip6 < 2; ++ip6) {
        unsigned char storage[1201], *p = storage + align;
        argos_packet_view_t v; argos_transport_view_t t;
        int off = frame(p, link, ip6, 50, 8);
        p[off + 3] = 1; p[off + 7] = 2;
        for (int cap = 1; cap <= off + 24; ++cap) {
            int ok = argos_packet_decode(link_type(link), p, cap, 1, &v);
            CHECK(ok == (cap >= off + 8), "ESP capture truncation and padding");
            if (ok) {
                argos_esp_result_t esp;
                CHECK(argos_packet_transport(&v, &t) && !t.has_ports && !t.sport && !t.dport,
                      "ESP slice has no invented ports");
                CHECK(t.payload_offset == off && t.payload_len == 8, "ESP slice excludes padding");
                CHECK(argos_esp_parse(p + t.payload_offset, (size_t)t.payload_len, &esp) &&
                      esp.spi == 1 && esp.sequence == 2, "explicit fixture reaches isolated ESP parser");
            }
        }
        for (unsigned lenfield = 0; lenfield < 256U; ++lenfield) {
            int ahlen = ((int)lenfield + 2) * 4;
            off = frame(p, link, ip6, 51, ahlen + 8);
            p[off] = 17; p[off + 1] = (unsigned char)lenfield; p[off + 7] = 1;
            if (ahlen >= 12) p[off + 11] = 2;
            put16(p + off + ahlen, 1234); put16(p + off + ahlen + 2, 319);
            put16(p + off + ahlen + 4, 8);
            CHECK(argos_packet_decode(link_type(link), p, off + ahlen + 16, 1, &v),
                  "legacy normalizer accepts AH framing, including semantic edge cases");
            CHECK(v.l4_offset == off + (ip6 ? ahlen : 0) && v.ip_protocol == (ip6 ? 17 : 51),
                  "IPv4 AH retained; IPv6 terminal L4 skips AH");
            CHECK(argos_packet_transport(&v, &t) && t.has_ports == ip6,
                  "terminal transport is not the IPv6 AH slice");
            argos_ah_result_t ah;
            CHECK(argos_ah_parse(p + off, (size_t)ahlen, &ah) == (ahlen >= 12),
                  "isolated AH parser minimum differs from legacy walker");
            /* This is a known limitation, not RFC validation: the isolated
             * parser has no IP-version input to enforce IPv6 8-byte alignment. */
        }
        off = frame(p, link, ip6, ip6 ? 44U : 51U, 32);
        if (ip6) { p[off] = 51; put16(p + off + 2, 8); }
        else put16(p + off - 20 + 6, 1);
        int ok = argos_packet_decode(link_type(link), p, off + 32, 1, &v);
        CHECK(ip6 ? !ok : ok && !argos_packet_transport(&v, &t),
              "nonfirst fragments cannot expose an AH transport slice");
    }
}

static void ptp_views(void) {
    unsigned char message[34] = {0}; message[1] = 2;
    put16(message + 2, 34); message[27] = 1; put16(message + 30, 7);
    argos_ptp_result_t golden;
    CHECK(argos_ptp_parse(message, sizeof(message), &golden), "PTP common-header baseline");
    /* Explicit test adapter only; no runtime enable or reachability claim. */
    for (int link = 0; link < 6; ++link) for (int ip6 = 0; ip6 < 2; ++ip6)
    for (unsigned port = 319; port <= 320; ++port) {
        unsigned char p[1200]; argos_packet_view_t v; argos_transport_view_t t;
        int off = frame(p, link, ip6, 17, 42);
        put16(p + off, (uint16_t)port); put16(p + off + 2, (uint16_t)port); put16(p + off + 4, 42);
        memcpy(p + off + 8, message, 34);
        CHECK(argos_packet_decode(link_type(link), p, off + 50, 1, &v) &&
              argos_packet_transport(&v, &t), "bounded UDP PTP fixture");
        argos_ptp_result_t r;
        CHECK(argos_ptp_parse(p + t.payload_offset, (size_t)t.payload_len, &r) &&
              !strcmp(r.detail, golden.detail), "same isolated PTP parser/result on UDP4/UDP6");
        put16(p + off + 4, 41);
        CHECK(argos_packet_decode(link_type(link), p, off + 50, 1, &v) &&
              argos_packet_transport(&v, &t) &&
              !argos_ptp_parse(p + t.payload_offset, (size_t)t.payload_len, &r),
              "IP/capture tail cannot complete short UDP PTP");
    }
    for (int tags = 0; tags <= 2; ++tags) {
        unsigned char p[1200] = {0}; int off = 14 + 4 * tags;
        put16(p + 12, tags ? 0x8100 : 0x88f7);
        if (tags) { put16(p + 14, 7); put16(p + 16, tags == 1 ? 0x88f7 : 0x8100); }
        if (tags == 2) { put16(p + 18, 8); put16(p + 20, 0x88f7); }
        memcpy(p + off, message, 34);
        argos_packet_view_t v; argos_ptp_result_t r;
        CHECK(argos_packet_decode(LINK_ETHERNET, p, off + 42, 1, &v) && !v.is_ip,
              "native PTP normalizes without inventing IP");
        CHECK(argos_ptp_parse(p + v.l3_offset, (size_t)(v.packet_end - v.l3_offset), &r) &&
              !strcmp(r.detail, golden.detail), "native and UDP share the same isolated PTP result");
        CHECK(!argos_ptp_parse(p + v.l3_offset, 33, &r), "short native common header rejected");
    }
}

static void ah_chain_limits(void) {
    unsigned char p[1200]; argos_packet_view_t v;
    /* HBH -> AH -> destination options -> AH -> ESP. Two known AH offsets
     * demonstrate why a future "first AH" sidecar must not imply all AHs. */
    int off = frame(p, 1, 1, 0, 56);
    p[off] = 51;
    p[off + 8] = 60; p[off + 9] = 2; p[off + 15] = 1;
    p[off + 24] = 51;
    p[off + 32] = 50; p[off + 33] = 2; p[off + 39] = 2;
    p[off + 51] = 3;
    CHECK(argos_packet_decode(LINK_ETHERNET, p, off + 64, 1, &v) &&
          v.ip_protocol == 50 && v.l4_offset == off + 48, "mixed chain retains only terminal ESP offset");
    argos_ah_result_t first, second;
    CHECK(argos_ah_parse(p + off + 8, 16, &first) && first.spi == 1 &&
          argos_ah_parse(p + off + 32, 16, &second) && second.spi == 2,
          "fixture-known AH slices are distinct from terminal transport");
    for (int bytes = 8; bytes < 24; ++bytes) {
        put16(p + 18, (uint16_t)bytes);
        CHECK(!argos_packet_decode(LINK_ETHERNET, p, off + 64, 1, &v),
              "captured tail cannot complete AH beyond declared IPv6 payload");
    }
    off = frame(p, 0, 1, 51, 16);
    p[off] = 59; p[off + 1] = 2; p[off + 7] = 1;
    CHECK(!argos_packet_decode(LINK_RAW_IP, p, off + 16, 1, &v),
          "AH followed by no-next-header currently rejects whole view");
    CHECK(argos_ah_parse(p + off, 16, &first), "valid AH framing can precede rejected terminal view");
}

int main(void) {
    bpf_matrix(); ipsec_views(); ptp_views(); ah_chain_limits();
    printf("Current non-port/AH/PTP contract: %lu checks PASS (no runtime integration)\n", cases);
    return 0;
}
