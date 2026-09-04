/* Optional normalization ownership only: staging parsers remain test-only. */
#define ARGOS_NONPORT_FIXTURE_MAIN argos_nonport_fixture_main
#include "test_nonport_contract.c"
#undef ARGOS_NONPORT_FIXTURE_MAIN
#include "reference_packet.h"

static int compare(link_type_t type, const unsigned char *p, int cap, int ip6,
                   argos_packet_view_t *v, argos_packet_ah_view_t *ah) {
    argos_packet_view_t old, disabled;
    reference_argos_packet_view_t frozen;
    memset(&frozen, 0xa5, sizeof(frozen));
    memset(&old, 0xa5, sizeof(old));
    memset(&disabled, 0xa5, sizeof(disabled));
    memset(v, 0xa5, sizeof(*v));
    memset(ah, 0xa5, sizeof(*ah));
    int expected = argos_packet_decode(type, p, cap, ip6, &old);
    CHECK(reference_argos_packet_decode((reference_link_type_t)type, p, cap, ip6, &frozen) == expected &&
          sizeof(frozen) == sizeof(old) && !memcmp(&old, &frozen, sizeof(old)),
          "frozen PR18 decoder equivalence including failed-view bytes");
    int ok = argos_packet_decode_with_ah(type, p, cap, ip6, v, ah);
    CHECK(ok == expected && !memcmp(v, &old, sizeof(old)), "legacy packet view unchanged");
    CHECK(argos_packet_decode_with_ah(type, p, cap, ip6, &disabled, NULL) == expected &&
          !memcmp(&disabled, &old, sizeof(old)), "NULL request preserves legacy decode");
    if (!ok) CHECK(!ah->offset && !ah->length, "no evidence after failed decode");
    if (ah->length) CHECK(ok && ah->offset >= v->l3_offset && ah->length >= 12 &&
        ah->length <= v->packet_end - ah->offset && !v->nonfirst_fragment,
        "borrowed AH slice bounded by successful normalized packet");
    return ok;
}

static void length_matrix(void) {
    for (int link = 0; link < 6; ++link) for (int align = 0; align < 2; ++align)
    for (int ip6 = 0; ip6 < 2; ++ip6) for (unsigned field = 0; field < 256; ++field) {
        unsigned char storage[1201], *p = storage + align;
        int bytes = ((int)field + 2) * 4;
        int off = frame(p, link, ip6, 51, bytes + 8);
        p[off] = 17; p[off + 1] = (unsigned char)field;
        put16(p + off + bytes + 4, 8);
        for (int cap = 0; cap <= off + bytes + 16; ++cap) {
            argos_packet_view_t v; argos_packet_ah_view_t ah;
            int ok = compare(link_type(link), p, cap, 1, &v, &ah);
            int present = ok && bytes >= 12 && (!ip6 || bytes % 8 == 0);
            CHECK(ah.length == (present ? bytes : 0) && ah.offset == (present ? off : 0),
                  "all AH lengths, alignments, capture truncations and padding");
            if (present) {
                /* Framing deliberately does not validate SPI or authentication. */
                argos_ah_result_t r;
                CHECK(!argos_ah_parse(p + ah.offset, (size_t)ah.length, &r),
                      "zero SPI remains a semantic parser rejection");
            }
        }
        /* Captured padding must not complete a header outside declared IP end. */
        int ip = off - (ip6 ? 40 : 20);
        put16(p + ip + (ip6 ? 4 : 2), (uint16_t)(bytes - 1 + (ip6 ? 0 : 20)));
        argos_packet_view_t v; argos_packet_ah_view_t ah;
        compare(link_type(link), p, off + bytes + 16, 1, &v, &ah);
        CHECK(!ah.length && !ah.offset, "IP declared bounds exclude captured tail");
    }
}

static void chain_matrix(void) {
    unsigned char p[1200]; argos_packet_view_t v; argos_packet_ah_view_t ah;
    for (int first = 8; first <= 20; first += 4) {
        int off = frame(p, 1, 1, 0, 8 + first + 8 + 16 + 8);
        p[off] = 51;
        p[off + 8] = 60; p[off + 9] = (unsigned char)(first / 4 - 2);
        p[off + 8 + first] = 51;
        p[off + 16 + first] = 50; p[off + 17 + first] = 2;
        CHECK(compare(LINK_ETHERNET, p, off + 40 + first, 1, &v, &ah), "mixed repeated AH chain");
        CHECK(v.ip_protocol == 50 && v.l4_offset == off + 32 + first,
              "terminal ESP remains separate from first AH");
        CHECK(ah.length == (first == 16 ? 16 : 0) && ah.offset == (first == 16 ? off + 8 : 0),
              "never replace invalid first AH with valid second AH");
        /* A valid early candidate must be discarded if a later header fails. */
        p[off + 17 + first] = 255;
        CHECK(!compare(LINK_ETHERNET, p, off + 40 + first, 1, &v, &ah), "malformed later AH clears result");
    }
    for (int depth = 0; depth <= 8; ++depth) {
        int off = frame(p, 0, 1, 51, 16 + depth * 8 + 8);
        p[off] = depth ? 60 : 50; p[off + 1] = 2;
        for (int i = 0; i < depth; ++i) p[off + 16 + i * 8] = i + 1 == depth ? 50 : 60;
        int ok = compare(LINK_RAW_IP, p, off + 24 + depth * 8, 1, &v, &ah);
        CHECK(ok == (depth <= 6) && ah.length == (ok ? 16 : 0), "legacy eight-iteration bound includes terminal");
    }
    int off = frame(p, 0, 1, 51, 16);
    p[off] = 59; p[off + 1] = 2;
    CHECK(!compare(LINK_RAW_IP, p, off + 16, 1, &v, &ah), "NoNext is not partial success");
    for (int ip6 = 0; ip6 < 2; ++ip6) for (unsigned frag = 0; frag < 3; ++frag) {
        off = frame(p, 0, ip6, ip6 ? 44 : 51, 32);
        int ah_off = off;
        if (ip6) { p[off] = 51; put16(p + off + 2, frag == 2 ? 8 : (uint16_t)frag); ah_off += 8; }
        else put16(p + 6, frag == 2 ? 1 : frag == 1 ? 0x2000 : 0);
        p[ah_off] = 50; p[ah_off + 1] = 2;
        compare(LINK_RAW_IP, p, off + 32, 1, &v, &ah);
        CHECK(ah.length == (frag == 2 ? 0 : 16), "only complete first/atomic fragment AH evidence");
    }
}

static void absent_and_failure(void) {
    unsigned char p[1200]; argos_packet_view_t v; argos_packet_ah_view_t ah;
    for (unsigned proto = 0; proto < 256; ++proto) {
        if (proto == 51) continue;
        for (int ip6 = 0; ip6 < 2; ++ip6) {
            int off = frame(p, 0, ip6, proto, 0);
            compare(LINK_RAW_IP, p, off, 1, &v, &ah);
            CHECK(!ah.length && !ah.offset, "absent AH is empty");
        }
    }
    int off = frame(p, 1, 1, 51, 16); p[off] = 50; p[off + 1] = 2;
    compare(LINK_ETHERNET, p, off + 16, 0, &v, &ah);
    CHECK(!ah.length, "disabled IPv6 gives no IP evidence");
    compare(LINK_RAW_IP, NULL, 100, 1, &v, &ah);
    ah.offset = ah.length = 99;
    CHECK(!argos_packet_decode_with_ah(LINK_RAW_IP, p, 100, 1, NULL, &ah) &&
          !ah.offset && !ah.length, "NULL packet view clears sidecar");
    compare(LINK_UNSUPPORTED, p, 100, 1, &v, &ah);
}

int main(void) {
    length_matrix(); chain_matrix(); absent_and_failure();
    printf("First-AH framing: %lu checks PASS; packet=%zu, optional=%zu bytes\n",
           cases, sizeof(argos_packet_view_t), sizeof(argos_packet_ah_view_t));
    return 0;
}
