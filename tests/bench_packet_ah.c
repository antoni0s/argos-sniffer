/* Decoder microbenchmark and inline-field alternative, not capture throughput. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include "../src/argos_packet.h"
#include "reference_packet.h"
static volatile unsigned sink;
typedef struct { argos_packet_view_t packet; argos_packet_ah_view_t ah; } inline_view_t;
static unsigned signature(int ok, int off, int protocol, int ah) {
    return ok ? (unsigned)(off + protocol + ah) : 0;
}
__attribute__((noinline))
static unsigned old_decode(const unsigned char *p) {
    reference_argos_packet_view_t v;
    int ok = reference_argos_packet_decode(reference_LINK_RAW_IP, p, 128, 1, &v);
    return signature(ok, v.l4_offset, v.ip_protocol, 0);
}
__attribute__((noinline))
static unsigned disabled_decode(const unsigned char *p) {
    argos_packet_view_t v;
    int ok = argos_packet_decode(LINK_RAW_IP, p, 128, 1, &v);
    return signature(ok, v.l4_offset, v.ip_protocol, 0);
}
__attribute__((noinline))
static unsigned enabled_decode(const unsigned char *p) {
    argos_packet_view_t v; argos_packet_ah_view_t ah;
    int ok = argos_packet_decode_with_ah(LINK_RAW_IP, p, 128, 1, &v, &ah);
    return signature(ok, v.l4_offset, v.ip_protocol, ah.length);
}
/* The inline-field alternative supplies the same evidence on every decode.
 * This adapter compares storage/work, not a second protocol parser. */
__attribute__((noinline))
static unsigned inline_decode(const unsigned char *p) {
    inline_view_t v;
    int ok = argos_packet_decode_with_ah(LINK_RAW_IP, p, 128, 1, &v.packet, &v.ah);
    return signature(ok, v.packet.l4_offset, v.packet.ip_protocol, v.ah.length);
}
static double now(void) {
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}
int main(void) {
    unsigned char p[256][128] = {{0}};
    for (unsigned i = 0; i < 256; ++i) {
        unsigned char *b = p[i];
        if (i % 4 == 0) { b[0] = 0x45; b[3] = 100; b[9] = 17; }
        else { b[0] = 0x60; b[5] = 80; b[6] = i % 4 == 1 ? 17 : i % 4 == 2 ? 51 : 0;
            if (b[6] == 51) { b[40] = 17; b[41] = 2; }
            if (b[6] == 0) { b[40] = 51; b[48] = 60; b[49] = 2; b[64] = 17; }
        }
        assert(old_decode(b) == disabled_decode(b));
        assert(enabled_decode(b) == inline_decode(b));
    }
    unsigned (*fn[])(const unsigned char *) = {old_decode, disabled_decode, enabled_decode, inline_decode};
    double elapsed[4] = {0};
    for (int round = 0; round < 8; ++round) for (int pass = 0; pass < 4; ++pass) {
        int which = (round + pass) % 4; unsigned sum = 0; double start = now();
        for (unsigned i = 0; i < 2000000U; ++i) sum += fn[which](p[i & 255]);
        elapsed[which] += now() - start; sink = sum;
    }
    printf("view=%zu optional=%zu inline-alternative=%zu bytes\n", sizeof(argos_packet_view_t),
           sizeof(argos_packet_ah_view_t), sizeof(inline_view_t));
    printf("ns/decode: frozen=%.3f disabled=%.3f enabled=%.3f inline=%.3f; disabled/frozen=%.3f\n",
           elapsed[0]*1e9/16000000., elapsed[1]*1e9/16000000., elapsed[2]*1e9/16000000.,
           elapsed[3]*1e9/16000000., elapsed[1]/elapsed[0]);
    return 0;
}
