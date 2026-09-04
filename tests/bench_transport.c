/* Focused normalized transport microbenchmark; not a capture throughput claim.
 * cc -std=c11 -O2 tests/bench_transport.c -o /tmp/bench && /tmp/bench */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include "../src/argos_packet.h"

static volatile unsigned sink;
static unsigned signature(int off, int len, int hl, unsigned sport, unsigned dport) {
    return (unsigned)(off + len + hl) + sport + dport;
}
__attribute__((noinline))
static unsigned legacy(const argos_packet_view_t *v, int enabled) {
    int off = v->l4_offset, available = v->packet_end - off;
    const unsigned char *p = v->frame + off;
    if (v->ip_protocol == 6) {
        if (available < 20) return 0;
        int hl = (p[12] >> 4) * 4;
        if (hl < 20 || hl > available || !enabled) return 0;
        return signature(off + hl, available - hl, hl, read_be16(p), read_be16(p+2));
    }
    if (available < 8 || !enabled) return 0;
    int length = read_be16(p+4);
    if (length <= 8 || length > available) return 0;
    return signature(off+8, length-8, 8, read_be16(p), read_be16(p+2));
}
__attribute__((noinline))
static unsigned current(const argos_packet_view_t *v, int enabled) {
    argos_transport_view_t t;
    if (v->ip_protocol == 6) {
        if (!argos_packet_transport_normalized(v, 6, &t) || !enabled) return 0;
    } else {
        if (v->packet_end - v->l4_offset < 8 || !enabled) return 0;
        if (!argos_packet_transport_normalized(v, 17, &t) || t.payload_len <= 0) return 0;
    }
    return signature(t.payload_offset, t.payload_len, t.header_len, t.sport, t.dport);
}
static double now(void) {
    struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}
int main(void) {
    unsigned char packets[256][128] = {{0}};
    argos_packet_view_t views[256];
    for (unsigned i = 0; i < 256; ++i) {
        unsigned char *p = packets[i];
        p[0] = 0x45; p[3] = 100; p[9] = (i & 1) ? 6 : 17;
        p[20] = 1; p[21] = (unsigned char)i; p[22] = 1; p[23] = 187;
        p[25] = (unsigned char)(i % 100); p[32] = (unsigned char)((i % 16) << 4);
        assert(argos_packet_decode(LINK_RAW_IP, p, 128, 1, &views[i]));
        assert(legacy(&views[i], 1) == current(&views[i], 1));
        assert(legacy(&views[i], 0) == current(&views[i], 0));
    }
    for (int mode = 0; mode < 2; ++mode) {
        double times[2] = {0, 0};
        for (int round = 0; round < 8; ++round) {
            for (int pass = 0; pass < 2; ++pass) {
                int which = (round + pass) & 1;
                unsigned sum = 0; double start = now();
                for (unsigned j = 0; j < 8000000U; ++j) {
                    const argos_packet_view_t *v = &views[j & 255U];
                    sum += which ? current(v, mode) : legacy(v, mode);
                }
                times[which] += now() - start; sink = sum;
            }
        }
        printf("%s: legacy %.3f ns/current %.3f ns, ratio %.3f\n",
               mode ? "enabled mixed" : "disabled mixed", times[0]*1e9/64000000.0,
               times[1]*1e9/64000000.0, times[1]/times[0]);
    }
    return 0;
}
