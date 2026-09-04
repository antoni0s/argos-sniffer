/* Focused policy benchmark, not an AF_PACKET throughput guarantee. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>
#include "../src/argos_network.h"
#include "network_context_legacy.h"

static volatile unsigned sink;
typedef struct { uint32_t v4; struct in6_addr v6; } endpoint_t;

__attribute__((noinline))
static unsigned legacy(const argos_network_state_t *s, const endpoint_t *src,
                       const endpoint_t *dst, int family, int ifindex) {
    int sl, dl, routed;
    if (family == 4) {
        sl = argos_network_is_lan4(s, src->v4);
        dl = argos_network_is_lan4(s, dst->v4);
        routed = legacy_routed4(s, src->v4, ifindex);
    } else {
        sl = argos_network_is_lan6(s, &src->v6);
        dl = argos_network_is_lan6(s, &dst->v6);
        routed = legacy_routed6(s, &src->v6, ifindex);
    }
    return (unsigned)((sl || dl || routed) + 2 * (sl || routed) + 4 * routed);
}

__attribute__((noinline))
static unsigned current(const argos_network_state_t *s, const endpoint_t *src,
                        const endpoint_t *dst, int family, int ifindex) {
    argos_network_packet_context_t out;
    int visible = family == 4 ? argos_network_context4(s, src->v4, dst->v4, ifindex, &out)
                             : argos_network_context6(s, &src->v6, &dst->v6, ifindex, &out);
    return (unsigned)(visible + 2 * out.source_side + 4 * out.routed);
}

static double now(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

int main(void) {
    argos_network_state_t s;
    argos_network_init(&s);
    endpoint_t endpoints[4];
    const char *v4[] = {"10.0.0.9", "10.1.0.9", "192.0.2.42", "8.8.8.8"};
    const char *v6[] = {"2001:db8:1234:1::2", "2001:db8:1234:2::2", "fd00::1", "2001:db8:9999::2"};
    for (unsigned i = 0; i < 4; ++i) {
        assert(inet_pton(AF_INET, v4[i], &endpoints[i].v4) == 1);
        assert(inet_pton(AF_INET6, v6[i], &endpoints[i].v6) == 1);
    }
    for (int count = 0; count <= ARGOS_NETWORK_MAX_PREFIXES; count += 32) {
        s.learned_count = count;
        for (int i = 0; i < count; ++i) {
            argos_network_prefix_t *p = &s.learned[i];
            memset(p, 0, sizeof(*p));
            p->ifindex = 7;
            p->family = i & 1 ? AF_INET : AF_INET6;
            p->v4 = htonl(0x0a000000U); p->v4mask = htonl(0xffffff00U);
            assert(inet_pton(AF_INET6, "2001:db8:1234:1::", &p->v6) == 1);
            memset(p->v6mask.s6_addr, 0xff, 8);
        }
        for (int family = 4; family <= 6; family += 2) {
            for (unsigned i = 0; i < 16; ++i)
                assert(legacy(&s, &endpoints[i & 3], &endpoints[i >> 2], family, 7) ==
                       current(&s, &endpoints[i & 3], &endpoints[i >> 2], family, 7));
            double times[2] = {0, 0};
            for (int round = 0; round < 4; ++round) for (int pass = 0; pass < 2; ++pass) {
                int which = (round + pass) & 1;
                unsigned sum = 0; double start = now();
                for (unsigned j = 0; j < 1000000U; ++j) {
                    const endpoint_t *src = &endpoints[j & 3], *dst = &endpoints[(j >> 2) & 3];
                    sum += which ? current(&s, src, dst, family, 7) : legacy(&s, src, dst, family, 7);
                }
                times[which] += now() - start; sink = sum;
            }
            printf("IPv%d prefixes=%d: legacy %.2f ns current %.2f ns ratio %.3f\n",
                   family, count, times[0] * 250.0, times[1] * 250.0, times[1] / times[0]);
        }
    }
    return 0;
}
