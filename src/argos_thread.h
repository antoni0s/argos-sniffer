#ifndef ARGOS_THREAD_H
#define ARGOS_THREAD_H

/* Argos-Sniffer v6 staging engine: Thread.
 * Standalone parser only; no runtime integration yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t dispatch;
    uint8_t mesh_header;
    uint8_t hops_left;
    uint16_t src_short;
    uint16_t dst_short;
} argos_thread_result_t;

static inline uint16_t athread_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* Lightweight 6LoWPAN/Thread mesh-header fingerprint. */
static inline int argos_thread_parse(const unsigned char *p, size_t n,
                                     argos_thread_result_t *r) {
    if (!p || !r || n < 1U) return 0;
    memset(r, 0, sizeof(*r));

    r->dispatch = p[0];
    if ((p[0] & 0xc0U) != 0x80U) return 0; /* mesh header dispatch 10xxxxxx */
    r->mesh_header = 1U;
    r->hops_left = (uint8_t)(p[0] & 0x0fU);

    if (n >= 5U) {
        r->src_short = athread_be16(p + 1);
        r->dst_short = athread_be16(p + 3);
    }
    return 1;
}

#endif /* ARGOS_THREAD_H */
