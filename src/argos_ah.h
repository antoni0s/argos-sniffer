#ifndef ARGOS_AH_H
#define ARGOS_AH_H

/* Argos-Sniffer v6 staging engine: IPsec AH.
 * Standalone fixed-header parser only; no runtime wiring yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t next_header;
    uint8_t payload_len;
    uint32_t spi;
    uint32_t sequence;
} argos_ah_result_t;

static inline uint32_t aah_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* RFC 4302 AH fixed header. payload_len is measured in 32-bit words minus 2. */
static inline int argos_ah_parse(const unsigned char *p, size_t n,
                                 argos_ah_result_t *r) {
    if (!p || !r || n < 12U) return 0;
    memset(r, 0, sizeof(*r));

    r->next_header = p[0];
    r->payload_len = p[1];
    r->spi = aah_be32(p + 4);
    r->sequence = aah_be32(p + 8);

    size_t header_len = ((size_t)r->payload_len + 2U) * 4U;
    if (header_len < 12U || header_len > n) return 0;
    if (r->spi == 0U) return 0;
    return 1;
}

#endif /* ARGOS_AH_H */
