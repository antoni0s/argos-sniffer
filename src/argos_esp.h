#ifndef ARGOS_ESP_H
#define ARGOS_ESP_H

/* Argos-Sniffer v6 staging engine: IPsec ESP.
 * Standalone fixed-header parser only; encrypted payload is never inspected.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t spi;
    uint32_t sequence;
} argos_esp_result_t;

static inline uint32_t aesp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* RFC 4303 ESP fixed header: SPI + Sequence Number. */
static inline int argos_esp_parse(const unsigned char *p, size_t n,
                                  argos_esp_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));
    r->spi = aesp_be32(p);
    r->sequence = aesp_be32(p + 4);
    if (r->spi == 0U) return 0;
    return 1;
}

#endif /* ARGOS_ESP_H */
