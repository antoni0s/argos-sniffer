#ifndef ARGOS_RTP_H
#define ARGOS_RTP_H

/* Argos-Sniffer v6 staging engine: RTP.
 * Parses only the fixed RTP header and stable media-flow identifiers.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t padding;
    uint8_t extension;
    uint8_t csrc_count;
    uint8_t marker;
    uint8_t payload_type;
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t ssrc;
    char detail[256];
} argos_rtp_result_t;

static inline uint16_t artp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t artp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline int argos_rtp_parse(const unsigned char *p, size_t n,
                                  argos_rtp_result_t *r) {
    if (!p || !r || n < 12U) return 0;
    memset(r, 0, sizeof(*r));

    r->version = (uint8_t)(p[0] >> 6);
    if (r->version != 2U) return 0;

    r->padding = (uint8_t)((p[0] >> 5) & 1U);
    r->extension = (uint8_t)((p[0] >> 4) & 1U);
    r->csrc_count = (uint8_t)(p[0] & 0x0fU);
    r->marker = (uint8_t)(p[1] >> 7);
    r->payload_type = (uint8_t)(p[1] & 0x7fU);
    r->sequence = artp_be16(p + 2);
    r->timestamp = artp_be32(p + 4);
    r->ssrc = artp_be32(p + 8);

    size_t base = 12U + ((size_t)r->csrc_count * 4U);
    if (base > n) return 0;

    (void)snprintf(r->detail, sizeof(r->detail),
                   "v=2;pt=%u;marker=%u;seq=%u;ts=%u;ssrc=0x%08x;csrc=%u;ext=%u;pad=%u",
                   (unsigned)r->payload_type, (unsigned)r->marker,
                   (unsigned)r->sequence, (unsigned)r->timestamp,
                   (unsigned)r->ssrc, (unsigned)r->csrc_count,
                   (unsigned)r->extension, (unsigned)r->padding);
    return 1;
}

#endif /* ARGOS_RTP_H */
