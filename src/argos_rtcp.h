#ifndef ARGOS_RTCP_H
#define ARGOS_RTCP_H

/* Argos-Sniffer v6 staging engine: RTCP.
 * Parses RTCP common headers and lightweight SDES/CNAME identity hints.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t padding;
    uint8_t report_count;
    uint8_t packet_type;
    uint16_t length_words;
    uint32_t ssrc;
    char cname[128];
    char detail[320];
} argos_rtcp_result_t;

static inline uint16_t artcp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t artcp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline int argos_rtcp_parse(const unsigned char *p, size_t n,
                                   argos_rtcp_result_t *r) {
    if (!p || !r || n < 4U) return 0;
    memset(r, 0, sizeof(*r));

    r->version = (uint8_t)(p[0] >> 6);
    if (r->version != 2U) return 0;

    r->padding = (uint8_t)((p[0] >> 5) & 1U);
    r->report_count = (uint8_t)(p[0] & 0x1fU);
    r->packet_type = p[1];
    r->length_words = artcp_be16(p + 2);

    size_t packet_len = ((size_t)r->length_words + 1U) * 4U;
    if (packet_len > n || packet_len < 4U) return 0;

    if (packet_len >= 8U &&
        (r->packet_type == 200U || r->packet_type == 201U ||
         r->packet_type == 202U || r->packet_type == 203U ||
         r->packet_type == 204U)) {
        r->ssrc = artcp_be32(p + 4);
    }

    if (r->packet_type == 202U && packet_len >= 10U) {
        size_t pos = 8U;
        while (pos + 2U <= packet_len) {
            uint8_t item_type = p[pos++];
            if (item_type == 0U) break;
            uint8_t item_len = p[pos++];
            if ((size_t)item_len > packet_len - pos) break;
            if (item_type == 1U && !r->cname[0]) {
                size_t take = item_len < sizeof(r->cname) - 1U ? item_len : sizeof(r->cname) - 1U;
                for (size_t i = 0U; i < take; ++i) {
                    unsigned char c = p[pos + i];
                    r->cname[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
                }
                r->cname[take] = '\0';
            }
            pos += item_len;
        }
    }

    (void)snprintf(r->detail, sizeof(r->detail),
                   "v=2;pt=%u;rc=%u;len=%u;ssrc=0x%08x%s%s",
                   (unsigned)r->packet_type, (unsigned)r->report_count,
                   (unsigned)packet_len, (unsigned)r->ssrc,
                   r->cname[0] ? ";cname=" : "",
                   r->cname[0] ? r->cname : "");
    return 1;
}

#endif /* ARGOS_RTCP_H */
