#ifndef ARGOS_CAST_H
#define ARGOS_CAST_H

/* Argos-Sniffer v6 staging engine: Google Cast.
 * Lightweight passive signature parser for Cast V2 transport metadata.
 * No protobuf decoding or runtime wiring yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t frame_length;
    int likely_cast;
    char namespace_hint[128];
    char detail[256];
} argos_cast_result_t;

static inline uint32_t acast_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline int acast_contains(const unsigned char *p, size_t n, const char *s) {
    size_t m = strlen(s);
    if (!p || !s || m == 0U || n < m) return 0;
    for (size_t i = 0U; i + m <= n; ++i) {
        if (memcmp(p + i, s, m) == 0) return 1;
    }
    return 0;
}

static inline int argos_cast_parse(const unsigned char *p, size_t n,
                                   argos_cast_result_t *r) {
    if (!p || !r || n < 5U) return 0;
    memset(r, 0, sizeof(*r));

    r->frame_length = acast_be32(p);
    if (r->frame_length == 0U || (size_t)r->frame_length > n - 4U) return 0;

    const unsigned char *msg = p + 4;
    size_t msg_len = r->frame_length;

    const char *known[] = {
        "urn:x-cast:com.google.cast.tp.connection",
        "urn:x-cast:com.google.cast.tp.heartbeat",
        "urn:x-cast:com.google.cast.receiver",
        "urn:x-cast:com.google.cast.media"
    };

    for (size_t k = 0U; k < sizeof(known)/sizeof(known[0]); ++k) {
        if (acast_contains(msg, msg_len, known[k])) {
            r->likely_cast = 1;
            (void)snprintf(r->namespace_hint, sizeof(r->namespace_hint), "%s", known[k]);
            break;
        }
    }

    if (!r->likely_cast &&
        (acast_contains(msg, msg_len, "CASTV2") ||
         acast_contains(msg, msg_len, "urn:x-cast:"))) {
        r->likely_cast = 1;
    }

    if (!r->likely_cast) return 0;

    (void)snprintf(r->detail, sizeof(r->detail),
                   "frame=%u%s%s",
                   (unsigned)r->frame_length,
                   r->namespace_hint[0] ? ";namespace=" : "",
                   r->namespace_hint[0] ? r->namespace_hint : "");
    return 1;
}

#endif /* ARGOS_CAST_H */
