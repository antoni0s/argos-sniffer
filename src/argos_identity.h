#ifndef ARGOS_IDENTITY_H
#define ARGOS_IDENTITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Optional identity evidence derived only from handshake/control fields that
 * Argos already inspects for protocol fingerprinting. This is not a generic
 * payload scanner. "Observed identity" is evidence, never device ownership.
 */
typedef struct {
    char protocol[24];
    char type[24];
    char value[192];
    uint32_t hash;
    uint16_t value_len;
    uint8_t present;
} argos_identity_result_t;

static inline uint32_t argos_identity_hash32(const unsigned char *p, size_t len) {
    uint32_t h = 2166136261U;
    if (!p) return 0U;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619U;
    }
    return h;
}

static inline size_t argos_identity_clean(const unsigned char *src, size_t len,
                                          char *dst, size_t cap) {
    size_t o = 0U;
    if (!dst || cap == 0U) return 0U;
    if (!src) { dst[0] = '\0'; return 0U; }
    for (size_t i = 0; i < len && o + 1U < cap; ++i) {
        unsigned char c = src[i];
        if (c >= 32U && c <= 126U) {
            dst[o++] = (c == '|' || c == '\\') ? '/' : (char)c;
        } else if (o > 0U && dst[o - 1U] != ' ') {
            dst[o++] = ' ';
        }
    }
    while (o > 0U && dst[o - 1U] == ' ') --o;
    dst[o] = '\0';
    return o;
}

static inline int argos_identity_build(argos_identity_result_t *r,
                                       const char *protocol, const char *type,
                                       const unsigned char *value, size_t len,
                                       int raw_mode) {
    if (!r) return 0;
    memset(r, 0, sizeof(*r));
    if (!protocol || !type || !value || len == 0U) return 0;
    if (len > 160U) len = 160U;
    snprintf(r->protocol, sizeof(r->protocol), "%s", protocol);
    snprintf(r->type, sizeof(r->type), "%s", type);
    r->hash = argos_identity_hash32(value, len);
    r->value_len = (uint16_t)len;
    r->present = 1U;
    if (raw_mode)
        argos_identity_clean(value, len, r->value, sizeof(r->value));
    else
        snprintf(r->value, sizeof(r->value), "hash=%08x,len=%u",
                 r->hash, (unsigned)r->value_len);
    return 1;
}


/* RDP identity evidence is limited to the mstshash cookie carried in the
 * initial X.224 Connection Request. It is a user/login hint, not proof of an
 * authenticated principal and never device ownership. No stream scan occurs:
 * only the already-inspected initial RDP handshake payload is considered. */
static inline int argos_identity_rdp_mstshash(const unsigned char *p, size_t len,
                                              int raw_mode,
                                              argos_identity_result_t *r) {
    static const unsigned char prefix[] = "Cookie: mstshash=";
    if (!p || !r || len < 11U || p[0] != 0x03U || p[1] != 0x00U || p[5] != 0xe0U)
        return 0;

    const size_t prefix_len = sizeof(prefix) - 1U;
    const unsigned char *c = NULL;
    for (size_t i = 0; i + prefix_len <= len; ++i) {
        int match = 1;
        for (size_t j = 0; j < prefix_len; ++j) {
            unsigned char a = p[i + j], b = prefix[j];
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b) { match = 0; break; }
        }
        if (match) { c = p + i + prefix_len; break; }
    }
    if (!c || c >= p + len) return 0;

    const unsigned char *end = NULL;
    for (const unsigned char *q = c; q + 1 < p + len; ++q) {
        if (q[0] == '\r' && q[1] == '\n') { end = q; break; }
    }
    if (!end || end <= c) return 0;
    size_t n = (size_t)(end - c);
    if (n > 120U) n = 120U;
    return argos_identity_build(r, "rdp", "mstshash", c, n, raw_mode);
}

#endif
