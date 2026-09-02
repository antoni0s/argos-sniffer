#ifndef ARGOS_TLS_SERVER_H
#define ARGOS_TLS_SERVER_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char version[3];
    uint16_t cipher;
    uint8_t extension_count;
    char alpn[32];
    uint64_t extension_signature;
    char fingerprint[96];
} argos_tls_server_result_t;

static inline uint16_t ats_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int ats_grease(uint16_t v) {
    return (v & 0x0f0fU) == 0x0a0aU && ((v >> 8) & 0xffU) == (v & 0xffU);
}

static inline const char *ats_version_code(uint16_t v) {
    switch (v) {
        case 0x0304U: return "13";
        case 0x0303U: return "12";
        case 0x0302U: return "11";
        case 0x0301U: return "10";
        default: return "00";
    }
}

static inline uint64_t ats_fnv_type(uint64_t h, uint16_t type) {
    const unsigned char b[2] = {(unsigned char)(type >> 8), (unsigned char)type};
    for (size_t i = 0; i < 2U; ++i) {
        h ^= (uint64_t)b[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static inline void ats_alpn_code(const unsigned char *p, size_t n, char out[32]) {
    strcpy(out, "none");
    if (!p || n < 3U) return;
    size_t list_len = ats_be16(p);
    if (list_len + 2U > n || list_len < 1U) return;
    size_t plen = p[2];
    if (plen == 0U || plen + 3U > n) return;
    size_t keep = plen < 31U ? plen : 31U;
    for (size_t i = 0; i < keep; ++i) {
        unsigned char c = p[3U + i];
        out[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|') ? c : '.');
    }
    out[keep] = '\0';
}

/* Argos TLS Server v1 (ats1) is intentionally NOT JA4S. It is an independent,
 * low-cost ServerHello fingerprint: negotiated version, selected cipher,
 * non-GREASE extension count/order signature, and visible ALPN. */
static inline int argos_tls_server_parse(const unsigned char *p, size_t n,
                                         argos_tls_server_result_t *out) {
    if (!p || !out || n < 49U) return 0;
    memset(out, 0, sizeof(*out));
    strcpy(out->alpn, "none");

    if (p[0] != 0x16U || p[5] != 0x02U) return 0; /* handshake / ServerHello */
    size_t record_len = ats_be16(p + 3);
    if (record_len < 44U || record_len + 5U > n) return 0;
    size_t hs_len = ((size_t)p[6] << 16) | ((size_t)p[7] << 8) | (size_t)p[8];
    if (hs_len < 40U || hs_len + 9U > n || hs_len + 4U > record_len) return 0;

    size_t end = 9U + hs_len;
    uint16_t negotiated = ats_be16(p + 9);
    size_t pos = 9U + 2U + 32U;
    if (pos >= end) return 0;
    size_t sid_len = p[pos++];
    if (sid_len > 32U || pos + sid_len + 3U > end) return 0;
    pos += sid_len;
    out->cipher = ats_be16(p + pos); pos += 2U;
    pos += 1U; /* compression */

    uint64_t ext_sig = UINT64_C(1469598103934665603);
    unsigned ext_count = 0U;
    if (pos < end) {
        if (pos + 2U > end) return 0;
        size_t ext_total = ats_be16(p + pos); pos += 2U;
        if (pos + ext_total > end) return 0;
        size_t ext_end = pos + ext_total;
        while (pos + 4U <= ext_end) {
            uint16_t type = ats_be16(p + pos);
            size_t elen = ats_be16(p + pos + 2U);
            pos += 4U;
            if (pos + elen > ext_end) return 0;
            if (!ats_grease(type)) {
                if (ext_count < 99U) ++ext_count;
                ext_sig = ats_fnv_type(ext_sig, type);
            }
            if (type == 0x002bU && elen == 2U) negotiated = ats_be16(p + pos);
            if (type == 0x0010U) ats_alpn_code(p + pos, elen, out->alpn);
            pos += elen;
        }
        if (pos != ext_end) return 0;
    }

    snprintf(out->version, sizeof(out->version), "%s", ats_version_code(negotiated));
    out->extension_count = (uint8_t)ext_count;
    out->extension_signature = ext_sig;
    snprintf(out->fingerprint, sizeof(out->fingerprint),
             "ats1_%s_%04x_%02u_%s_%016llx",
             out->version, (unsigned)out->cipher, ext_count, out->alpn,
             (unsigned long long)ext_sig);
    return 1;
}

#endif /* ARGOS_TLS_SERVER_H */
