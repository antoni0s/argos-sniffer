#ifndef ARGOS_LLDP_MED_H
#define ARGOS_LLDP_MED_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int have_capabilities;
    uint16_t capabilities;
    uint8_t device_class;
    int have_policy;
    uint8_t app_type;
    uint8_t policy_unknown;
    uint8_t policy_tagged;
    uint16_t vlan;
    uint8_t priority;
    uint8_t dscp;
    char hardware[64];
    char firmware[64];
    char software[64];
    char serial[64];
    char manufacturer[96];
    char model[96];
    char asset[64];
    char detail[640];
} argos_lldp_med_result_t;

static inline uint16_t alm_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t alm_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void alm_text(const unsigned char *p, size_t n, char *out, size_t cap) {
    if (!out || cap == 0U) return;
    size_t take = n < cap - 1U ? n : cap - 1U;
    for (size_t i = 0; i < take; ++i) {
        unsigned char c = p[i];
        out[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
    }
    while (take > 0U && out[take - 1U] == ' ') --take;
    out[take] = '\0';
}
static inline const char *alm_class(uint8_t v) {
    switch (v) {
        case 1: return "endpoint1";
        case 2: return "endpoint2";
        case 3: return "endpoint3";
        case 4: return "network";
        default: return "unknown";
    }
}
static inline const char *alm_app(uint8_t v) {
    switch (v) {
        case 1: return "voice";
        case 2: return "voice-signaling";
        case 3: return "guest-voice";
        case 4: return "guest-voice-signaling";
        case 5: return "softphone-voice";
        case 6: return "video-conferencing";
        case 7: return "streaming-video";
        case 8: return "video-signaling";
        default: return "reserved";
    }
}
static inline void alm_append(char *out, size_t cap, const char *key, const char *value) {
    if (!out || !key || !value || !value[0] || cap == 0U) return;
    size_t used = strlen(out);
    if (used >= cap - 1U) return;
    (void)snprintf(out + used, cap - used, "%s%s=%s", used ? ";" : "", key, value);
}

/* ANSI/TIA-1057 LLDP-MED organizational TLVs use OUI 00-12-BB. Location
 * Identification (subtype 3) is deliberately ignored: Argos fingerprints
 * equipment and policy, not physical/civic location. Power TLV subtype 4 is
 * likewise left for a later PoE-specific vector. */
static inline int argos_lldp_med_parse(const unsigned char *p, size_t n,
                                       argos_lldp_med_result_t *r) {
    if (!p || !r) return 0;
    memset(r, 0, sizeof(*r));
    size_t pos = 0U;
    while (pos + 2U <= n) {
        uint16_t h = alm_be16(p + pos); pos += 2U;
        unsigned type = h >> 9;
        size_t len = h & 0x01ffU;
        if (type == 0U) break;
        if (len > n - pos) return 0;
        if (type == 127U && len >= 4U &&
            p[pos] == 0x00U && p[pos + 1U] == 0x12U && p[pos + 2U] == 0xbbU) {
            uint8_t subtype = p[pos + 3U];
            const unsigned char *v = p + pos + 4U;
            size_t vlen = len - 4U;
            if (subtype == 1U && vlen >= 3U) {
                r->seen = 1; r->have_capabilities = 1;
                r->capabilities = alm_be16(v);
                r->device_class = v[2];
            } else if (subtype == 2U && vlen == 4U && !r->have_policy) {
                uint32_t w = alm_be32(v);
                r->seen = 1; r->have_policy = 1;
                r->app_type = (uint8_t)(w >> 24);
                r->policy_unknown = (uint8_t)((w >> 23) & 1U);
                r->policy_tagged = (uint8_t)((w >> 22) & 1U);
                r->vlan = (uint16_t)((w >> 9) & 0x0fffU);
                r->priority = (uint8_t)((w >> 6) & 0x07U);
                r->dscp = (uint8_t)(w & 0x3fU);
            } else if (subtype >= 5U && subtype <= 11U && vlen > 0U) {
                r->seen = 1;
                char *dst = subtype == 5U ? r->hardware : subtype == 6U ? r->firmware :
                            subtype == 7U ? r->software : subtype == 8U ? r->serial :
                            subtype == 9U ? r->manufacturer : subtype == 10U ? r->model : r->asset;
                size_t cap = subtype == 9U || subtype == 10U ? 96U : 64U;
                if (!dst[0]) alm_text(v, vlen, dst, cap);
            }
        }
        pos += len;
    }
    if (!r->seen) return 0;

    char tmp[160];
    if (r->have_capabilities) {
        snprintf(tmp, sizeof(tmp), "%s", alm_class(r->device_class));
        alm_append(r->detail, sizeof(r->detail), "class", tmp);
        snprintf(tmp, sizeof(tmp), "0x%04x", (unsigned)r->capabilities);
        alm_append(r->detail, sizeof(r->detail), "caps", tmp);
    }
    if (r->have_policy) {
        snprintf(tmp, sizeof(tmp), "%s,%s,%s,vlan=%u,prio=%u,dscp=%u",
                 alm_app(r->app_type), r->policy_unknown ? "unknown" : "defined",
                 r->policy_tagged ? "tagged" : "untagged", (unsigned)r->vlan,
                 (unsigned)r->priority, (unsigned)r->dscp);
        alm_append(r->detail, sizeof(r->detail), "policy", tmp);
    }
    alm_append(r->detail, sizeof(r->detail), "manufacturer", r->manufacturer);
    alm_append(r->detail, sizeof(r->detail), "model", r->model);
    alm_append(r->detail, sizeof(r->detail), "hardware", r->hardware);
    alm_append(r->detail, sizeof(r->detail), "firmware", r->firmware);
    alm_append(r->detail, sizeof(r->detail), "software", r->software);
    alm_append(r->detail, sizeof(r->detail), "serial", r->serial);
    alm_append(r->detail, sizeof(r->detail), "asset", r->asset);
    return r->detail[0] != '\0';
}

#endif /* ARGOS_LLDP_MED_H */
