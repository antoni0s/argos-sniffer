#ifndef ARGOS_HSRP_H
#define ARGOS_HSRP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t wire_version;
    uint8_t opcode;
    uint8_t state;
    uint8_t hello_time;
    uint8_t hold_time;
    uint8_t priority;
    uint8_t group;
    uint8_t auth_nonzero;
    char detail[256];
} argos_hsrp1_result_t;

static inline const char *ahsrp_opcode(uint8_t v) {
    return v==0U ? "hello" : v==1U ? "coup" : v==2U ? "resign" : "unknown";
}
static inline const char *ahsrp_state(uint8_t v) {
    switch(v) {
        case 0U: return "initial"; case 1U: return "learn"; case 2U: return "listen";
        case 4U: return "speak"; case 8U: return "standby"; case 16U: return "active";
        default: return "unknown";
    }
}

/* Classic HSRP (commonly called HSRPv1) uses wire Version=0 and a fixed
 * 20-byte UDP/1985 payload. The 8-byte cleartext authentication field and
 * virtual IPv4 address are deliberately not emitted. */
static inline int argos_hsrp1_parse(const unsigned char *p, size_t n,
                                    argos_hsrp1_result_t *r) {
    if (!p || !r || n < 20U) return 0;
    memset(r,0,sizeof(*r));
    if (p[0] != 0U || p[1] > 2U) return 0;
    r->wire_version=p[0]; r->opcode=p[1]; r->state=p[2];
    r->hello_time=p[3]; r->hold_time=p[4]; r->priority=p[5]; r->group=p[6];
    for (size_t i=8U;i<16U;i++) if (p[i] != 0U) { r->auth_nonzero=1U; break; }
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=1;wire_version=0;opcode=%s;state=%s;hello_s=%u;hold_s=%u;priority=%u;group=%u;auth_present=%u",
        ahsrp_opcode(r->opcode), ahsrp_state(r->state), (unsigned)r->hello_time,
        (unsigned)r->hold_time, (unsigned)r->priority, (unsigned)r->group,
        (unsigned)r->auth_nonzero);
    return 1;
}


typedef struct {
    uint8_t wire_version;
    uint8_t opcode;
    uint8_t state;
    uint8_t ip_version;
    uint16_t group;
    uint32_t priority;
    uint32_t hello_ms;
    uint32_t hold_ms;
    uint8_t identifier[6];
    uint8_t extra_tlvs;
    char detail[320];
} argos_hsrp2_result_t;

static inline uint16_t ahsrp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t ahsrp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* HSRPv2 uses a TLV payload on UDP/1985. The Group State TLV is type 1,
 * length 40 and carries version/opcode/state/IP-version/group, a six-byte
 * sender identifier, 32-bit priority and millisecond timers. Virtual IP and
 * any following authentication TLVs are intentionally never emitted. */
static inline int argos_hsrp2_parse(const unsigned char *p, size_t n,
                                    argos_hsrp2_result_t *r) {
    if (!p || !r || n < 42U) return 0;
    memset(r, 0, sizeof(*r));

    size_t pos = 0U;
    while (pos + 2U <= n) {
        uint8_t type = p[pos];
        uint8_t len = p[pos + 1U];
        size_t end = pos + 2U + (size_t)len;
        if (end > n) return 0;

        if (type == 1U && len == 40U) {
            const unsigned char *v = p + pos + 2U;
            if (v[0] != 2U || v[1] > 2U) return 0;
            if (v[3] != 4U && v[3] != 6U) return 0;
            uint16_t group = ahsrp_be16(v + 4U);
            if (group > 4095U) return 0;

            r->wire_version = v[0];
            r->opcode = v[1];
            r->state = v[2];
            r->ip_version = v[3];
            r->group = group;
            memcpy(r->identifier, v + 6U, 6U);
            r->priority = ahsrp_be32(v + 12U);
            r->hello_ms = ahsrp_be32(v + 16U);
            r->hold_ms = ahsrp_be32(v + 20U);

            size_t scan = end;
            while (scan + 2U <= n) {
                uint8_t slen = p[scan + 1U];
                size_t send = scan + 2U + (size_t)slen;
                if (send > n) return 0;
                if (r->extra_tlvs != 255U) r->extra_tlvs++;
                scan = send;
            }
            if (scan != n) return 0;

            (void)snprintf(r->detail, sizeof(r->detail),
                "version=2;opcode=%s;state=%s;ip_version=%u;group=%u;priority=%u;hello_ms=%u;hold_ms=%u;id=%02x%02x%02x%02x%02x%02x;extra_tlvs=%u",
                ahsrp_opcode(r->opcode), ahsrp_state(r->state), (unsigned)r->ip_version,
                (unsigned)r->group, (unsigned)r->priority, (unsigned)r->hello_ms,
                (unsigned)r->hold_ms, r->identifier[0], r->identifier[1],
                r->identifier[2], r->identifier[3], r->identifier[4], r->identifier[5],
                (unsigned)r->extra_tlvs);
            return 1;
        }
        pos = end;
    }
    return 0;
}

#endif /* ARGOS_HSRP_H */
