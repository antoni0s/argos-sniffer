#ifndef ARGOS_NVMEOF_H
#define ARGOS_NVMEOF_H

/* Argos-Sniffer v6 staging engine: NVMe over Fabrics.
 * Passive identification only; not wired into CLI/runtime yet.
 * Focuses on NVMe/TCP common PDU headers and ICReq/ICResp negotiation.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    uint8_t pdu_type;
    uint8_t flags;
    uint8_t hlen;
    uint32_t plen;
    uint16_t pfv;
    uint32_t maxh2cdata;
    uint8_t hpda;
    uint8_t cpda;
    uint8_t digest;
    char detail[256];
} argos_nvmeof_result_t;

static inline uint16_t anv_le16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t anv_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline int argos_nvmeof_parse(const unsigned char *p, size_t n,
                                     argos_nvmeof_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r,0,sizeof(*r));

    r->pdu_type=p[0]; r->flags=p[1]; r->hlen=p[2]; r->plen=anv_le32(p+4);
    if (r->hlen < 8U || r->plen < r->hlen) return 0;

    switch (r->pdu_type) {
        case 0x00U: /* ICReq */
            if (n < 16U || r->hlen < 16U) return 0;
            r->pfv=anv_le16(p+8);
            r->hpda=p[10];
            r->digest=p[11];
            r->maxh2cdata=anv_le32(p+12);
            r->seen=1;
            break;
        case 0x01U: /* ICResp */
            if (n < 16U || r->hlen < 16U) return 0;
            r->pfv=anv_le16(p+8);
            r->cpda=p[10];
            r->digest=p[11];
            r->maxh2cdata=anv_le32(p+12);
            r->seen=1;
            break;
        case 0x04U: case 0x05U: case 0x06U: case 0x07U:
            r->seen=1; /* capsule/data PDUs: fingerprint type only */
            break;
        default:
            return 0;
    }

    (void)snprintf(r->detail,sizeof(r->detail),
                   "type=0x%02x;flags=0x%02x;hlen=%u;plen=%u;pfv=%u;hpda=%u;cpda=%u;digest=0x%02x;maxh2cdata=%u",
                   (unsigned)r->pdu_type,(unsigned)r->flags,(unsigned)r->hlen,(unsigned)r->plen,
                   (unsigned)r->pfv,(unsigned)r->hpda,(unsigned)r->cpda,(unsigned)r->digest,
                   (unsigned)r->maxh2cdata);
    return 1;
}

#endif /* ARGOS_NVMEOF_H */
