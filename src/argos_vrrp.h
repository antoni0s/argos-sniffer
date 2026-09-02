#ifndef ARGOS_VRRP_H
#define ARGOS_VRRP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t vrid;
    uint8_t priority;
    uint8_t address_count;
    uint8_t auth_type;
    uint16_t advert_interval;
    uint8_t interval_unit_cs;
    uint8_t owner;
    uint8_t relinquish;
    char detail[256];
} argos_vrrp_result_t;

static inline uint16_t avrrp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* RFC 3768 VRRPv2 (IPv4) and RFC 5798 VRRPv3 (IPv4/IPv6).
 * Virtual IP addresses and v2 authentication data are intentionally not
 * emitted: VRID/priority/count/interval are sufficient HA fingerprints. */
static inline int argos_vrrp_parse(const unsigned char *p, size_t n,
                                   uint8_t ip_version,
                                   argos_vrrp_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));
    r->version = (uint8_t)(p[0] >> 4);
    r->type = (uint8_t)(p[0] & 0x0fU);
    if (r->type != 1U) return 0; /* Advertisement */
    r->vrid = p[1];
    r->priority = p[2];
    r->address_count = p[3];
    if (r->vrid == 0U || r->address_count == 0U) return 0;
    r->owner = (uint8_t)(r->priority == 255U);
    r->relinquish = (uint8_t)(r->priority == 0U);

    if (r->version == 2U) {
        if (ip_version != 4U) return 0;
        size_t need = 8U + (size_t)r->address_count * 4U + 8U;
        if (n < need) return 0;
        r->auth_type = p[4];
        r->advert_interval = p[5];
        r->interval_unit_cs = 0U;
        (void)snprintf(r->detail, sizeof(r->detail),
            "version=2;vrid=%u;priority=%u;count=%u;auth_type=%u;interval_s=%u;owner=%u;relinquish=%u",
            (unsigned)r->vrid, (unsigned)r->priority, (unsigned)r->address_count,
            (unsigned)r->auth_type, (unsigned)r->advert_interval,
            (unsigned)r->owner, (unsigned)r->relinquish);
        return 1;
    }

    if (r->version == 3U) {
        if (ip_version != 4U && ip_version != 6U) return 0;
        size_t addr_len = ip_version == 6U ? 16U : 4U;
        size_t need = 8U + (size_t)r->address_count * addr_len;
        if (n < need) return 0;
        uint16_t interval_word = avrrp_be16(p + 4);
        r->advert_interval = (uint16_t)(interval_word & 0x0fffU);
        r->interval_unit_cs = 1U;
        (void)snprintf(r->detail, sizeof(r->detail),
            "version=3;family=ipv%u;vrid=%u;priority=%u;count=%u;interval_cs=%u;owner=%u;relinquish=%u",
            (unsigned)ip_version, (unsigned)r->vrid, (unsigned)r->priority,
            (unsigned)r->address_count, (unsigned)r->advert_interval,
            (unsigned)r->owner, (unsigned)r->relinquish);
        return 1;
    }
    return 0;
}

#endif /* ARGOS_VRRP_H */
