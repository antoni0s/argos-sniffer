#ifndef ARGOS_RIP_H
#define ARGOS_RIP_H

/* Argos-Sniffer v6 staging engine: RIP / RIPng.
 *
 * Standalone parser only. This header is intentionally not wired into the
 * v6 dispatcher, CLI flags, telemetry, deduplication or capture path yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    ARGOS_RIP_NONE = 0,
    ARGOS_RIP_V1 = 1,
    ARGOS_RIP_V2 = 2,
    ARGOS_RIP_NG = 3
} argos_rip_kind_t;

typedef struct {
    argos_rip_kind_t kind;
    uint8_t command;
    uint8_t version;
    uint16_t entry_count;
    uint32_t first_ipv4_prefix;
    uint32_t first_ipv4_mask;
    uint32_t first_ipv4_nexthop;
    uint32_t first_metric;
    uint16_t first_route_tag;
    unsigned char first_ipv6_prefix[16];
    uint8_t first_ipv6_prefix_len;
    char detail[512];
} argos_rip_result_t;

static inline uint16_t arip_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t arip_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void arip_ipv4(char out[16], uint32_t v) {
    (void)snprintf(out, 16, "%u.%u.%u.%u",
                   (unsigned)((v >> 24) & 0xffU),
                   (unsigned)((v >> 16) & 0xffU),
                   (unsigned)((v >> 8) & 0xffU),
                   (unsigned)(v & 0xffU));
}

static inline void arip_ipv6(char out[48], const unsigned char p[16]) {
    (void)snprintf(out, 48,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

/* RIPv1/RIPv2 payload, normally UDP/520.
 * Header: command, version, zero. Route entries are fixed 20-byte records.
 * Authentication entries are not emitted as fingerprints.
 */
static inline int argos_rip_parse(const unsigned char *p, size_t n,
                                  argos_rip_result_t *r) {
    if (!p || !r || n < 4U) return 0;
    memset(r, 0, sizeof(*r));

    if (p[0] != 1U && p[0] != 2U) return 0;
    if (p[1] != 1U && p[1] != 2U) return 0;
    if (p[2] != 0U || p[3] != 0U) return 0;
    if (((n - 4U) % 20U) != 0U) return 0;

    r->command = p[0];
    r->version = p[1];
    r->kind = p[1] == 1U ? ARGOS_RIP_V1 : ARGOS_RIP_V2;
    r->entry_count = (uint16_t)((n - 4U) / 20U);

    for (uint16_t i = 0U; i < r->entry_count; ++i) {
        const unsigned char *e = p + 4U + ((size_t)i * 20U);
        uint16_t afi = arip_be16(e);

        /* RIPv2 simple authentication uses AFI 0xffff. Skip it entirely. */
        if (afi == 0xffffU) continue;
        if (afi != 2U) continue;

        r->first_route_tag = arip_be16(e + 2);
        r->first_ipv4_prefix = arip_be32(e + 4);
        r->first_ipv4_mask = arip_be32(e + 8);
        r->first_ipv4_nexthop = arip_be32(e + 12);
        r->first_metric = arip_be32(e + 16);
        break;
    }

    char prefix[16], mask[16], nh[16];
    arip_ipv4(prefix, r->first_ipv4_prefix);
    arip_ipv4(mask, r->first_ipv4_mask);
    arip_ipv4(nh, r->first_ipv4_nexthop);

    (void)snprintf(r->detail, sizeof(r->detail),
        "kind=%s;command=%u;entries=%u;first_prefix=%s;mask=%s;nexthop=%s;tag=%u;metric=%u",
        r->kind == ARGOS_RIP_V1 ? "ripv1" : "ripv2",
        (unsigned)r->command,
        (unsigned)r->entry_count,
        prefix,
        mask,
        nh,
        (unsigned)r->first_route_tag,
        (unsigned)r->first_metric);

    return 1;
}

/* RIPng payload, normally UDP/521.
 * Header is command/version/zero/zero and entries are fixed 20-byte records:
 * IPv6 prefix(16), route tag(2), prefix length(1), metric(1).
 */
static inline int argos_ripng_parse(const unsigned char *p, size_t n,
                                    argos_rip_result_t *r) {
    if (!p || !r || n < 4U) return 0;
    memset(r, 0, sizeof(*r));

    if (p[0] != 1U && p[0] != 2U) return 0;
    if (p[1] != 1U) return 0;
    if (p[2] != 0U || p[3] != 0U) return 0;
    if (((n - 4U) % 20U) != 0U) return 0;

    r->kind = ARGOS_RIP_NG;
    r->command = p[0];
    r->version = p[1];
    r->entry_count = (uint16_t)((n - 4U) / 20U);

    if (r->entry_count > 0U) {
        const unsigned char *e = p + 4U;
        memcpy(r->first_ipv6_prefix, e, 16);
        r->first_route_tag = arip_be16(e + 16);
        r->first_ipv6_prefix_len = e[18];
        r->first_metric = e[19];
        if (r->first_ipv6_prefix_len > 128U) return 0;
    }

    char prefix[48];
    arip_ipv6(prefix, r->first_ipv6_prefix);
    (void)snprintf(r->detail, sizeof(r->detail),
        "kind=ripng;command=%u;entries=%u;first_prefix=%s/%u;tag=%u;metric=%u",
        (unsigned)r->command,
        (unsigned)r->entry_count,
        prefix,
        (unsigned)r->first_ipv6_prefix_len,
        (unsigned)r->first_route_tag,
        (unsigned)r->first_metric);

    return 1;
}

#endif /* ARGOS_RIP_H */
