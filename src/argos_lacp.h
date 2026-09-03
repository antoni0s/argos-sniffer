#ifndef ARGOS_LACP_H
#define ARGOS_LACP_H

/* Argos-Sniffer v6 staging engine: LACP.
 *
 * Standalone parser only. This header is intentionally not wired into the
 * v6 dispatcher, CLI flags, telemetry, deduplication or capture path yet.
 * Integration will replace the corresponding embedded implementation in
 * argos_l2.h in a later step.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint16_t actor_system_priority;
    unsigned char actor_system[6];
    uint16_t actor_key;
    uint16_t actor_port_priority;
    uint16_t actor_port;
    uint8_t actor_state;
    uint16_t partner_system_priority;
    unsigned char partner_system[6];
    uint16_t partner_key;
    uint16_t partner_port_priority;
    uint16_t partner_port;
    uint8_t partner_state;
    char detail[512];
} argos_lacp_result_t;

static inline uint16_t alacp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void alacp_mac(char out[18], const unsigned char mac[6]) {
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline void alacp_state_add(char out[80], size_t *used,
                                   const char *name) {
    if (!out || !used || !name || *used >= 79U) return;

    if (*used != 0U && *used < 79U) out[(*used)++] = ',';
    size_t room = 79U - *used;
    size_t n = strlen(name);
    if (n > room) n = room;
    if (n > 0U) memcpy(out + *used, name, n);
    *used += n;
    out[*used] = '\0';
}

static inline void alacp_state(char out[80], uint8_t s) {
    size_t used = 0U;
    out[0] = '\0';

    if (s & 0x01U) alacp_state_add(out, &used, "active");
    if (s & 0x02U) alacp_state_add(out, &used, "short");
    if (s & 0x04U) alacp_state_add(out, &used, "agg");
    if (s & 0x08U) alacp_state_add(out, &used, "sync");
    if (s & 0x10U) alacp_state_add(out, &used, "collect");
    if (s & 0x20U) alacp_state_add(out, &used, "dist");
    if (s & 0x40U) alacp_state_add(out, &used, "defaulted");
    if (s & 0x80U) alacp_state_add(out, &used, "expired");
    if (!out[0]) (void)strcpy(out, "none");
}

/* IEEE 802.1AX LACPDU carried by Slow Protocols EtherType 0x8809.
 * Expected payload layout:
 *   Subtype=0x01, Version, Actor TLV(type=1,len=20),
 *   Partner TLV(type=2,len=20).
 *
 * Only fixed actor/partner control-plane identity and state are retained.
 */
static inline int argos_lacp_parse(const unsigned char *p, size_t n,
                                   argos_lacp_result_t *r) {
    if (!p || !r || n < 42U) return 0;
    memset(r, 0, sizeof(*r));

    if (p[0] != 0x01U) return 0;
    if (p[1] != 0x01U && p[1] != 0x02U) return 0;
    if (p[2] != 0x01U || p[3] != 0x14U) return 0;
    if (p[22] != 0x02U || p[23] != 0x14U) return 0;

    r->version = p[1];

    r->actor_system_priority = alacp_be16(p + 4);
    memcpy(r->actor_system, p + 6, 6);
    r->actor_key = alacp_be16(p + 12);
    r->actor_port_priority = alacp_be16(p + 14);
    r->actor_port = alacp_be16(p + 16);
    r->actor_state = p[18];

    r->partner_system_priority = alacp_be16(p + 24);
    memcpy(r->partner_system, p + 26, 6);
    r->partner_key = alacp_be16(p + 32);
    r->partner_port_priority = alacp_be16(p + 34);
    r->partner_port = alacp_be16(p + 36);
    r->partner_state = p[38];

    char actor_mac[18];
    char partner_mac[18];
    char actor_state[80];
    char partner_state[80];

    alacp_mac(actor_mac, r->actor_system);
    alacp_mac(partner_mac, r->partner_system);
    alacp_state(actor_state, r->actor_state);
    alacp_state(partner_state, r->partner_state);

    (void)snprintf(
        r->detail, sizeof(r->detail),
        "v=%u;actor=%s;sys_prio=%u;key=%u;port_prio=%u;port=%u;state=0x%02x(%s);"
        "partner=%s;partner_prio=%u;partner_key=%u;partner_port_prio=%u;partner_port=%u;partner_state=0x%02x(%s)",
        (unsigned)r->version,
        actor_mac,
        (unsigned)r->actor_system_priority,
        (unsigned)r->actor_key,
        (unsigned)r->actor_port_priority,
        (unsigned)r->actor_port,
        (unsigned)r->actor_state,
        actor_state,
        partner_mac,
        (unsigned)r->partner_system_priority,
        (unsigned)r->partner_key,
        (unsigned)r->partner_port_priority,
        (unsigned)r->partner_port,
        (unsigned)r->partner_state,
        partner_state);

    return 1;
}

#endif /* ARGOS_LACP_H */
