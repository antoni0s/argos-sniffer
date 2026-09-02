#ifndef ARGOS_STP_H
#define ARGOS_STP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint16_t root_priority;
    unsigned char root_mac[6];
    uint32_t root_cost;
    uint16_t bridge_priority;
    unsigned char bridge_mac[6];
    uint16_t port_id;
    uint16_t message_age;
    uint16_t max_age;
    uint16_t hello_time;
    uint16_t forward_delay;
    char detail[512];
} argos_stp_result_t;

static inline uint16_t astp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t astp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void astp_mac(char out[18], const unsigned char mac[6]) {
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Classic IEEE 802.1D BPDU over 802.3 LLC: DSAP=0x42, SSAP=0x42, UI=0x03.
 * Version 0 is intentionally handled here; RSTP/MSTP are separate gates. */
static inline int argos_stp_parse(const unsigned char *p, size_t n,
                                  argos_stp_result_t *r) {
    if (!p || !r || n < 7U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x42U || p[1] != 0x42U || p[2] != 0x03U) return 0;
    if (p[3] != 0x00U || p[4] != 0x00U) return 0; /* protocol id */
    r->version = p[5];
    r->type = p[6];
    if (r->version != 0U) return 0;

    if (r->type == 0x80U) {
        (void)snprintf(r->detail, sizeof(r->detail), "version=0;type=tcn");
        return 1;
    }
    if (r->type != 0x00U || n < 38U) return 0;

    r->flags = p[7];
    r->root_priority = astp_be16(p + 8);
    memcpy(r->root_mac, p + 10, 6);
    r->root_cost = astp_be32(p + 16);
    r->bridge_priority = astp_be16(p + 20);
    memcpy(r->bridge_mac, p + 22, 6);
    r->port_id = astp_be16(p + 28);
    r->message_age = astp_be16(p + 30);
    r->max_age = astp_be16(p + 32);
    r->hello_time = astp_be16(p + 34);
    r->forward_delay = astp_be16(p + 36);

    char root[18], bridge[18];
    astp_mac(root, r->root_mac);
    astp_mac(bridge, r->bridge_mac);
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=0;type=config;flags=0x%02x;root_prio=%u;root=%s;cost=%u;"
        "bridge_prio=%u;bridge=%s;port=0x%04x;age=%u;max=%u;hello=%u;fwd=%u",
        (unsigned)r->flags, (unsigned)r->root_priority, root, (unsigned)r->root_cost,
        (unsigned)r->bridge_priority, bridge, (unsigned)r->port_id,
        (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
}

#endif /* ARGOS_STP_H */
