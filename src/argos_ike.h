#ifndef ARGOS_IKE_H
#define ARGOS_IKE_H

/* Argos-Sniffer v6 staging engine: IKE / IKEv2.
 * Standalone parser only; no CLI, dispatcher, telemetry or BPF wiring yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t initiator_spi;
    uint64_t responder_spi;
    uint8_t next_payload;
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
} argos_ike_result_t;

static inline uint32_t aike_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t aike_be64(const unsigned char *p) {
    return ((uint64_t)aike_be32(p) << 32) | (uint64_t)aike_be32(p + 4);
}

/* RFC 7296 fixed 28-byte IKE header. Also accepts IKEv1 major version 1. */
static inline int argos_ike_parse(const unsigned char *p, size_t n,
                                  argos_ike_result_t *r) {
    if (!p || !r || n < 28U) return 0;
    memset(r, 0, sizeof(*r));

    r->initiator_spi = aike_be64(p);
    r->responder_spi = aike_be64(p + 8);
    r->next_payload = p[16];
    r->version_major = (uint8_t)(p[17] >> 4);
    r->version_minor = (uint8_t)(p[17] & 0x0fU);
    r->exchange_type = p[18];
    r->flags = p[19];
    r->message_id = aike_be32(p + 20);
    r->length = aike_be32(p + 24);

    if (r->version_major != 1U && r->version_major != 2U) return 0;
    if (r->length < 28U || r->length > n) return 0;
    return 1;
}

#endif /* ARGOS_IKE_H */
