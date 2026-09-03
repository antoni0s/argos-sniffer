#ifndef ARGOS_MATTER_H
#define ARGOS_MATTER_H

/* Argos-Sniffer v6 staging engine: Matter.
 * Standalone parser only; not wired into CLI, dispatcher, telemetry or BPF.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint16_t exchange_id;
    uint16_t protocol_id;
    uint8_t opcode;
    char detail[160];
} argos_matter_result_t;

static inline uint16_t amatter_le16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Lightweight fingerprint of Matter secure-channel/application message headers.
 * This intentionally avoids payload semantics and keeps only stable framing data.
 */
static inline int argos_matter_parse(const unsigned char *p, size_t n,
                                     argos_matter_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));

    r->flags = p[0];
    r->version = (uint8_t)((p[0] >> 4) & 0x0fU);
    if (r->version > 1U) return 0;

    r->exchange_id = amatter_le16(p + 4);
    r->protocol_id = amatter_le16(p + 6);
    if (n > 8U) r->opcode = p[8];

    return 1;
}

#endif /* ARGOS_MATTER_H */
