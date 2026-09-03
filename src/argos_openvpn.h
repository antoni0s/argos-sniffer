#ifndef ARGOS_OPENVPN_H
#define ARGOS_OPENVPN_H

/* Argos-Sniffer v6 staging engine: OpenVPN.
 * Standalone framing fingerprint only; not wired into runtime yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t opcode;
    uint8_t key_id;
    uint8_t peer_id_present;
    uint32_t peer_id;
} argos_openvpn_result_t;

static inline uint32_t aovpn_be24(const unsigned char *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

/* OpenVPN control/data packet first byte: opcode in high 5 bits, key-id in low 3. */
static inline int argos_openvpn_parse(const unsigned char *p, size_t n,
                                      argos_openvpn_result_t *r) {
    if (!p || !r || n < 1U) return 0;
    memset(r, 0, sizeof(*r));

    r->opcode = (uint8_t)(p[0] >> 3);
    r->key_id = (uint8_t)(p[0] & 0x07U);
    if (r->opcode == 0U || r->opcode > 11U) return 0;

    if ((r->opcode == 9U || r->opcode == 10U) && n >= 4U) {
        r->peer_id_present = 1U;
        r->peer_id = aovpn_be24(p + 1);
    }
    return 1;
}

#endif /* ARGOS_OPENVPN_H */
