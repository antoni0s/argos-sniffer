#ifndef ARGOS_FAST_COMPLETE_STAGING_H
#define ARGOS_FAST_COMPLETE_STAGING_H

/*
 * Argos Sniffer v6 — fast-complete policy staging table
 *
 * STAGING ONLY. This is intentionally data-only policy metadata used by tests
 * and architecture review. It is not wired to production flow state,
 * suppression, dispatcher or telemetry code.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    ARGOS_FC_TLS = 0,
    ARGOS_FC_QUIC,
    ARGOS_FC_HTTP,
    ARGOS_FC_SMB,
    ARGOS_FC_NFS,
    ARGOS_FC_RDP,
    ARGOS_FC_SSH,
    ARGOS_FC_LDAP,
    ARGOS_FC_RTSP,
    ARGOS_FC_IKE,
    ARGOS_FC_COUNT
} argos_fast_complete_protocol_t;

typedef struct {
    argos_fast_complete_protocol_t protocol;
    const char *name;
    uint16_t max_packets;
    uint32_t max_bytes;
    uint16_t timeout_ms;
    uint16_t max_state_bytes;
    uint8_t direction_mask; /* bit0 client->server, bit1 server->client */
    const char *complete_when;
    const char *drop_when;
} argos_fast_complete_policy_t;

/*
 * Initial review budgets, not production contracts. Values are deliberately
 * conservative and must be validated against real fixtures/benchmarks before
 * promotion. They exist to force every engine to have an explicit ceiling.
 */
static const argos_fast_complete_policy_t argos_fast_complete_staging_policies[ARGOS_FC_COUNT] = {
    { ARGOS_FC_TLS,     "tls",     8,  16384, 3000, 512, 3, "client/server hello evidence complete", "handshake unsupported or budget exhausted" },
    { ARGOS_FC_QUIC,    "quic",    8,  16384, 3000, 768, 3, "initial crypto fingerprint complete", "initial decrypt/reassembly budget exhausted" },
    { ARGOS_FC_HTTP,    "http",    4,   8192, 2000, 256, 3, "request/response headers identified", "body/bulk transfer begins or header budget exhausted" },
    { ARGOS_FC_SMB,     "smb",     8,  16384, 3000, 512, 3, "negotiate/session setup identity evidence complete", "bulk file data or budget exhausted" },
    { ARGOS_FC_NFS,     "nfs",     6,   8192, 3000, 256, 3, "rpc program/version/procedure evidence complete", "bulk read/write procedure or budget exhausted" },
    { ARGOS_FC_RDP,     "rdp",     6,   8192, 3000, 384, 3, "negotiation/security identity evidence complete", "graphics/data phase or budget exhausted" },
    { ARGOS_FC_SSH,     "ssh",     6,   8192, 3000, 256, 3, "banner and key-exchange fingerprint complete", "encrypted transport phase or budget exhausted" },
    { ARGOS_FC_LDAP,    "ldap",    6,   8192, 3000, 256, 3, "bind/search identity metadata complete", "opaque/bulk result data or budget exhausted" },
    { ARGOS_FC_RTSP,    "rtsp",    6,   8192, 3000, 256, 3, "method/server/user-agent/transport evidence complete", "media payload phase or budget exhausted" },
    { ARGOS_FC_IKE,     "ike",     6,   8192, 3000, 256, 3, "version/exchange/SPI/NAT-T evidence complete", "encrypted payload-only phase or budget exhausted" }
};

static inline const argos_fast_complete_policy_t *
argos_fast_complete_staging_get(argos_fast_complete_protocol_t protocol)
{
    if ((unsigned)protocol >= (unsigned)ARGOS_FC_COUNT)
        return NULL;
    return &argos_fast_complete_staging_policies[(unsigned)protocol];
}

#endif /* ARGOS_FAST_COMPLETE_STAGING_H */
