#ifndef ARGOS_WIREGUARD_H
#define ARGOS_WIREGUARD_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int emit;
    char detail[96];
} argos_wireguard_result_t;

/* Shared structural classifier used by both the full parser and the optional
 * pre-parser suppression path. 0=not valid type-4, 1=keepalive, 2=data. */
static inline int argos_wireguard_transport_kind(const unsigned char *p, size_t len) {
    if (!p || len < 4U || p[0] != 4U || p[1] != 0U || p[2] != 0U || p[3] != 0U) return 0;
    if (len < 32U || (len & 15U) != 0U) return 0;
    return len == 32U ? 1 : 2;
}

/* WireGuard v1 messages start with a one-byte type and three reserved zero
 * bytes. We use only structural properties that are visible before crypto;
 * sender/receiver indices, keys, MACs, cookies and ciphertext stay opaque. */
static inline int argos_wireguard_parse(const unsigned char *p, size_t len,
                                        argos_wireguard_result_t *r) {
    if (!p || !r || len < 4U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[1] != 0U || p[2] != 0U || p[3] != 0U) return 0;

    const unsigned type = p[0];
    const char *kind = NULL;
    if (type == 1U) {
        if (len != 148U) return 0;
        kind = "handshake-initiation";
    } else if (type == 2U) {
        if (len != 92U) return 0;
        kind = "handshake-response";
    } else if (type == 3U) {
        if (len != 64U) return 0;
        kind = "cookie-reply";
    } else if (type == 4U) {
        /* 16-byte transport header + AEAD ciphertext/tag. Empty keepalive is
         * 32 bytes; encrypted transport packets remain 16-byte aligned. */
        int transport_kind = argos_wireguard_transport_kind(p, len);
        if (transport_kind == 0) return 0;
        kind = transport_kind == 1 ? "transport-keepalive" : "transport-data";
    } else {
        return 0;
    }

    r->emit = 1;
    snprintf(r->detail, sizeof(r->detail), "type=%s", kind);
    return 1;
}

#endif
