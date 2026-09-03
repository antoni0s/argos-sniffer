#ifndef ARGOS_LDAPS_H
#define ARGOS_LDAPS_H

/* Argos-Sniffer v6 staging engine: LDAPS.
 * Standalone passive identification only; no TLS decryption is attempted.
 * This module intentionally fingerprints the dedicated LDAP-over-TLS service
 * boundary and delegates TLS parsing to the existing TLS engine at integration.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int looks_tls;
    uint8_t content_type;
    uint16_t legacy_version;
    uint16_t record_length;
    char detail[192];
} argos_ldaps_result_t;

static inline uint16_t aldaps_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int argos_ldaps_parse(const unsigned char *p, size_t n,
                                    argos_ldaps_result_t *r) {
    if (!p || !r || n < 5U) return 0;
    memset(r, 0, sizeof(*r));

    r->content_type = p[0];
    r->legacy_version = aldaps_be16(p + 1);
    r->record_length = aldaps_be16(p + 3);

    if (r->content_type < 20U || r->content_type > 23U) return 0;
    if ((r->legacy_version & 0xff00U) != 0x0300U) return 0;
    if ((size_t)r->record_length > n - 5U) return 0;

    r->seen = 1;
    r->looks_tls = 1;
    (void)snprintf(r->detail, sizeof(r->detail),
                   "tls_record=1;content_type=%u;legacy_version=0x%04x;record_length=%u",
                   (unsigned)r->content_type,
                   (unsigned)r->legacy_version,
                   (unsigned)r->record_length);
    return 1;
}

#endif /* ARGOS_LDAPS_H */
