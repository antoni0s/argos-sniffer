#ifndef ARGOS_TLS_CERTIFICATE_STAGING_H
#define ARGOS_TLS_CERTIFICATE_STAGING_H

/*
 * Argos Sniffer v6 — TLS Certificate handshake staging parser
 *
 * STAGING ONLY:
 * - no production includes or runtime wiring;
 * - no heap allocation;
 * - no ASN.1/X.509 deep parsing;
 * - bounded certificate counting;
 * - exposes leaf offset/length for a future certificate-lite DER parser.
 *
 * This layer deliberately owns only TLS Certificate-message framing.  X.509
 * subject/SAN/issuer/validity extraction, if later justified, should be a
 * separate bounded parser consuming only the leaf certificate slice.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_TLS_CERT_STAGING_MAX_CERTS 16U

typedef struct {
    uint8_t tls13_format;
    uint8_t certificate_count;
    uint8_t certificate_count_truncated;
    uint8_t has_leaf;

    size_t leaf_offset;
    size_t leaf_length;
    size_t certificate_list_bytes;
    size_t parsed_certificate_bytes;
} argos_tls_certificate_staging_result_t;

static inline uint32_t argos_tls_cert_staging_be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static inline uint16_t argos_tls_cert_staging_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/*
 * Parse one complete TLS record whose first handshake message is Certificate.
 *
 * tls13_format == 0:
 *   certificate_list<0..2^24-1>
 *   repeated: cert_len(3) + DER certificate
 *
 * tls13_format != 0:
 *   certificate_request_context<0..255>
 *   certificate_list<0..2^24-1>
 *   repeated: cert_len(3) + DER certificate + extensions_len(2) + extensions
 *
 * Returns 1 for a structurally valid Certificate message, 0 otherwise.
 */
static inline int argos_tls_certificate_staging_parse(
    const uint8_t *record,
    size_t len,
    int tls13_format,
    argos_tls_certificate_staging_result_t *out)
{
    size_t record_end, hs_end, pos, list_end;
    uint32_t record_len, hs_len, list_len;

    if (!record || !out || len < 12U)
        return 0;

    memset(out, 0, sizeof(*out));
    out->tls13_format = tls13_format ? 1U : 0U;

    if (record[0] != 0x16U) /* handshake */
        return 0;

    record_len = (uint32_t)argos_tls_cert_staging_be16(record + 3U);
    if ((size_t)record_len > len - 5U)
        return 0;
    record_end = 5U + (size_t)record_len;

    if (record_end < 9U || record[5] != 0x0bU) /* Certificate */
        return 0;

    hs_len = argos_tls_cert_staging_be24(record + 6U);
    if ((size_t)hs_len > record_end - 9U)
        return 0;
    hs_end = 9U + (size_t)hs_len;
    pos = 9U;

    if (tls13_format) {
        size_t context_len;
        if (pos >= hs_end)
            return 0;
        context_len = (size_t)record[pos++];
        if (context_len > hs_end - pos)
            return 0;
        pos += context_len;
    }

    if (hs_end - pos < 3U)
        return 0;

    list_len = argos_tls_cert_staging_be24(record + pos);
    pos += 3U;
    if ((size_t)list_len > hs_end - pos)
        return 0;

    out->certificate_list_bytes = (size_t)list_len;
    list_end = pos + (size_t)list_len;

    while (pos < list_end) {
        size_t cert_len;

        if (list_end - pos < 3U)
            return 0;

        cert_len = (size_t)argos_tls_cert_staging_be24(record + pos);
        pos += 3U;

        if (cert_len == 0U || cert_len > list_end - pos)
            return 0;

        if (!out->has_leaf) {
            out->has_leaf = 1U;
            out->leaf_offset = pos;
            out->leaf_length = cert_len;
        }

        if (out->certificate_count < ARGOS_TLS_CERT_STAGING_MAX_CERTS)
            out->certificate_count++;
        else
            out->certificate_count_truncated = 1U;

        out->parsed_certificate_bytes += cert_len;
        pos += cert_len;

        if (tls13_format) {
            size_t ext_len;
            if (list_end - pos < 2U)
                return 0;
            ext_len = (size_t)argos_tls_cert_staging_be16(record + pos);
            pos += 2U;
            if (ext_len > list_end - pos)
                return 0;
            pos += ext_len;
        }
    }

    return pos == list_end && list_end == hs_end;
}

#endif /* ARGOS_TLS_CERTIFICATE_STAGING_H */
