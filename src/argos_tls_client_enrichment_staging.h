#ifndef ARGOS_TLS_CLIENT_ENRICHMENT_STAGING_H
#define ARGOS_TLS_CLIENT_ENRICHMENT_STAGING_H

/*
 * Argos Sniffer v6 — TLS ClientHello enrichment staging parser
 *
 * STAGING ONLY. No production/runtime integration.
 * Extracts only bounded presence metadata for future encrypted-session
 * observations: ECH, PSK/resumption offer, early_data and supported_versions.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_TLS_CLIENT_ENRICH_MAX_VERSIONS 8U

typedef struct {
    uint16_t legacy_version;
    uint16_t supported_versions[ARGOS_TLS_CLIENT_ENRICH_MAX_VERSIONS];
    uint8_t supported_version_count;
    uint8_t supported_versions_truncated;

    uint8_t has_supported_versions;
    uint8_t has_pre_shared_key;
    uint8_t has_psk_key_exchange_modes;
    uint8_t has_early_data;
    uint8_t has_ech;
} argos_tls_client_enrichment_staging_result_t;

static inline uint16_t argos_tls_client_enrichment_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int argos_tls_client_enrichment_parse(
    const uint8_t *record,
    size_t len,
    argos_tls_client_enrichment_staging_result_t *out)
{
    size_t pos, record_end, handshake_end;

    if (!record || !out || len < 5U + 4U + 35U)
        return 0;

    memset(out, 0, sizeof(*out));

    if (record[0] != 0x16U)
        return 0;

    {
        uint16_t record_len = argos_tls_client_enrichment_be16(record + 3U);
        if ((size_t)record_len > len - 5U)
            return 0;
        record_end = 5U + (size_t)record_len;
    }

    if (record_end < 9U || record[5] != 0x01U)
        return 0;

    {
        size_t hs_len = ((size_t)record[6] << 16) |
                        ((size_t)record[7] << 8) |
                        (size_t)record[8];
        if (hs_len > record_end - 9U)
            return 0;
        handshake_end = 9U + hs_len;
    }

    pos = 9U;
    if (handshake_end - pos < 35U)
        return 0;

    out->legacy_version = argos_tls_client_enrichment_be16(record + pos);
    pos += 2U + 32U;

    if (pos >= handshake_end)
        return 0;

    {
        size_t sid_len = (size_t)record[pos++];
        if (sid_len > handshake_end - pos)
            return 0;
        pos += sid_len;
    }

    if (handshake_end - pos < 2U)
        return 0;
    {
        size_t cipher_len = (size_t)argos_tls_client_enrichment_be16(record + pos);
        pos += 2U;
        if ((cipher_len & 1U) != 0U || cipher_len > handshake_end - pos)
            return 0;
        pos += cipher_len;
    }

    if (pos >= handshake_end)
        return 0;
    {
        size_t comp_len = (size_t)record[pos++];
        if (comp_len > handshake_end - pos)
            return 0;
        pos += comp_len;
    }

    if (pos == handshake_end)
        return 1;
    if (handshake_end - pos < 2U)
        return 0;

    {
        size_t ext_total = (size_t)argos_tls_client_enrichment_be16(record + pos);
        size_t ext_end;
        pos += 2U;
        if (ext_total > handshake_end - pos)
            return 0;
        ext_end = pos + ext_total;

        while (pos < ext_end) {
            uint16_t ext_type;
            size_t ext_len;
            const uint8_t *ext_data;

            if (ext_end - pos < 4U)
                return 0;

            ext_type = argos_tls_client_enrichment_be16(record + pos);
            ext_len = (size_t)argos_tls_client_enrichment_be16(record + pos + 2U);
            pos += 4U;
            if (ext_len > ext_end - pos)
                return 0;
            ext_data = record + pos;

            switch (ext_type) {
            case 0x002bU: /* supported_versions */
                out->has_supported_versions = 1U;
                if (ext_len >= 1U) {
                    size_t list_len = (size_t)ext_data[0];
                    size_t vp = 1U;
                    if (list_len <= ext_len - 1U && (list_len & 1U) == 0U) {
                        while (vp + 1U < 1U + list_len) {
                            uint16_t v = argos_tls_client_enrichment_be16(ext_data + vp);
                            if (out->supported_version_count < ARGOS_TLS_CLIENT_ENRICH_MAX_VERSIONS)
                                out->supported_versions[out->supported_version_count++] = v;
                            else
                                out->supported_versions_truncated = 1U;
                            vp += 2U;
                        }
                    }
                }
                break;
            case 0x0029U: /* pre_shared_key */
                out->has_pre_shared_key = 1U;
                break;
            case 0x002dU: /* psk_key_exchange_modes */
                out->has_psk_key_exchange_modes = 1U;
                break;
            case 0x002aU: /* early_data */
                out->has_early_data = 1U;
                break;
            case 0xfe0dU: /* encrypted_client_hello */
                out->has_ech = 1U;
                break;
            default:
                break;
            }

            pos += ext_len;
        }

        if (pos != ext_end)
            return 0;
    }

    return 1;
}

#endif /* ARGOS_TLS_CLIENT_ENRICHMENT_STAGING_H */
