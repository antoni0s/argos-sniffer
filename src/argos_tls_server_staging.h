#ifndef ARGOS_TLS_SERVER_STAGING_H
#define ARGOS_TLS_SERVER_STAGING_H

/*
 * Argos Sniffer v6 — TLS ServerHello staging parser
 *
 * STAGING ONLY:
 * - not included by production code;
 * - no dispatcher/config/state/telemetry integration;
 * - no heap allocation;
 * - bounded extension capture;
 * - extracts only passive ServerHello metadata useful for future JA4S-style
 *   fingerprinting and encrypted-session observations.
 *
 * The final JA4S hash construction is intentionally not implemented here.
 * Promotion must reuse the canonical v6 hashing/output contract after those
 * interfaces are frozen. This staging parser only establishes safe wire
 * parsing semantics and normalized inputs.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_TLS_SERVER_MAX_EXTENSIONS 32U
#define ARGOS_TLS_SERVER_ALPN_MAX       16U

typedef struct {
    uint16_t legacy_version;
    uint16_t negotiated_version;
    uint16_t cipher_suite;

    uint16_t extensions[ARGOS_TLS_SERVER_MAX_EXTENSIONS];
    uint8_t extension_count;
    uint8_t extensions_truncated;

    char alpn[ARGOS_TLS_SERVER_ALPN_MAX];

    uint8_t has_supported_versions;
    uint8_t has_alpn;
    uint8_t has_pre_shared_key;
    uint8_t has_key_share;
    uint8_t has_early_data;
    uint8_t has_ech;
} argos_tls_server_staging_result_t;

static inline uint16_t argos_tls_server_staging_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int argos_tls_server_staging_is_grease(uint16_t value)
{
    return ((value & 0x0f0fU) == 0x0a0aU) &&
           ((uint8_t)(value >> 8) == (uint8_t)value);
}

static inline void argos_tls_server_staging_copy_alpn(
    const uint8_t *data,
    size_t len,
    char out[ARGOS_TLS_SERVER_ALPN_MAX])
{
    size_t n = len;
    if (n >= ARGOS_TLS_SERVER_ALPN_MAX)
        n = ARGOS_TLS_SERVER_ALPN_MAX - 1U;

    for (size_t i = 0; i < n; ++i) {
        uint8_t c = data[i];
        out[i] = (c >= 0x20U && c <= 0x7eU && c != (uint8_t)'|')
                   ? (char)c
                   : '_';
    }
    out[n] = '\0';
}

/*
 * Parse one complete TLS record containing a ServerHello.
 *
 * Expected layout:
 *   TLS record header:  type(1), version(2), length(2)
 *   Handshake header:   type(1=ServerHello), length(3)
 *   ServerHello body:
 *       legacy_version(2)
 *       random(32)
 *       session_id_len(1) + session_id
 *       cipher_suite(2)
 *       compression(1)
 *       extensions_len(2) + extensions
 *
 * Returns 1 on a structurally valid ServerHello, 0 otherwise.
 * It never reads beyond len and never allocates.
 */
static inline int argos_tls_server_staging_parse(
    const uint8_t *record,
    size_t len,
    argos_tls_server_staging_result_t *out)
{
    size_t pos;
    size_t record_end;
    size_t handshake_end;

    if (!record || !out || len < 5U + 4U + 38U)
        return 0;

    memset(out, 0, sizeof(*out));

    if (record[0] != 0x16U) /* handshake record */
        return 0;

    {
        uint16_t record_len = argos_tls_server_staging_be16(record + 3U);
        if ((size_t)record_len > len - 5U)
            return 0;
        record_end = 5U + (size_t)record_len;
    }

    if (record_end < 9U || record[5] != 0x02U) /* ServerHello */
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

    out->legacy_version = argos_tls_server_staging_be16(record + pos);
    out->negotiated_version = out->legacy_version;
    pos += 2U;

    pos += 32U; /* random */

    if (pos >= handshake_end)
        return 0;

    {
        size_t sid_len = (size_t)record[pos++];
        if (sid_len > handshake_end - pos)
            return 0;
        pos += sid_len;
    }

    if (handshake_end - pos < 3U)
        return 0;

    out->cipher_suite = argos_tls_server_staging_be16(record + pos);
    pos += 2U;

    /* Legacy compression_method must be present. TLS 1.3 uses zero. */
    pos += 1U;

    /* Extensions are optional in older ServerHello forms. */
    if (pos == handshake_end)
        return 1;

    if (handshake_end - pos < 2U)
        return 0;

    {
        size_t ext_total = (size_t)argos_tls_server_staging_be16(record + pos);
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

            ext_type = argos_tls_server_staging_be16(record + pos);
            ext_len = (size_t)argos_tls_server_staging_be16(record + pos + 2U);
            pos += 4U;

            if (ext_len > ext_end - pos)
                return 0;

            ext_data = record + pos;

            /* GREASE is intentionally excluded from canonical fingerprint input. */
            if (!argos_tls_server_staging_is_grease(ext_type)) {
                if (out->extension_count < ARGOS_TLS_SERVER_MAX_EXTENSIONS) {
                    out->extensions[out->extension_count++] = ext_type;
                } else {
                    out->extensions_truncated = 1U;
                }
            }

            switch (ext_type) {
            case 0x002bU: /* supported_versions */
                out->has_supported_versions = 1U;
                if (ext_len == 2U)
                    out->negotiated_version = argos_tls_server_staging_be16(ext_data);
                break;

            case 0x0010U: /* ALPN */
                /* ServerHello/EncryptedExtensions ALPN encoding is a protocol
                 * name list. If present here, accept exactly one bounded name. */
                out->has_alpn = 1U;
                if (ext_len >= 3U) {
                    size_t list_len = (size_t)argos_tls_server_staging_be16(ext_data);
                    if (list_len <= ext_len - 2U && list_len >= 1U) {
                        size_t name_len = (size_t)ext_data[2U];
                        if (name_len <= list_len - 1U && name_len <= ext_len - 3U)
                            argos_tls_server_staging_copy_alpn(ext_data + 3U, name_len, out->alpn);
                    }
                }
                break;

            case 0x0029U: /* pre_shared_key */
                out->has_pre_shared_key = 1U;
                break;

            case 0x0033U: /* key_share */
                out->has_key_share = 1U;
                break;

            case 0x002aU: /* early_data */
                out->has_early_data = 1U;
                break;

            /* ECH-related extension values seen in deployed drafts/final
             * evolution are deliberately treated as presence hints only.
             * Promotion must re-check the then-current RFC/IANA assignment. */
            case 0xfe0dU:
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

#endif /* ARGOS_TLS_SERVER_STAGING_H */
