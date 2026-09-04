#ifndef ARGOS_TLS_SERVER_STAGING_H
#define ARGOS_TLS_SERVER_STAGING_H

/*
 * Argos Sniffer v6 — TLS ServerHello staging parser
 *
 * STAGING ONLY. No production/runtime integration.
 * Pure bounded parser for future server-side TLS fingerprinting.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_TLS_SERVER_MAX_EXTENSIONS 32U
#define ARGOS_TLS_SERVER_ALPN_MAX       16U
#define ARGOS_TLS_SERVER_RAW_EXT_MAX    160U

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
    uint8_t is_hello_retry_request;
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

static inline int argos_tls_server_staging_is_hrr_random(const uint8_t *p)
{
    static const uint8_t hrr_random[32] = {
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
        0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
        0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c
    };
    return p && memcmp(p, hrr_random, sizeof(hrr_random)) == 0;
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

/* Two-character TLS version token used by JA4-family formats. */
static inline void argos_tls_server_staging_version_token(uint16_t version, char out[3])
{
    switch (version) {
    case 0x0304U: out[0] = '1'; out[1] = '3'; break;
    case 0x0303U: out[0] = '1'; out[1] = '2'; break;
    case 0x0302U: out[0] = '1'; out[1] = '1'; break;
    case 0x0301U: out[0] = '1'; out[1] = '0'; break;
    case 0x0300U: out[0] = 's'; out[1] = '3'; break;
    default:      out[0] = '0'; out[1] = '0'; break;
    }
    out[2] = '\0';
}

/* First/last-character ALPN token, or "00" if unavailable. */
static inline void argos_tls_server_staging_alpn_token(
    const char *alpn,
    char out[3])
{
    size_t n;
    if (!alpn || !alpn[0]) {
        out[0] = '0'; out[1] = '0'; out[2] = '\0';
        return;
    }
    n = strlen(alpn);
    if ((unsigned char)alpn[0] > 127U) {
        out[0] = '9'; out[1] = '9'; out[2] = '\0';
        return;
    }
    out[0] = alpn[0];
    out[1] = (n > 1U) ? alpn[n - 1U] : alpn[0];
    out[2] = '\0';
}

/*
 * Build only raw JA4S-compatible components. No hashing is performed here.
 * Extension order is preserved because JA4S hashes server extensions in wire
 * order. GREASE has already been excluded by the parser.
 */
static inline int argos_tls_server_staging_raw_components(
    const argos_tls_server_staging_result_t *r,
    char transport,
    char version[3],
    char alpn_token[3],
    char cipher_hex[5],
    char extensions_hex[ARGOS_TLS_SERVER_RAW_EXT_MAX])
{
    static const char hex[] = "0123456789abcdef";
    size_t pos = 0U;

    if (!r || !version || !alpn_token || !cipher_hex || !extensions_hex)
        return 0;

    if (transport != 't' && transport != 'q' && transport != 'd')
        return 0;

    argos_tls_server_staging_version_token(r->negotiated_version, version);
    argos_tls_server_staging_alpn_token(r->alpn, alpn_token);

    cipher_hex[0] = hex[(r->cipher_suite >> 12) & 0x0fU];
    cipher_hex[1] = hex[(r->cipher_suite >> 8) & 0x0fU];
    cipher_hex[2] = hex[(r->cipher_suite >> 4) & 0x0fU];
    cipher_hex[3] = hex[r->cipher_suite & 0x0fU];
    cipher_hex[4] = '\0';

    extensions_hex[0] = '\0';
    for (uint8_t i = 0; i < r->extension_count; ++i) {
        uint16_t v = r->extensions[i];
        size_t need = (i == 0U) ? 4U : 5U;
        if (pos + need >= ARGOS_TLS_SERVER_RAW_EXT_MAX)
            return 0;
        if (i != 0U)
            extensions_hex[pos++] = ',';
        extensions_hex[pos++] = hex[(v >> 12) & 0x0fU];
        extensions_hex[pos++] = hex[(v >> 8) & 0x0fU];
        extensions_hex[pos++] = hex[(v >> 4) & 0x0fU];
        extensions_hex[pos++] = hex[v & 0x0fU];
        extensions_hex[pos] = '\0';
    }

    return 1;
}

/* Parse one complete TLS record containing a ServerHello. */
static inline int argos_tls_server_staging_parse(
    const uint8_t *record,
    size_t len,
    argos_tls_server_staging_result_t *out)
{
    size_t pos, record_end, handshake_end;

    if (!record || !out || len < 5U + 4U + 38U)
        return 0;

    memset(out, 0, sizeof(*out));

    if (record[0] != 0x16U)
        return 0;

    {
        uint16_t record_len = argos_tls_server_staging_be16(record + 3U);
        if ((size_t)record_len > len - 5U)
            return 0;
        record_end = 5U + (size_t)record_len;
    }

    if (record_end < 9U || record[5] != 0x02U)
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

    out->is_hello_retry_request =
        (uint8_t)argos_tls_server_staging_is_hrr_random(record + pos);
    pos += 32U;

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
    pos += 1U; /* compression */

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

            if (!argos_tls_server_staging_is_grease(ext_type)) {
                if (out->extension_count < ARGOS_TLS_SERVER_MAX_EXTENSIONS)
                    out->extensions[out->extension_count++] = ext_type;
                else
                    out->extensions_truncated = 1U;
            }

            switch (ext_type) {
            case 0x002bU:
                out->has_supported_versions = 1U;
                if (ext_len == 2U)
                    out->negotiated_version = argos_tls_server_staging_be16(ext_data);
                break;
            case 0x0010U:
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
            case 0x0029U: out->has_pre_shared_key = 1U; break;
            case 0x0033U: out->has_key_share = 1U; break;
            case 0x002aU: out->has_early_data = 1U; break;
            case 0xfe0dU: out->has_ech = 1U; break;
            default: break;
            }

            pos += ext_len;
        }

        if (pos != ext_end)
            return 0;
    }

    return 1;
}

#endif /* ARGOS_TLS_SERVER_STAGING_H */
