#ifndef ARGOS_TLS_H
#define ARGOS_TLS_H

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TLS ClientHello/JA4 engine. Parsing and fingerprint construction live here;
 * deduplication, routed attribution and telemetry sinks remain runtime concerns. */
typedef struct {
    char sni[256];
    char ja4[128];
    char alpn[32];
} argos_tls_client_result_t;

static inline uint16_t atc_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* Byte-compatible with the legacy main-file sanitizer used by TLS: values
 * outside printable ASCII and the telemetry delimiter become spaces. */
static inline void atc_sanitize_field(const unsigned char *src, int len, char *dst, int dstsz, int lower) {
    int o = 0;
    if (!dst || dstsz <= 0) return;
    if (!src || len <= 0) { dst[0] = '\0'; return; }
    for (int i = 0; i < len && o < dstsz - 1; ++i) {
        unsigned char c = src[i];
        if (c < 32U || c > 126U || c == '|') c = ' ';
        else if (lower) c = (unsigned char)tolower(c);
        dst[o++] = (char)c;
    }
    dst[o] = '\0';
}

/* ============================================================================
 * SECTION: Micro MD5 Implementation (For JA4 Fingerprinting)
 * Provides a lightweight, optimized MD5 calculation routine tailored for JA4
 * cipher and extension string hashing.
 * ============================================================================ */
#define ATC_LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
/**
 * Computes the MD5 hash of an input message and outputs it as a lowercase hex string.
 *
 * NOTE: MD5 is defined over 32-bit words in LITTLE-ENDIAN byte order, and the
 * trailing 64-bit bit-length field must also be written little-endian. This
 * implementation reads/writes those multi-byte values explicitly byte-by-byte
 * (see below) instead of casting the buffer to uint32_t* and dereferencing
 * it, which would silently produce wrong hashes on a big-endian host (some
 * MIPS-based OpenWrt boards are big-endian) and would also be an unaligned /
 * strict-aliasing violation.
 */
static const uint32_t ATC_MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint32_t ATC_MD5_S[16] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void atc_md5_compress(uint32_t state[4], const uint8_t block[64]) {
        /* Load this block's 16 words explicitly as little-endian, byte by
         * byte -- portable across host endianness and avoids casting a raw
         * byte pointer to uint32_t* (alignment/strict-aliasing safe). */
        uint32_t w[16];
        for (int wi = 0; wi < 16; wi++) {
            const uint8_t *b = block + (size_t)wi * 4U;
            w[wi] = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16)      { f = (b & c) | ((~b) & d); g = i; }
            else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
            else             { f = c ^ (b | (~d)); g = (7 * i) % 16; }

            uint32_t temp = d;
            d = c; c = b;

            b = b + ATC_LEFTROTATE((a + f + ATC_MD5_K[i] + w[g]), ATC_MD5_S[(i/16)*4 + (i%4)]);
            a = temp;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void atc_md5_hash(const uint8_t *initial_msg, size_t initial_len, char *out_hex) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t offset = 0U;

    /* Stream complete input blocks directly. Only the final one or two padded
     * blocks need scratch, so JA4 hashing has fixed stack work and no allocator. */
    while (initial_len - offset >= 64U) {
        atc_md5_compress(state, initial_msg + offset);
        offset += 64U;
    }

    uint8_t tail[128] = {0};
    size_t remain = initial_len - offset;
    if (remain != 0U) memcpy(tail, initial_msg + offset, remain);
    tail[remain] = 0x80U;
    size_t padded = remain < 56U ? 64U : 128U;
    uint64_t bits_len = (uint64_t)initial_len * UINT64_C(8);
    for (unsigned i = 0; i < 8U; ++i)
        tail[padded - 8U + i] = (uint8_t)(bits_len >> (8U * i));
    atc_md5_compress(state, tail);
    if (padded == 128U) atc_md5_compress(state, tail + 64U);

    uint32_t h0 = state[0], h1 = state[1], h2 = state[2], h3 = state[3];
    snprintf(out_hex, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        h0&0xff, (h0>>8)&0xff, (h0>>16)&0xff, (h0>>24)&0xff,
        h1&0xff, (h1>>8)&0xff, (h1>>16)&0xff, (h1>>24)&0xff,
        h2&0xff, (h2>>8)&0xff, (h2>>16)&0xff, (h2>>24)&0xff,
        h3&0xff, (h3>>8)&0xff, (h3>>16)&0xff, (h3>>24)&0xff);
}

static inline int atc_cmp_uint16(const void *a, const void *b) { return (int)(*(const uint16_t *)a) - (int)(*(const uint16_t *)b); }

/**
 * Checks if a 16-bit value matches TLS GREASE extension/cipher definitions.
 */
static inline int atc_grease16(uint16_t v) {
    return ((v >> 8) == (v & 0xFF)) && ((v & 0x0F) == 0x0A);
}

/**
 * Parses a TLS ClientHello (record type 0x16, handshake type 0x01) to
 * extract the SNI, ALPN, cipher suites and extensions, and builds a JA4
 * client fingerprint from them.
 *
 * ClientHello wire layout (offsets below are from the start of `payload`,
 * i.e. from the TLS record header):
 *   byte 0        record type            (0x16 = handshake)
 *   bytes 1-2     record version
 *   bytes 3-4     record length
 *   byte 5        handshake type         (0x01 = ClientHello)
 *   bytes 6-8     handshake length       (24-bit)
 *   bytes 9-10    legacy client_version  (may be overridden below by the
 *                                          supported_versions extension)
 *   bytes 11-42   client random          (32 bytes)
 *   byte 43       session_id length      (followed by that many bytes)
 *   ...           cipher_suites: 2-byte length + 2-byte cipher IDs
 *   ...           compression_methods: 1-byte length + methods
 *   ...           extensions: 2-byte total length + TLV extension list
 */
static inline int argos_tls_client_parse(const unsigned char *payload, int len, argos_tls_client_result_t *out) {
    if (!payload || !out || len < 44 || payload[0] != 0x16 || payload[5] != 0x01) return 0;
    memset(out, 0, sizeof(*out)); /* not a TLS handshake / not a ClientHello */

    /* Skip the fixed 43-byte header, then the variable-length session_id. */
    int pos = 43; if (pos >= len) return 0; pos += payload[pos] + 1;

    if (pos + 2 > len) return 0;
    int cipher_len = atc_be16(payload + pos);
    int cipher_count = cipher_len / 2;
    if (pos + 2 + cipher_len > len) return 0;

    /* Build the comma-separated cipher hex list that gets MD5-hashed into
     * ja4_b, excluding GREASE reserved values (RFC 8701) -- browsers insert
     * these as random noise to prevent protocol ossification, so they carry
     * no fingerprinting signal and would make otherwise-identical clients
     * hash differently run to run. `real_cipher_count` counts exactly the
     * entries that end up in the hash. */
    char cipher_hex[4096] = {0}; int chex_pos = 0; int real_cipher_count = 0;
    for (int i = 0; i < cipher_count && chex_pos < (int)sizeof(cipher_hex) - 5; i++) {
        uint16_t c = atc_be16(payload + pos + 2 + (i * 2));
        if (!atc_grease16(c)) {
            int written = snprintf(cipher_hex + chex_pos, sizeof(cipher_hex) - (size_t)chex_pos, "%04x,", c);
            if (written < 0) return 0;
            if (written >= (int)(sizeof(cipher_hex) - (size_t)chex_pos)) break;
            chex_pos += written;
            real_cipher_count++;
        }
    }
    if (chex_pos > 0) cipher_hex[chex_pos-1] = '\0'; /* drop trailing comma */
    pos += cipher_len + 2;

    /* compression_methods (unused, just skip over it). */
    if (pos + 1 > len) return 0;
    pos += payload[pos] + 1;
    /* extensions block: 2-byte total length, then the TLV extension list. */
    if (pos + 2 > len) return 0;
    int ext_list_len = atc_be16(payload + pos);
    pos += 2;
    int end = pos + ext_list_len; if (end > len) end = len;

    char sni[256] = {0}, alpn[32] = {0}; int ext_count = 0;
    uint16_t ext_arr[128] = {0};
    /* Track whether the SNI / ALPN extensions were actually present in this
     * ClientHello, independent of the parsed string contents, so valid values
     * that happen to start with placeholder-like text remain distinguishable. */
    int has_sni = 0, has_alpn = 0;

    /* Legacy client_version at bytes 9-10 (see layout above); len>=44 was
     * already checked, so this read is always in-bounds. May be superseded
     * below by the supported_versions extension, which TLS 1.3+ clients
     * actually use for negotiation. */
    uint16_t tls_version = (len >= 11) ? atc_be16(payload + 9) : 0x0301;

    /* Walk the extensions TLV list: type(2) + length(2) + payload. */
    while (pos + 4 <= end) {
        uint16_t e_type = atc_be16(payload + pos); int e_len = atc_be16(payload + pos + 2);
        pos += 4;
        /* Collect extension IDs for the ja4_c hash. SNI (0x00) and ALPN
         * (0x10) are excluded here since JA4 encodes them elsewhere (the
         * 'd'/'i' flag and the ALPN first/last char below); GREASE values
         * are excluded as noise, same reasoning as for ciphers above. */
        if (e_type != 0x0000 && e_type != 0x0010 && !atc_grease16(e_type) && ext_count < 128) ext_arr[ext_count++] = e_type;

        if (e_type == 0 && pos + e_len <= end && e_len >= 5 && sni[0] == '\0') {
            /* server_name extension: list length(2) + name_type(1) + name length(2) + name bytes. */
            has_sni = 1;
            int sn_len = atc_be16(payload + pos + 3);
            if (payload[pos + 2] == 0 && pos + 5 + sn_len <= end && sn_len < 256) {
                atc_sanitize_field(payload + pos + 5, sn_len, sni, sizeof(sni), 0);
            }
        }
        else if (e_type == 16 && pos + e_len <= end && e_len >= 3 && alpn[0] == '\0') {
            /* ALPN extension: list length(2), then one or more
             * (proto length(1) + proto bytes) entries. Only the first
             * offered protocol is kept, which is all JA4 needs. */
            has_alpn = 1;
            int alpn_list_len = atc_be16(payload + pos);
            if (alpn_list_len > 0 && pos + 3 <= end) {
                int first_alpn_len = payload[pos + 2];
                if (first_alpn_len < 32 && pos + 3 + first_alpn_len <= end) atc_sanitize_field(payload + pos + 3, first_alpn_len, alpn, sizeof(alpn), 0);
            }
        }
        else if (e_type == 0x002b && pos + e_len <= end && e_len >= 3) {
            /* supported_versions extension: list length(1) + 2-byte version
             * entries. Pick the highest non-GREASE version offered, since
             * that's what a TLS 1.3 client actually negotiates with. */
            int list_len = payload[pos];
            uint16_t best = 0;
            for (int vi = 0, voff = pos + 1; vi + 1 < list_len && voff + 1 < end; vi += 2, voff += 2) {
                uint16_t v = atc_be16(payload + voff);
                if (!atc_grease16(v) && v > best) best = v;
            }
            if (best) tls_version = best;
        }
        pos += e_len;
    }

    /* Capture JA4 ALPN characters BEFORE applying the human-readable
     * "none" fallback below.  If the ALPN extension is present but its first
     * protocol identifier is empty/oversized/unparseable, JA4 must keep the
     * neutral 00 marker rather than fingerprinting the placeholder text. */
    char alpn_first = '0', alpn_last = '0';
    if (has_alpn && alpn[0] != '\0') { alpn_first = alpn[0]; alpn_last = alpn[strlen(alpn) - 1]; }

    /* Display values fall back to the literal string "none" when absent.
     * These placeholders are telemetry-only and never feed JA4. */
    if (sni[0] == '\0') strcpy(sni, "none");
    if (alpn[0] == '\0') strcpy(alpn, "none");

    /* ja4_c hash input: sorted, comma-joined list of extension IDs. */
    qsort(ext_arr, (size_t)ext_count, sizeof(uint16_t), atc_cmp_uint16);
    char ext_hex[2048] = {0}; int ex_pos = 0;
    for(int i=0; i<ext_count && ex_pos < 2000; i++) {
        int written = snprintf(ext_hex + ex_pos, sizeof(ext_hex) - (size_t)ex_pos, "%04x,", ext_arr[i]);
        if (written < 0) return 0;
        if (written >= (int)(sizeof(ext_hex) - (size_t)ex_pos)) {
            ex_pos = (int)sizeof(ext_hex) - 1;
            break;
        }
        ex_pos += written;
    }
    if (ex_pos > 0) ext_hex[ex_pos-1] = '\0';

    const char *ja4_ver;
    switch (tls_version) {
        case 0x0304: ja4_ver = "13"; break;
        case 0x0303: ja4_ver = "12"; break;
        case 0x0302: ja4_ver = "11"; break;
        case 0x0301: ja4_ver = "10"; break;
        case 0x0300: ja4_ver = "s3"; break;
        default:     ja4_ver = "00"; break;
    }
    /* Keep the JA4 cipher count consistent with ja4_b by excluding GREASE. */
    int a_cipher_count = real_cipher_count > 99 ? 99 : real_cipher_count;
    int a_ext_count = ext_count > 99 ? 99 : ext_count;

    char ja4_a[64], ja4_b[33], ja4_c[33];
    snprintf(ja4_a, sizeof(ja4_a), "t%s%c%02d%02d%c%c", ja4_ver,
        has_sni ? 'd' : 'i',
        a_cipher_count, a_ext_count, alpn_first, alpn_last);

    atc_md5_hash((uint8_t*)cipher_hex, strlen(cipher_hex), ja4_b);
    atc_md5_hash((uint8_t*)ext_hex, strlen(ext_hex), ja4_c);

    /* Final fingerprint. NOTE: this is JA4-*like*, not FoxIO JA4:
     *   - hash is MD5 (OpenWrt-cheap), not SHA-256
     *   - ciphers are hashed in WIRE order, not sorted
     *   - ja4_c does not append the signature_algorithms list
     *   - extension *count* excludes SNI/ALPN (spec includes them)
     * Kept byte-compatible with 5.0.9 collectors. Spec-compliant JA4 is in v6. */
    char ja4_full[128];
    snprintf(ja4_full, sizeof(ja4_full), "%s_%.12s_%.12s", ja4_a, ja4_b, ja4_c);

    snprintf(out->sni, sizeof(out->sni), "%s", sni);
    snprintf(out->alpn, sizeof(out->alpn), "%s", alpn);
    snprintf(out->ja4, sizeof(out->ja4), "%s", ja4_full);
    return 1;
}



/* ========================================================================== */
/* TLS ServerHello / ATS1 engine                                              */
/* ========================================================================== */
typedef struct {
    char version[3];
    uint16_t cipher;
    uint8_t extension_count;
    char alpn[32];
    uint64_t extension_signature;
    char fingerprint[96];
} argos_tls_server_result_t;

static inline uint16_t ats_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int ats_grease(uint16_t v) {
    return (v & 0x0f0fU) == 0x0a0aU && ((v >> 8) & 0xffU) == (v & 0xffU);
}

static inline const char *ats_version_code(uint16_t v) {
    switch (v) {
        case 0x0304U: return "13";
        case 0x0303U: return "12";
        case 0x0302U: return "11";
        case 0x0301U: return "10";
        default: return "00";
    }
}

static inline uint64_t ats_fnv_type(uint64_t h, uint16_t type) {
    const unsigned char b[2] = {(unsigned char)(type >> 8), (unsigned char)type};
    for (size_t i = 0; i < 2U; ++i) {
        h ^= (uint64_t)b[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static inline void ats_alpn_code(const unsigned char *p, size_t n, char out[32]) {
    strcpy(out, "none");
    if (!p || n < 3U) return;
    size_t list_len = ats_be16(p);
    if (list_len + 2U > n || list_len < 1U) return;
    size_t plen = p[2];
    if (plen == 0U || plen + 3U > n) return;
    size_t keep = plen < 31U ? plen : 31U;
    for (size_t i = 0; i < keep; ++i) {
        unsigned char c = p[3U + i];
        out[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|') ? c : '.');
    }
    out[keep] = '\0';
}

/* Argos TLS Server v1 (ats1) is intentionally NOT JA4S. It is an independent,
 * low-cost ServerHello fingerprint: negotiated version, selected cipher,
 * non-GREASE extension count/order signature, and visible ALPN. */
static inline int argos_tls_server_parse(const unsigned char *p, size_t n,
                                         argos_tls_server_result_t *out) {
    if (!p || !out || n < 49U) return 0;
    memset(out, 0, sizeof(*out));
    strcpy(out->alpn, "none");

    if (p[0] != 0x16U || p[5] != 0x02U) return 0; /* handshake / ServerHello */
    size_t record_len = ats_be16(p + 3);
    if (record_len < 44U || record_len + 5U > n) return 0;
    size_t hs_len = ((size_t)p[6] << 16) | ((size_t)p[7] << 8) | (size_t)p[8];
    if (hs_len < 40U || hs_len + 9U > n || hs_len + 4U > record_len) return 0;

    size_t end = 9U + hs_len;
    uint16_t negotiated = ats_be16(p + 9);
    size_t pos = 9U + 2U + 32U;
    if (pos >= end) return 0;
    size_t sid_len = p[pos++];
    if (sid_len > 32U || pos + sid_len + 3U > end) return 0;
    pos += sid_len;
    out->cipher = ats_be16(p + pos); pos += 2U;
    pos += 1U; /* compression */

    uint64_t ext_sig = UINT64_C(1469598103934665603);
    unsigned ext_count = 0U;
    if (pos < end) {
        if (pos + 2U > end) return 0;
        size_t ext_total = ats_be16(p + pos); pos += 2U;
        if (pos + ext_total > end) return 0;
        size_t ext_end = pos + ext_total;
        while (pos + 4U <= ext_end) {
            uint16_t type = ats_be16(p + pos);
            size_t elen = ats_be16(p + pos + 2U);
            pos += 4U;
            if (pos + elen > ext_end) return 0;
            if (!ats_grease(type)) {
                if (ext_count < 99U) ++ext_count;
                ext_sig = ats_fnv_type(ext_sig, type);
            }
            if (type == 0x002bU && elen == 2U) negotiated = ats_be16(p + pos);
            if (type == 0x0010U) ats_alpn_code(p + pos, elen, out->alpn);
            pos += elen;
        }
        if (pos != ext_end) return 0;
    }

    snprintf(out->version, sizeof(out->version), "%s", ats_version_code(negotiated));
    out->extension_count = (uint8_t)ext_count;
    out->extension_signature = ext_sig;
    snprintf(out->fingerprint, sizeof(out->fingerprint),
             "ats1_%s_%04x_%02u_%s_%016llx",
             out->version, (unsigned)out->cipher, ext_count, out->alpn,
             (unsigned long long)ext_sig);
    return 1;
}

#endif /* ARGOS_TLS_H */
