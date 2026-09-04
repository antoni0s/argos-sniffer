/* ============================================================================
 * argos_quic.h - QUIC v1/v2 Initial Packet Decryptor & TLS ClientHello Extractor
 * Pure C / no OpenSSL dependency. (PRODUCTION - SILENT)
 * ============================================================================ */

#ifndef ARGOS_QUIC_H
#define ARGOS_QUIC_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* -------------------------------------------------------------------------- */
/* SHA-256                                                                    */
/* -------------------------------------------------------------------------- */
typedef struct { uint32_t state[8]; uint64_t count; uint8_t buffer[64]; } sha256_ctx;
#define ARGOS_ROTR32(x, n) (((x) >> (n)) | ((x) << (32U - (n))))

static const uint32_t argos_sha256_k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void argos_sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, m[64], t1, t2; unsigned i, j;
    for (i = 0, j = 0; i < 16U; ++i, j += 4U)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1U] << 16) | ((uint32_t)data[j + 2U] << 8) | (uint32_t)data[j + 3U];
    for (i = 16U; i < 64U; ++i) {
        uint32_t s0 = ARGOS_ROTR32(m[i - 15U], 7U) ^ ARGOS_ROTR32(m[i - 15U], 18U) ^ (m[i - 15U] >> 3U);
        uint32_t s1 = ARGOS_ROTR32(m[i - 2U], 17U) ^ ARGOS_ROTR32(m[i - 2U], 19U) ^ (m[i - 2U] >> 10U);
        m[i] = m[i - 16U] + s0 + m[i - 7U] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64U; ++i) {
        uint32_t S1 = ARGOS_ROTR32(e, 6U) ^ ARGOS_ROTR32(e, 11U) ^ ARGOS_ROTR32(e, 25U);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = ARGOS_ROTR32(a, 2U) ^ ARGOS_ROTR32(a, 13U) ^ ARGOS_ROTR32(a, 22U);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + S1 + ch + argos_sha256_k[i] + m[i];
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void argos_sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U; ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU; ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
    ctx->count = 0;
}

static void argos_sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = (size_t)(ctx->count & 63U); ctx->count += (uint64_t)len;
    while (len != 0U) {
        size_t take = 64U - i; if (take > len) take = len;
        memcpy(ctx->buffer + i, data, take); i += take; data += take; len -= take;
        if (i == 64U) { argos_sha256_transform(ctx, ctx->buffer); i = 0U; }
    }
}

static void argos_sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint64_t bits = ctx->count * 8U; size_t i = (size_t)(ctx->count & 63U); int j;
    ctx->buffer[i++] = 0x80U;
    if (i > 56U) { memset(ctx->buffer + i, 0, 64U - i); argos_sha256_transform(ctx, ctx->buffer); i = 0U; }
    memset(ctx->buffer + i, 0, 56U - i);
    for (j = 0; j < 8; ++j) ctx->buffer[56U + (size_t)j] = (uint8_t)(bits >> (56U - 8U * (unsigned)j));
    argos_sha256_transform(ctx, ctx->buffer);
    for (j = 0; j < 8; ++j) {
        hash[j * 4] = (uint8_t)(ctx->state[j] >> 24); hash[j * 4 + 1] = (uint8_t)(ctx->state[j] >> 16);
        hash[j * 4 + 2] = (uint8_t)(ctx->state[j] >> 8); hash[j * 4 + 3] = (uint8_t)(ctx->state[j]);
    }
}

/* -------------------------------------------------------------------------- */
/* HMAC-SHA-256                                                               */
/* -------------------------------------------------------------------------- */
static void argos_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32]) {
    sha256_ctx ctx; uint8_t k[64] = { 0 }, ipad[64], opad[64], inner[32]; size_t i;
    if (key_len > 64U) { argos_sha256_init(&ctx); argos_sha256_update(&ctx, key, key_len); argos_sha256_final(&ctx, k); } 
    else if (key_len != 0U) { memcpy(k, key, key_len); }
    for (i = 0; i < 64U; ++i) { ipad[i] = k[i] ^ 0x36U; opad[i] = k[i] ^ 0x5cU; }
    argos_sha256_init(&ctx); argos_sha256_update(&ctx, ipad, sizeof(ipad)); argos_sha256_update(&ctx, data, data_len); argos_sha256_final(&ctx, inner);
    argos_sha256_init(&ctx); argos_sha256_update(&ctx, opad, sizeof(opad)); argos_sha256_update(&ctx, inner, sizeof(inner)); argos_sha256_final(&ctx, out);
}

/* -------------------------------------------------------------------------- */
/* HKDF                                                                        */
/* -------------------------------------------------------------------------- */
static void argos_hkdf_extract_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
    argos_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static int argos_hkdf_expand_label(const uint8_t prk[32], const char *label, uint16_t out_len, uint8_t *out) {
    size_t label_len, full_label_len, info_len; uint8_t info[256], t[32], prev[32];
    size_t generated = 0U; unsigned block = 1U;
    if (label == NULL || out == NULL) return 0;
    label_len = strlen(label);
    if (10U + label_len > sizeof(info)) return 0;
    if (out_len == 0U) return 1;
    full_label_len = 6U + label_len; info_len = 0U;
    info[info_len++] = (uint8_t)(out_len >> 8); info[info_len++] = (uint8_t)(out_len & 0xffU);
    info[info_len++] = (uint8_t)full_label_len;
    memcpy(info + info_len, "tls13 ", 6U); info_len += 6U;
    memcpy(info + info_len, label, label_len); info_len += label_len;
    info[info_len++] = 0U; 
    memset(prev, 0, sizeof(prev));

    while (generated < out_len) {
        uint8_t hmac_input[256 + 32 + 1]; size_t hlen = 0U, take;
        if (block == 0U || block > 255U) return 0;
        if (block != 1U) { memcpy(hmac_input + hlen, prev, 32U); hlen += 32U; }
        memcpy(hmac_input + hlen, info, info_len); hlen += info_len;
        hmac_input[hlen++] = (uint8_t)block;
        argos_hmac_sha256(prk, 32U, hmac_input, hlen, t);
        memcpy(prev, t, 32U);
        take = (size_t)out_len - generated; if (take > 32U) take = 32U;
        memcpy(out + generated, t, take); generated += take; ++block;
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* AES-128                                                                     */
/* -------------------------------------------------------------------------- */
static const uint8_t argos_aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t argos_aes_rcon[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
static uint8_t argos_aes_xtime(uint8_t x) {
    return (uint8_t)(((uint32_t)x << 1U) ^ ((((uint32_t)x >> 7U) & 1U) * 0x1bU));
}

static void argos_aes128_expand_key(const uint8_t key[16], uint8_t exp_key[176]) {
    int i; memcpy(exp_key, key, 16U);
    for (i = 16; i < 176; i += 4) {
        uint8_t t[4] = { exp_key[i - 4], exp_key[i - 3], exp_key[i - 2], exp_key[i - 1] };
        if ((i & 15) == 0) {
            uint8_t k = t[0]; t[0] = argos_aes_sbox[t[1]] ^ argos_aes_rcon[i / 16]; t[1] = argos_aes_sbox[t[2]]; t[2] = argos_aes_sbox[t[3]]; t[3] = argos_aes_sbox[k];
        }
        exp_key[i] = exp_key[i - 16] ^ t[0]; exp_key[i + 1] = exp_key[i - 15] ^ t[1];
        exp_key[i + 2] = exp_key[i - 14] ^ t[2]; exp_key[i + 3] = exp_key[i - 13] ^ t[3];
    }
}

static void argos_aes128_encrypt_block(const uint8_t exp_key[176], uint8_t block[16]) {
    int round, j, c; for (j = 0; j < 16; ++j) block[j] ^= exp_key[j];
    for (round = 1; round <= 10; ++round) {
        uint8_t t; for (j = 0; j < 16; ++j) block[j] = argos_aes_sbox[block[j]];
        t = block[1]; block[1] = block[5]; block[5] = block[9]; block[9] = block[13]; block[13] = t;
        t = block[2]; block[2] = block[10]; block[10] = t; t = block[6]; block[6] = block[14]; block[14] = t;
        t = block[3]; block[3] = block[15]; block[15] = block[11]; block[11] = block[7]; block[7] = t;
        if (round != 10) {
            for (c = 0; c < 4; ++c) {
                uint8_t *v = block + (c * 4), a = v[0], b = v[1], cc = v[2], d = v[3];
                uint8_t x = (uint8_t)(a ^ b ^ cc ^ d);
                v[0] ^= x ^ argos_aes_xtime((uint8_t)(a ^ b)); v[1] ^= x ^ argos_aes_xtime((uint8_t)(b ^ cc));
                v[2] ^= x ^ argos_aes_xtime((uint8_t)(cc ^ d)); v[3] ^= x ^ argos_aes_xtime((uint8_t)(d ^ a));
            }
        }
        for (j = 0; j < 16; ++j) block[j] ^= exp_key[round * 16 + j];
    }
}

/* -------------------------------------------------------------------------- */
/* AES-GCM                                                                     */
/* -------------------------------------------------------------------------- */
static void argos_xor16(uint8_t a[16], const uint8_t b[16]) { size_t i; for (i = 0; i < 16U; ++i) a[i] ^= b[i]; }
static void argos_shift_right_one(uint8_t v[16]) {
    int i; uint8_t carry = 0U;
    for (i = 0; i < 16; ++i) { uint8_t next = (uint8_t)(v[i] & 1U); v[i] = (uint8_t)((v[i] >> 1) | (carry << 7)); carry = next; }
}

static void argos_ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = { 0 }, v[16]; unsigned i, bit; memcpy(v, h, 16U);
    for (i = 0; i < 128U; ++i) {
        bit = (unsigned)((x[i / 8U] >> (7U - (i % 8U))) & 1U);
        if (bit) argos_xor16(z, v);
        if (v[15] & 1U) { argos_shift_right_one(v); v[0] ^= 0xe1U; } else { argos_shift_right_one(v); }
    }
    memcpy(x, z, 16U);
}

static void argos_ghash_update_block(uint8_t y[16], const uint8_t h[16], const uint8_t *block, size_t len) {
    uint8_t x[16] = { 0 }; if (len > 16U) len = 16U; if (len != 0U) memcpy(x, block, len);
    argos_xor16(y, x); argos_ghash_mul(y, h);
}

static void argos_ghash(const uint8_t h[16], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t out[16]) {
    uint8_t y[16] = { 0 }, len_block[16] = { 0 }; size_t pos = 0U;
    while (pos < aad_len) { size_t take = aad_len - pos; if (take > 16U) take = 16U; argos_ghash_update_block(y, h, aad + pos, take); pos += take; }
    pos = 0U;
    while (pos < ciphertext_len) { size_t take = ciphertext_len - pos; if (take > 16U) take = 16U; argos_ghash_update_block(y, h, ciphertext + pos, take); pos += take; }
    uint64_t a_bits = (uint64_t)aad_len * 8U, c_bits = (uint64_t)ciphertext_len * 8U; int i;
    for (i = 0; i < 8; ++i) { len_block[i] = (uint8_t)(a_bits >> (56 - 8 * i)); len_block[8 + i] = (uint8_t)(c_bits >> (56 - 8 * i)); }
    argos_ghash_update_block(y, h, len_block, 16U); memcpy(out, y, 16U);
}

static void argos_inc32(uint8_t block[16]) { int i; for (i = 15; i >= 12; --i) { if (++block[i] != 0U) break; } }
static int argos_ct_equal16(const uint8_t a[16], const uint8_t b[16]) { uint8_t diff = 0U; size_t i; for (i = 0; i < 16U; ++i) diff |= (uint8_t)(a[i] ^ b[i]); return diff == 0U; }

static int argos_aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext) {
    uint8_t exp_key[176], h[16] = { 0 }, j0[16] = { 0 }, counter[16], s[16], tag[16]; size_t plain_len, pos;
    if (key == NULL || iv == NULL || ciphertext == NULL || plaintext == NULL || ciphertext_len < 16U) return 0;
    plain_len = ciphertext_len - 16U; memcpy(j0, iv, 12U); j0[15] = 1U;
    argos_aes128_expand_key(key, exp_key); memcpy(h, j0, 16U); memset(h, 0, 16U); argos_aes128_encrypt_block(exp_key, h);
    /* Authenticate before writing plaintext. Besides avoiding CTR work for forged
     * packets, this permits caller-owned AAD/plaintext scratch to alias safely. */
    argos_ghash(h, aad, aad_len, ciphertext, plain_len, s);
    uint8_t e_j0[16]; memcpy(e_j0, j0, 16U); argos_aes128_encrypt_block(exp_key, e_j0); argos_xor16(e_j0, s); memcpy(tag, e_j0, 16U);
    if (!argos_ct_equal16(tag, ciphertext + plain_len)) return 0;
    memcpy(counter, j0, 16U); argos_inc32(counter); pos = 0U;
    while (pos < plain_len) {
        uint8_t stream[16]; size_t take = plain_len - pos; if (take > 16U) take = 16U;
        memcpy(stream, counter, 16U); argos_aes128_encrypt_block(exp_key, stream);
        for (size_t i = 0; i < take; ++i) plaintext[pos + i] = ciphertext[pos + i] ^ stream[i];
        argos_inc32(counter); pos += take;
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* QUIC Initial version profiles (RFC 9001 v1 + RFC 9369 v2)                  */
/* -------------------------------------------------------------------------- */
#define ARGOS_QUIC_VERSION_V1 0x00000001U
#define ARGOS_QUIC_VERSION_V2 0x6b3343cfU
static const uint8_t ARGOS_QUIC_V1_SALT[20] = { 0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a };
static const uint8_t ARGOS_QUIC_V2_SALT[20] = { 0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9 };
#define ARGOS_QUIC_MAX_CRYPTO 8192U
#define ARGOS_QUIC_FAKE_TLS_HEADER 5U
#define ARGOS_QUIC_FAKE_TLS_CAP 8192U
#define ARGOS_QUIC_MAX_PACKET 65535U
#define ARGOS_QUIC_SUCCESS_SLOTS 64U
#define ARGOS_QUIC_SUCCESS_TTL_SECS 15
#define ARGOS_QUIC_WORKSPACE_BYTES \
    (ARGOS_QUIC_MAX_PACKET + ARGOS_QUIC_MAX_CRYPTO + ARGOS_QUIC_FAKE_TLS_CAP)

typedef struct quic_session quic_session_t;
typedef struct {
    uint64_t key;
    time_t last_seen;
    uint8_t valid;
} argos_quic_success_entry_t;

typedef struct {
    uint8_t *workspace;
    uint8_t *packet_scratch;
    uint8_t *present;
    uint8_t *fake_tls;
    quic_session_t *sessions;
    argos_quic_success_entry_t success[ARGOS_QUIC_SUCCESS_SLOTS];
} argos_quic_state_t;

typedef struct {
    uint32_t version;
    uint8_t initial_type;
    const uint8_t *salt;
    size_t salt_len;
    const char *key_label;
    const char *iv_label;
    const char *hp_label;
} argos_quic_initial_profile_t;

static int argos_quic_initial_profile(uint32_t version, argos_quic_initial_profile_t *profile) {
    if (profile == NULL) return 0;
    memset(profile, 0, sizeof(*profile));
    profile->version = version;
    if (version == ARGOS_QUIC_VERSION_V1) {
        profile->initial_type = 0U;
        profile->salt = ARGOS_QUIC_V1_SALT; profile->salt_len = sizeof(ARGOS_QUIC_V1_SALT);
        profile->key_label = "quic key"; profile->iv_label = "quic iv"; profile->hp_label = "quic hp";
        return 1;
    }
    if (version == ARGOS_QUIC_VERSION_V2) {
        profile->initial_type = 1U;
        profile->salt = ARGOS_QUIC_V2_SALT; profile->salt_len = sizeof(ARGOS_QUIC_V2_SALT);
        profile->key_label = "quicv2 key"; profile->iv_label = "quicv2 iv"; profile->hp_label = "quicv2 hp";
        return 1;
    }
    return 0;
}

static int argos_quic_packet_profile(const uint8_t *packet, size_t packet_len,
                                     argos_quic_initial_profile_t *profile) {
    if (packet == NULL || packet_len < 5U || profile == NULL) return 0;
    if ((packet[0] & 0xc0U) != 0xc0U) return 0;
    uint32_t version = ((uint32_t)packet[1] << 24) | ((uint32_t)packet[2] << 16) |
                       ((uint32_t)packet[3] << 8) | (uint32_t)packet[4];
    if (!argos_quic_initial_profile(version, profile)) return 0;
    return ((packet[0] & 0x30U) >> 4) == profile->initial_type;
}

static int argos_quic_derive_client_keys(const argos_quic_initial_profile_t *profile,
                                         const uint8_t *dcid, size_t dcid_len,
                                         uint8_t key[16], uint8_t iv[12], uint8_t hp[16]) {
    uint8_t initial_secret[32], client_secret[32];
    if (profile == NULL || profile->salt == NULL || dcid == NULL || key == NULL || iv == NULL || hp == NULL) return 0;
    argos_hkdf_extract_sha256(profile->salt, profile->salt_len, dcid, dcid_len, initial_secret);
    if (!argos_hkdf_expand_label(initial_secret, "client in", 32U, client_secret)) return 0;
    if (!argos_hkdf_expand_label(client_secret, profile->key_label, 16U, key)) return 0;
    if (!argos_hkdf_expand_label(client_secret, profile->iv_label, 12U, iv)) return 0;
    if (!argos_hkdf_expand_label(client_secret, profile->hp_label, 16U, hp)) return 0;
    return 1;
}

static int argos_quic_read_varint(const uint8_t *buf, size_t len, size_t *pos, uint64_t *value) {
    if (buf == NULL || pos == NULL || value == NULL || *pos >= len) return 0;
    uint8_t first = buf[*pos]; unsigned prefix = first >> 6; size_t n = (size_t)1U << prefix;
    if (n > len - *pos) return 0;
    uint64_t v = (uint64_t)(first & 0x3fU); for (size_t i = 1U; i < n; ++i) v = (v << 8) | buf[*pos + i];
    *pos += n; *value = v; return 1;
}

static int argos_quic_skip_ack(const uint8_t *buf, size_t len, size_t *pos, int ecn) {
    uint64_t largest, delay, range_count, first_range, range, i;
    if (!argos_quic_read_varint(buf, len, pos, &largest)) return 0;
    if (!argos_quic_read_varint(buf, len, pos, &delay)) return 0;
    if (!argos_quic_read_varint(buf, len, pos, &range_count)) return 0;
    if (!argos_quic_read_varint(buf, len, pos, &first_range)) return 0;
    for (i = 0; i < range_count; ++i) {
        if (!argos_quic_read_varint(buf, len, pos, &range)) return 0;
        if (!argos_quic_read_varint(buf, len, pos, &range)) return 0;
    }
    if (ecn) {
        if (!argos_quic_read_varint(buf, len, pos, &range)) return 0;
        if (!argos_quic_read_varint(buf, len, pos, &range)) return 0;
        if (!argos_quic_read_varint(buf, len, pos, &range)) return 0;
    }
    return 1;
}

static int argos_quic_extract_clienthello(const uint8_t *frames, size_t frames_len,
                                          uint8_t *hello, size_t hello_cap,
                                          uint8_t *present, size_t present_cap,
                                          size_t *hello_len) {
    size_t pos = 0U, crypto_cap = frames_len, contiguous = 0U; uint64_t i;
    if (hello == NULL || present == NULL || hello_len == NULL || hello_cap < 4U) return 0;
    *hello_len = 0U;
    if (frames == NULL || frames_len == 0U) return 0;
    if (crypto_cap > ARGOS_QUIC_MAX_CRYPTO) crypto_cap = ARGOS_QUIC_MAX_CRYPTO;
    if (crypto_cap > hello_cap) crypto_cap = hello_cap;
    if (crypto_cap < 4U) return 0;
    if (present_cap < crypto_cap) return 0;
    memset(present, 0, crypto_cap);

    while (pos < frames_len) {
        uint64_t frame_type;
        if (!argos_quic_read_varint(frames, frames_len, &pos, &frame_type)) break;

        if (frame_type == 0x00U || frame_type == 0x01U) continue; 
        if (frame_type == 0x02U || frame_type == 0x03U) { if (!argos_quic_skip_ack(frames, frames_len, &pos, frame_type == 0x03U)) break; continue; }
        if (frame_type == 0x06U) { 
            uint64_t offset, length;
            if (!argos_quic_read_varint(frames, frames_len, &pos, &offset)) break;
            if (!argos_quic_read_varint(frames, frames_len, &pos, &length)) break;
            if (offset > (uint64_t)crypto_cap || length > (uint64_t)crypto_cap - offset) break;
            if (length > (uint64_t)(frames_len - pos)) break;
            if (length != 0U) { memcpy(hello + (size_t)offset, frames + pos, (size_t)length); memset(present + (size_t)offset, 1, (size_t)length); }
            pos += (size_t)length; continue;
        }
        break; /* Stop cleanly when an unknown frame type is encountered. */
    }

    if (present[0] == 0U || hello[0] != 0x01U) return 0;
    if (present[1] == 0U || present[2] == 0U || present[3] == 0U) return 0;
    {
        size_t body_len = ((size_t)hello[1] << 16) | ((size_t)hello[2] << 8) | (size_t)hello[3];
        size_t total = 4U + body_len;
        if (total < 4U || total > crypto_cap || total > hello_cap) return 0;
        for (i = 0U; i < (uint64_t)total; ++i) if (present[i] == 0U) return 0;
        contiguous = total;
    }
    *hello_len = contiguous; return 1;
}

static inline int decrypt_quic_sni(argos_quic_state_t *state,
                                   const uint8_t *packet, int pkt_len,
                                   int dcid_pos, int dcid_len,
                                   uint8_t *fake_tls_buf, int fake_tls_buf_cap,
                                   int *fake_tls_len) {
    uint8_t quic_key[16], quic_iv[12], quic_hp[16], hp_exp_key[176], sample[16], mask[16];
    argos_quic_initial_profile_t profile;
    uint8_t *decrypted, *hello; uint8_t unprotected_first;
    size_t pos, packet_end, pn_offset, payload_offset, payload_len, ciphertext_len, hello_len = 0U;
    uint64_t token_len, packet_length; uint32_t pn; unsigned pn_len;

    if (state == NULL || state->packet_scratch == NULL || state->present == NULL ||
        packet == NULL || fake_tls_buf == NULL || fake_tls_len == NULL) return 0;
    *fake_tls_len = 0;
    if (fake_tls_buf_cap < (int)ARGOS_QUIC_FAKE_TLS_HEADER || pkt_len <= 0 || dcid_pos < 6 || dcid_len < 0 || dcid_len > 20) return 0;
    if ((size_t)pkt_len < 7U || (size_t)dcid_pos > (size_t)pkt_len || (size_t)dcid_len > (size_t)pkt_len - (size_t)dcid_pos) return 0;

    if (!argos_quic_packet_profile(packet, (size_t)pkt_len, &profile)) return 0;
    
    pos = (size_t)dcid_pos + (size_t)dcid_len;
    if (pos >= (size_t)pkt_len) return 0;
    size_t scid_len = packet[pos]; pos += 1U;
    if (scid_len > 20U || scid_len > (size_t)pkt_len - pos) return 0;
    pos += scid_len;

    if (!argos_quic_read_varint(packet, (size_t)pkt_len, &pos, &token_len)) return 0;
    if (token_len > (uint64_t)((size_t)pkt_len - pos)) return 0;
    pos += (size_t)token_len;

    if (!argos_quic_read_varint(packet, (size_t)pkt_len, &pos, &packet_length)) return 0;
    pn_offset = pos;
    if (packet_length > (uint64_t)((size_t)pkt_len - pn_offset)) return 0;
    packet_end = pn_offset + (size_t)packet_length;

    if (packet_end < pn_offset + 4U + 16U) return 0;

    if (!argos_quic_derive_client_keys(&profile, packet + dcid_pos, (size_t)dcid_len, quic_key, quic_iv, quic_hp)) return 0;

    argos_aes128_expand_key(quic_hp, hp_exp_key);
    memcpy(sample, packet + pn_offset + 4U, 16U); memcpy(mask, sample, 16U);
    argos_aes128_encrypt_block(hp_exp_key, mask);

    unprotected_first = (uint8_t)(packet[0] ^ (mask[0] & 0x0fU));
    if ((unprotected_first & 0x0cU) != 0U) return 0;

    pn_len = (unsigned)((unprotected_first & 0x03U) + 1U);
    if (pn_offset + pn_len > packet_end) return 0;
    
    size_t aad_len = pn_offset + (size_t)pn_len;
    if (aad_len > ARGOS_QUIC_MAX_PACKET) return 0;
    uint8_t *aad = state->packet_scratch;
    memcpy(aad, packet, aad_len); aad[0] = unprotected_first; pn = 0U;
    for (unsigned i = 0; i < pn_len; ++i) { aad[pn_offset + i] = (uint8_t)(packet[pn_offset + i] ^ mask[1U + i]); pn = (pn << 8) | aad[pn_offset + i]; }

    payload_offset = pn_offset + (size_t)pn_len; payload_len = packet_end - payload_offset;
    if (payload_len <= 16U || payload_len > ARGOS_QUIC_MAX_PACKET) return 0;
    ciphertext_len = payload_len;

    decrypted = state->packet_scratch; /* Safe alias: GCM authenticates AAD first. */
    uint8_t nonce[12]; memcpy(nonce, quic_iv, sizeof(nonce));
    nonce[8] ^= (uint8_t)(pn >> 24); nonce[9] ^= (uint8_t)(pn >> 16); nonce[10] ^= (uint8_t)(pn >> 8); nonce[11] ^= (uint8_t)pn;

    if (!argos_aes128_gcm_decrypt(quic_key, nonce, aad, aad_len, packet + payload_offset, ciphertext_len, decrypted)) {
        return 0;
    }

    hello = fake_tls_buf + ARGOS_QUIC_FAKE_TLS_HEADER;
    if (!argos_quic_extract_clienthello(decrypted, payload_len - 16U,
                                        hello, (size_t)fake_tls_buf_cap - ARGOS_QUIC_FAKE_TLS_HEADER,
                                        state->present, ARGOS_QUIC_MAX_CRYPTO, &hello_len)) {
        return 0;
    }

    if (hello_len + ARGOS_QUIC_FAKE_TLS_HEADER > (size_t)fake_tls_buf_cap) {
        return 0;
    }

    fake_tls_buf[0] = 0x16U; fake_tls_buf[1] = 0x03U; fake_tls_buf[2] = 0x01U;
    fake_tls_buf[3] = (uint8_t)(hello_len >> 8); fake_tls_buf[4] = (uint8_t)(hello_len & 0xffU);
    *fake_tls_len = (int)(hello_len + ARGOS_QUIC_FAKE_TLS_HEADER);

    return 1;
}



/* ========================================================================== */
/* Stateful QUIC engine                                                       */
/*
 * Optional runtime layer used by -W. It deliberately shares the stateless
 * Initial crypto/VarInt primitives above. Its table is prepared only for an
 * enabled -W engine before capture, so the default gateway footprint is unchanged.
 * ========================================================================== */
#define QUIC_STATE_SLOTS 64
#define QUIC_STATE_TTL 5 /* Short TTL bounds retained reassembly state. */

struct quic_session {
    uint8_t dcid[20];
    int dcid_len;
    uint32_t version;
    int used;
    uint8_t crypto_buf[8192];
    uint8_t present[8192 / 8];
    uint64_t largest_pn;
    int have_pn;
    time_t last_seen;
};

/* Prepare at a lifecycle boundary, never from packet processing. Stateless
 * scratch is one reusable block. Heavy reassembly remains a separate -W-only
 * allocation; partial failure is retained for an explicit later retry. */
static inline int argos_quic_prepare(argos_quic_state_t *state, int heavy) {
    if (!state) return 0;
    if (!state->workspace) {
        state->workspace = (uint8_t *)calloc(1U, ARGOS_QUIC_WORKSPACE_BYTES);
        if (state->workspace) {
            state->packet_scratch = state->workspace;
            state->present = state->workspace + ARGOS_QUIC_MAX_PACKET;
            state->fake_tls = state->present + ARGOS_QUIC_MAX_CRYPTO;
        }
    }
    if (state->workspace && heavy && !state->sessions)
        state->sessions = (quic_session_t *)calloc(QUIC_STATE_SLOTS,
                                                   sizeof(*state->sessions));
    return state->workspace != NULL && (!heavy || state->sessions != NULL);
}

static inline void argos_quic_destroy(argos_quic_state_t *state) {
    if (!state) return;
    free(state->sessions);
    free(state->workspace);
    memset(state, 0, sizeof(*state));
}

/* Direct-slot post-success suppression is intentionally independent from
 * Initial reassembly. Collisions replace one slot; rollback/expiry fail open. */
static inline int argos_quic_success_recent_at(argos_quic_state_t *state,
                                               uint64_t key, time_t now) {
    if (!state) return 0;
    argos_quic_success_entry_t *e =
        &state->success[(size_t)(key & (ARGOS_QUIC_SUCCESS_SLOTS - 1U))];
    if (!e->valid || e->key != key) return 0;
    if (now < e->last_seen ||
        (now - e->last_seen) > ARGOS_QUIC_SUCCESS_TTL_SECS) {
        e->valid = 0U;
        return 0;
    }
    return 1;
}

static inline int argos_quic_success_recent(argos_quic_state_t *state, uint64_t key) {
    return argos_quic_success_recent_at(state, key, time(NULL));
}

static inline void argos_quic_mark_success_at(argos_quic_state_t *state,
                                              uint64_t key, time_t now) {
    if (!state) return;
    argos_quic_success_entry_t *e =
        &state->success[(size_t)(key & (ARGOS_QUIC_SUCCESS_SLOTS - 1U))];
    e->key = key;
    e->last_seen = now;
    e->valid = 1U;
}

static inline void argos_quic_mark_success(argos_quic_state_t *state, uint64_t key) {
    argos_quic_mark_success_at(state, key, time(NULL));
}


/* Presence is tracked as one bit per CRYPTO byte instead of one byte per
 * CRYPTO byte. This cuts the reassembly table by almost half while preserving
 * exact out-of-order fragment tracking. */
static inline void quic_present_set_range(quic_session_t *s, size_t off, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        size_t bit = off + i;
        s->present[bit >> 3] |= (uint8_t)(1U << (bit & 7U));
    }
}

static inline int quic_present_test(const quic_session_t *s, size_t off) {
    return (s->present[off >> 3] & (uint8_t)(1U << (off & 7U))) != 0U;
}

static inline void quic_heavy_gc_at(argos_quic_state_t *state, time_t now) {
    if (!state || !state->sessions) return;
    for (int i=0; i<QUIC_STATE_SLOTS; i++) {
        if (state->sessions[i].used &&
            (now < state->sessions[i].last_seen ||
             (now - state->sessions[i].last_seen) > QUIC_STATE_TTL)) {
            memset(&state->sessions[i], 0, sizeof(state->sessions[i])); /* Evict stale state */
        }
    }
}

static inline void quic_heavy_gc(argos_quic_state_t *state) {
    quic_heavy_gc_at(state, time(NULL));
}

static int quic_heavy_find_session(argos_quic_state_t *state,
                                   uint32_t version, const uint8_t *dcid, int dcid_len) {
    if (!state || !state->sessions) return -1;
    for (int i = 0; i < QUIC_STATE_SLOTS; i++) {
        if (state->sessions[i].used && state->sessions[i].version == version &&
            state->sessions[i].dcid_len == dcid_len &&
            memcmp(state->sessions[i].dcid, dcid, (size_t)dcid_len) == 0) return i;
    }
    return -1;
}

static int quic_heavy_get_or_create_session(argos_quic_state_t *state,
                                            uint32_t version, const uint8_t *dcid, int dcid_len) {
    if (!state || !state->sessions) return -1;
    int slot = quic_heavy_find_session(state, version, dcid, dcid_len);
    if (slot >= 0) return slot;
    for (int i = 0; i < QUIC_STATE_SLOTS; i++) {
        if (!state->sessions[i].used) {
            memset(&state->sessions[i], 0, sizeof(state->sessions[i]));
            state->sessions[i].used = 1;
            state->sessions[i].version = version;
            state->sessions[i].dcid_len = dcid_len;
            if (dcid_len > 0) memcpy(state->sessions[i].dcid, dcid, (size_t)dcid_len);
            return i;
        }
    }
    return -1;
}

static uint64_t quic_heavy_reconstruct_pn(argos_quic_state_t *state, int slot,
                                          uint32_t truncated_pn, unsigned pn_len) {
    const uint64_t pn_win = 1ULL << (8U * pn_len);
    const uint64_t pn_hwin = pn_win / 2U;
    const uint64_t pn_mask = pn_win - 1U;
    uint64_t expected = state->sessions[slot].have_pn ? state->sessions[slot].largest_pn + 1U : 0U;
    uint64_t candidate = (expected & ~pn_mask) | (uint64_t)truncated_pn;
    if (candidate + pn_hwin <= expected) candidate += pn_win;
    else if (candidate > expected + pn_hwin && candidate >= pn_win) candidate -= pn_win;
    return candidate;
}

static int argos_quic_extract_stateful(argos_quic_state_t *state,
                                       const uint8_t *frames, size_t frames_len,
                                       uint32_t version, const uint8_t *dcid, int dcid_len,
                                       uint8_t *hello, size_t hello_cap, size_t *hello_len) {
    *hello_len = 0;
    if (!frames || !dcid || dcid_len < 0 || dcid_len > 20 || !hello || hello_cap < 4U) return 0;

    size_t pos = 0;
    int slot = quic_heavy_get_or_create_session(state, version, dcid, dcid_len);
    if (slot < 0) return 0;
    time_t now = time(NULL);
    state->sessions[slot].last_seen = now;

    /* Parse and reassemble CRYPTO fragments. */
    while (pos < frames_len) {
        uint64_t frame_type;
        if (!argos_quic_read_varint(frames, frames_len, &pos, &frame_type)) break;

        if (frame_type == 0x00U || frame_type == 0x01U) continue;
        if (frame_type == 0x02U || frame_type == 0x03U) { if (!argos_quic_skip_ack(frames, frames_len, &pos, frame_type == 0x03U)) break; continue; }
        if (frame_type == 0x06U) { /* CRYPTO FRAME */
            uint64_t offset, length;
            if (!argos_quic_read_varint(frames, frames_len, &pos, &offset)) break;
            if (!argos_quic_read_varint(frames, frames_len, &pos, &length)) break;

            /* Store the fragment at its exact CRYPTO offset. */
            if (offset > sizeof(state->sessions[slot].crypto_buf) ||
                length > sizeof(state->sessions[slot].crypto_buf) - offset ||
                length > frames_len - pos) break;
            size_t frag_offset = (size_t)offset;
            size_t frag_length = (size_t)length;
            memcpy(state->sessions[slot].crypto_buf + frag_offset, frames + pos, frag_length);
            quic_present_set_range(&state->sessions[slot], frag_offset, frag_length);
            pos += frag_length;
            continue;
        }
        break;
    }

    /* Check whether the complete TLS ClientHello is now available. */
    if (quic_present_test(&state->sessions[slot], 0U) && state->sessions[slot].crypto_buf[0] == 0x01) {
        if (quic_present_test(&state->sessions[slot], 1U) && quic_present_test(&state->sessions[slot], 2U) && quic_present_test(&state->sessions[slot], 3U)) {
            size_t ch_len = ((size_t)state->sessions[slot].crypto_buf[1] << 16U) |
                            ((size_t)state->sessions[slot].crypto_buf[2] << 8U) |
                            (size_t)state->sessions[slot].crypto_buf[3];
            size_t total = 4 + ch_len;
            if (total <= sizeof(state->sessions[slot].crypto_buf) && total <= hello_cap) {
                int complete = 1;
                for (size_t i=0; i<total; i++) {
                    if (!quic_present_test(&state->sessions[slot], i)) { complete = 0; break; }
                }
                if (complete) {
                    /* Success: the ClientHello is fully reassembled. */
                    memcpy(hello, state->sessions[slot].crypto_buf, total);
                    *hello_len = total;
                    memset(&state->sessions[slot], 0, sizeof(state->sessions[slot])); /* Evict completed session */
                    return 1;
                }
            }
        }
    }
    return 0; /* More Initial packets may complete the ClientHello. */
}

static inline int decrypt_quic_sni_stateful(argos_quic_state_t *state,
                                            const uint8_t *packet, int pkt_len,
                                            int dcid_pos, int dcid_len,
                                            uint8_t *fake_tls_buf, int fake_tls_buf_cap,
                                            int *fake_tls_len) {
    uint8_t quic_key[16], quic_iv[12], quic_hp[16], hp_exp_key[176], sample[16], mask[16];
    argos_quic_initial_profile_t profile;
    uint8_t *decrypted, *hello; uint8_t unprotected_first;
    size_t pos, packet_end, pn_offset, payload_offset, payload_len, ciphertext_len, hello_len = 0U;
    uint64_t token_len, packet_length; uint32_t truncated_pn; uint64_t pn; unsigned pn_len;

    if (fake_tls_len == NULL) return -1;
    *fake_tls_len = 0;
    if (state == NULL || state->packet_scratch == NULL || state->sessions == NULL ||
        packet == NULL || fake_tls_buf == NULL) return -1;
    if (fake_tls_buf_cap < 5 || pkt_len <= 0 || dcid_pos < 6 || dcid_len < 0 || dcid_len > 20) return -1;
    if ((size_t)pkt_len < 7U || (size_t)dcid_pos > (size_t)pkt_len || (size_t)dcid_len > (size_t)pkt_len - (size_t)dcid_pos) return -1;
    if (!argos_quic_packet_profile(packet, (size_t)pkt_len, &profile)) return -1;

    pos = (size_t)dcid_pos + (size_t)dcid_len;
    if (pos >= (size_t)pkt_len) return -1;
    size_t scid_len = packet[pos]; pos += 1U;
    if (scid_len > 20U || scid_len > (size_t)pkt_len - pos) return -1;
    pos += scid_len;

    if (!argos_quic_read_varint(packet, (size_t)pkt_len, &pos, &token_len)) return -1;
    if (token_len > (uint64_t)((size_t)pkt_len - pos)) return -1;
    pos += (size_t)token_len;

    if (!argos_quic_read_varint(packet, (size_t)pkt_len, &pos, &packet_length)) return -1;
    pn_offset = pos;
    if (packet_length > (uint64_t)((size_t)pkt_len - pn_offset)) return -1;
    packet_end = pn_offset + (size_t)packet_length;

    if (packet_end < pn_offset + 4U + 16U) return -1;

    if (!argos_quic_derive_client_keys(&profile, packet + dcid_pos, (size_t)dcid_len, quic_key, quic_iv, quic_hp)) return -1;

    argos_aes128_expand_key(quic_hp, hp_exp_key);
    memcpy(sample, packet + pn_offset + 4U, 16U); memcpy(mask, sample, 16U);
    argos_aes128_encrypt_block(hp_exp_key, mask);

    unprotected_first = (uint8_t)(packet[0] ^ (mask[0] & 0x0fU));
    if ((unprotected_first & 0x0cU) != 0U) return -1;

    pn_len = (unsigned)((unprotected_first & 0x03U) + 1U);
    if (pn_offset + pn_len > packet_end) return -1;

    size_t aad_len = pn_offset + (size_t)pn_len;
    if (aad_len > ARGOS_QUIC_MAX_PACKET) return -1;
    uint8_t *aad = state->packet_scratch;
    memcpy(aad, packet, aad_len); aad[0] = unprotected_first; truncated_pn = 0U;
    for (unsigned i = 0; i < pn_len; ++i) { aad[pn_offset + i] = (uint8_t)(packet[pn_offset + i] ^ mask[1U + i]); truncated_pn = (truncated_pn << 8) | aad[pn_offset + i]; }

    int session_slot = quic_heavy_get_or_create_session(state, profile.version,
                                                        packet + dcid_pos, dcid_len);
    if (session_slot < 0) return -1;
    pn = quic_heavy_reconstruct_pn(state, session_slot, truncated_pn, pn_len);

    payload_offset = pn_offset + (size_t)pn_len; payload_len = packet_end - payload_offset;
    if (payload_len <= 16U || payload_len > ARGOS_QUIC_MAX_PACKET) return -1;
    ciphertext_len = payload_len;

    decrypted = state->packet_scratch; /* Safe alias: GCM authenticates AAD first. */
    uint8_t nonce[12]; memcpy(nonce, quic_iv, sizeof(nonce));
    nonce[8] ^= (uint8_t)(pn >> 24); nonce[9] ^= (uint8_t)(pn >> 16); nonce[10] ^= (uint8_t)(pn >> 8); nonce[11] ^= (uint8_t)pn;

    if (!argos_aes128_gcm_decrypt(quic_key, nonce, aad, aad_len, packet + payload_offset, ciphertext_len, decrypted)) {
        return -1;
    }
    state->sessions[session_slot].largest_pn = pn;
    state->sessions[session_slot].have_pn = 1;
    state->sessions[session_slot].last_seen = time(NULL);

    hello = fake_tls_buf + ARGOS_QUIC_FAKE_TLS_HEADER;
    /* Stateful extraction reassembles CRYPTO frames across Initial packets. */
    if (!argos_quic_extract_stateful(state, decrypted, payload_len - 16U,
                                     profile.version, packet + dcid_pos, dcid_len,
                                     hello, (size_t)fake_tls_buf_cap - ARGOS_QUIC_FAKE_TLS_HEADER,
                                     &hello_len)) {
        /* Authenticated Initial, but the CRYPTO stream is not complete yet. */
        return 0;
    }

    if (hello_len + ARGOS_QUIC_FAKE_TLS_HEADER > (size_t)fake_tls_buf_cap) return -1;

    fake_tls_buf[0] = 0x16U; fake_tls_buf[1] = 0x03U; fake_tls_buf[2] = 0x01U;
    fake_tls_buf[3] = (uint8_t)(hello_len >> 8); fake_tls_buf[4] = (uint8_t)(hello_len & 0xffU);
    *fake_tls_len = (int)(hello_len + 5);

    return 1;
}

#endif /* ARGOS_QUIC_H */
