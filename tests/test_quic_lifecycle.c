#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned calls, frees, live, hot, fail_call;
static size_t allocated_bytes;
static void *tracked_calloc(size_t n, size_t bytes) {
    assert(!hot); ++calls;
    if (calls == fail_call) return NULL;
    void *p = calloc(n, bytes); assert(p); ++live; allocated_bytes += n * bytes; return p;
}
static void tracked_free(void *p) {
    assert(!hot); if (p) { assert(live); --live; ++frees; free(p); }
}
#define calloc tracked_calloc
#define free tracked_free
#include "../src/argos_quic.h"
#undef calloc
#undef free

static void gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plain, size_t plain_len, uint8_t *out) {
    uint8_t expanded[176], h[16] = {0}, j0[16] = {0}, counter[16], s[16];
    argos_aes128_expand_key(key, expanded);
    argos_aes128_encrypt_block(expanded, h);
    memcpy(j0, iv, 12); j0[15] = 1;
    memcpy(counter, j0, 16); argos_inc32(counter);
    for (size_t pos = 0; pos < plain_len;) {
        uint8_t stream[16]; size_t take = plain_len - pos; if (take > 16) take = 16;
        memcpy(stream, counter, 16); argos_aes128_encrypt_block(expanded, stream);
        for (size_t i = 0; i < take; ++i) out[pos + i] = plain[pos + i] ^ stream[i];
        argos_inc32(counter); pos += take;
    }
    argos_ghash(h, aad, aad_len, out, plain_len, s);
    argos_aes128_encrypt_block(expanded, j0); argos_xor16(j0, s);
    memcpy(out + plain_len, j0, 16);
}

/* Build a deterministic valid v1 Initial with one complete eight-byte
 * ClientHello-shaped CRYPTO value. Crypto primitives are separately pinned by
 * the RFC 9369 key fixture; this packet exercises end-to-end framing/lifecycle. */
static size_t make_initial(uint8_t packet[96]) {
    static const uint8_t dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    uint8_t plain[32] = {0x06,0x00,0x08,0x01,0x00,0x00,0x04,0xde,0xad,0xbe,0xef};
    size_t pn_offset = 17, payload_offset = 19, plain_len = sizeof(plain);
    memset(packet, 0, 96); packet[0] = 0xc1; packet[4] = 1;
    packet[5] = sizeof(dcid); memcpy(packet + 6, dcid, sizeof(dcid));
    packet[14] = 0; packet[15] = 0; packet[16] = (uint8_t)(2 + plain_len + 16);
    packet[17] = 0; packet[18] = 2;

    argos_quic_initial_profile_t profile; uint8_t key[16], iv[12], hp[16], nonce[12];
    assert(argos_quic_initial_profile(ARGOS_QUIC_VERSION_V1, &profile));
    assert(argos_quic_derive_client_keys(&profile, dcid, sizeof(dcid), key, iv, hp));
    memcpy(nonce, iv, sizeof(nonce)); nonce[11] ^= 2;
    gcm_encrypt(key, nonce, packet, payload_offset, plain, plain_len, packet + payload_offset);

    uint8_t expanded[176], mask[16];
    argos_aes128_expand_key(hp, expanded);
    memcpy(mask, packet + pn_offset + 4, 16); argos_aes128_encrypt_block(expanded, mask);
    packet[0] ^= mask[0] & 0x0f; packet[17] ^= mask[1]; packet[18] ^= mask[2];
    return payload_offset + plain_len + 16;
}

int main(void) {
    argos_quic_state_t a = {0}, b = {0}, c = {0};
    assert(!argos_quic_prepare(NULL, 0)); argos_quic_destroy(NULL);
    assert(argos_quic_prepare(&a, 0));
    assert(calls == 1 && live == 1 && allocated_bytes == ARGOS_QUIC_WORKSPACE_BYTES);
    assert(a.packet_scratch == a.workspace);
    assert(a.present == a.workspace + ARGOS_QUIC_MAX_PACKET);
    assert(a.fake_tls == a.present + ARGOS_QUIC_MAX_CRYPTO && !a.sessions);
    assert(argos_quic_prepare(&a, 0) && calls == 1);

    uint8_t packet[96]; size_t packet_len = make_initial(packet); int out_len = 0;
    hot = 1;
    assert(decrypt_quic_sni(&a, packet, (int)packet_len, 6, 8,
                            a.fake_tls, ARGOS_QUIC_FAKE_TLS_CAP, &out_len));
    assert(out_len == 13 && memcmp(a.fake_tls, "\x16\x03\x01\x00\x08\x01\x00\x00\x04\xde\xad\xbe\xef", 13) == 0);
    packet[packet_len - 1] ^= 1;
    assert(!decrypt_quic_sni(&a, packet, (int)packet_len, 6, 8,
                             a.fake_tls, ARGOS_QUIC_FAKE_TLS_CAP, &out_len));
    packet[packet_len - 1] ^= 1;
    hot = 0; assert(calls == 1);

    assert(argos_quic_prepare(&a, 1));
    size_t session_bytes = QUIC_STATE_SLOTS * sizeof(quic_session_t);
    assert(calls == 2 && live == 2 && allocated_bytes == ARGOS_QUIC_WORKSPACE_BYTES + session_bytes);
    hot = 1;
    assert(decrypt_quic_sni_stateful(&a, packet, (int)packet_len, 6, 8,
                                     a.fake_tls, ARGOS_QUIC_FAKE_TLS_CAP, &out_len) == 1);
    hot = 0; assert(calls == 2);

    fail_call = calls + 1; assert(!argos_quic_prepare(&b, 0)); fail_call = 0;
    hot = 1;
    assert(!decrypt_quic_sni(&b, packet, (int)packet_len, 6, 8, NULL, 0, &out_len));
    hot = 0; assert(calls == 3);
    assert(argos_quic_prepare(&b, 0) && calls == 4);

    assert(argos_quic_prepare(&c, 0)); fail_call = calls + 1;
    assert(!argos_quic_prepare(&c, 1) && c.workspace && !c.sessions); fail_call = 0;
    unsigned before = calls; hot = 1;
    assert(decrypt_quic_sni_stateful(&c, packet, (int)packet_len, 6, 8,
                                     c.fake_tls, ARGOS_QUIC_FAKE_TLS_CAP, &out_len) == -1);
    hot = 0; assert(calls == before);
    assert(argos_quic_prepare(&c, 1));

    argos_quic_destroy(&a); argos_quic_destroy(&a);
    argos_quic_destroy(&b); argos_quic_destroy(&c); argos_quic_destroy(&c);
    assert(!live && frees == 5);
    printf("QUIC lifecycle/success/failure/no packet allocation: PASS; scratch=%u heavy=%zu bytes\n",
           (unsigned)ARGOS_QUIC_WORKSPACE_BYTES, session_bytes);
    return 0;
}
