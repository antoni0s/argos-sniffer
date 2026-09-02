/* ============================================================================
 * argos_quic_heavy.h - Stateful QUIC v1/v2 Reassembler & Extractor
 * ============================================================================ */
#ifndef ARGOS_QUIC_HEAVY_H
#define ARGOS_QUIC_HEAVY_H

#include <time.h>
#include <stddef.h>

/* argos_quic.h must be included before this header so the stateful layer can
 * reuse the HKDF, AES-GCM and QUIC VarInt primitives. */

#define QUIC_STATE_SLOTS 64
#define QUIC_STATE_TTL 5 /* Short TTL bounds retained reassembly state. */

typedef struct {
    uint8_t dcid[20];
    int dcid_len;
    uint32_t version;
    int used;
    uint8_t crypto_buf[8192];
    uint8_t present[8192 / 8];
    uint64_t largest_pn;
    int have_pn;
    time_t last_seen;
} quic_session_t;

/* Allocate the heavy table only when stateful QUIC is actually exercised.
 * This keeps the default non--W gateway footprint small. */
static quic_session_t *quic_sessions = NULL;


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

static int quic_heavy_ensure_table(void) {
    if (quic_sessions) return 1;
    quic_sessions = (quic_session_t *)calloc(QUIC_STATE_SLOTS, sizeof(*quic_sessions));
    return quic_sessions != NULL;
}

static void quic_heavy_gc(void) {
    if (!quic_sessions) return;
    time_t now = time(NULL);
    for (int i=0; i<QUIC_STATE_SLOTS; i++) {
        if (quic_sessions[i].used && (now - quic_sessions[i].last_seen) > QUIC_STATE_TTL) {
            memset(&quic_sessions[i], 0, sizeof(quic_sessions[i])); /* Evict stale state */
        }
    }
}

static int quic_heavy_find_session(uint32_t version, const uint8_t *dcid, int dcid_len) {
    if (!quic_sessions) return -1;
    for (int i = 0; i < QUIC_STATE_SLOTS; i++) {
        if (quic_sessions[i].used && quic_sessions[i].version == version &&
            quic_sessions[i].dcid_len == dcid_len &&
            memcmp(quic_sessions[i].dcid, dcid, (size_t)dcid_len) == 0) return i;
    }
    return -1;
}

static int quic_heavy_get_or_create_session(uint32_t version, const uint8_t *dcid, int dcid_len) {
    if (!quic_heavy_ensure_table()) return -1;
    int slot = quic_heavy_find_session(version, dcid, dcid_len);
    if (slot >= 0) return slot;
    for (int i = 0; i < QUIC_STATE_SLOTS; i++) {
        if (!quic_sessions[i].used) {
            memset(&quic_sessions[i], 0, sizeof(quic_sessions[i]));
            quic_sessions[i].used = 1;
            quic_sessions[i].version = version;
            quic_sessions[i].dcid_len = dcid_len;
            if (dcid_len > 0) memcpy(quic_sessions[i].dcid, dcid, (size_t)dcid_len);
            return i;
        }
    }
    return -1;
}

static uint64_t quic_heavy_reconstruct_pn(int slot, uint32_t truncated_pn, unsigned pn_len) {
    const uint64_t pn_win = 1ULL << (8U * pn_len);
    const uint64_t pn_hwin = pn_win / 2U;
    const uint64_t pn_mask = pn_win - 1U;
    uint64_t expected = quic_sessions[slot].have_pn ? quic_sessions[slot].largest_pn + 1U : 0U;
    uint64_t candidate = (expected & ~pn_mask) | (uint64_t)truncated_pn;
    if (candidate + pn_hwin <= expected) candidate += pn_win;
    else if (candidate > expected + pn_hwin && candidate >= pn_win) candidate -= pn_win;
    return candidate;
}

static int argos_quic_extract_stateful(const uint8_t *frames, size_t frames_len, uint32_t version, const uint8_t *dcid, int dcid_len, uint8_t *hello, size_t hello_cap, size_t *hello_len) {
    *hello_len = 0;
    if (!frames || !dcid || dcid_len < 0 || dcid_len > 20 || !hello || hello_cap < 4U) return 0;

    size_t pos = 0;
    int slot = quic_heavy_get_or_create_session(version, dcid, dcid_len);
    if (slot < 0) return 0;
    time_t now = time(NULL);
    quic_sessions[slot].last_seen = now;

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
            if (offset > sizeof(quic_sessions[slot].crypto_buf) ||
                length > sizeof(quic_sessions[slot].crypto_buf) - offset ||
                length > frames_len - pos) break;
            size_t frag_offset = (size_t)offset;
            size_t frag_length = (size_t)length;
            memcpy(quic_sessions[slot].crypto_buf + frag_offset, frames + pos, frag_length);
            quic_present_set_range(&quic_sessions[slot], frag_offset, frag_length);
            pos += frag_length;
            continue;
        }
        break; 
    }

    /* Check whether the complete TLS ClientHello is now available. */
    if (quic_present_test(&quic_sessions[slot], 0U) && quic_sessions[slot].crypto_buf[0] == 0x01) {
        if (quic_present_test(&quic_sessions[slot], 1U) && quic_present_test(&quic_sessions[slot], 2U) && quic_present_test(&quic_sessions[slot], 3U)) {
            size_t ch_len = ((size_t)quic_sessions[slot].crypto_buf[1] << 16U) |
                            ((size_t)quic_sessions[slot].crypto_buf[2] << 8U) |
                            (size_t)quic_sessions[slot].crypto_buf[3];
            size_t total = 4 + ch_len;
            if (total <= sizeof(quic_sessions[slot].crypto_buf) && total <= hello_cap) {
                int complete = 1;
                for (size_t i=0; i<total; i++) {
                    if (!quic_present_test(&quic_sessions[slot], i)) { complete = 0; break; }
                }
                if (complete) {
                    /* Success: the ClientHello is fully reassembled. */
                    memcpy(hello, quic_sessions[slot].crypto_buf, total);
                    *hello_len = total;
                    memset(&quic_sessions[slot], 0, sizeof(quic_sessions[slot])); /* Evict completed session */
                    return 1;
                }
            }
        }
    }
    return 0; /* More Initial packets may complete the ClientHello. */
}

static inline int decrypt_quic_sni_stateful(const uint8_t *packet, int pkt_len, int dcid_pos, int dcid_len, uint8_t *fake_tls_buf, int fake_tls_buf_cap, int *fake_tls_len) {
    uint8_t quic_key[16], quic_iv[12], quic_hp[16], hp_exp_key[176], sample[16], mask[16];
    argos_quic_initial_profile_t profile;
    uint8_t *decrypted = NULL, *hello = NULL, unprotected_first;
    size_t pos, packet_end, pn_offset, payload_offset, payload_len, ciphertext_len, hello_len = 0U;
    uint64_t token_len, packet_length; uint32_t truncated_pn; uint64_t pn; unsigned pn_len;

    *fake_tls_len = 0;
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
    uint8_t *aad = (uint8_t *)malloc(aad_len);
    if (!aad) return -1;
    memcpy(aad, packet, aad_len); aad[0] = unprotected_first; truncated_pn = 0U;
    for (unsigned i = 0; i < pn_len; ++i) { aad[pn_offset + i] = (uint8_t)(packet[pn_offset + i] ^ mask[1U + i]); truncated_pn = (truncated_pn << 8) | aad[pn_offset + i]; }

    int session_slot = quic_heavy_get_or_create_session(profile.version, packet + dcid_pos, dcid_len);
    if (session_slot < 0) { free(aad); return -1; }
    pn = quic_heavy_reconstruct_pn(session_slot, truncated_pn, pn_len);

    payload_offset = pn_offset + (size_t)pn_len; payload_len = packet_end - payload_offset;
    if (payload_len <= 16U) { free(aad); return -1; }
    ciphertext_len = payload_len;

    decrypted = (uint8_t *)malloc(payload_len - 16U);
    if (!decrypted) { free(aad); return -1; }
    uint8_t nonce[12]; memcpy(nonce, quic_iv, sizeof(nonce));
    nonce[8] ^= (uint8_t)(pn >> 24); nonce[9] ^= (uint8_t)(pn >> 16); nonce[10] ^= (uint8_t)(pn >> 8); nonce[11] ^= (uint8_t)pn;

    if (!argos_aes128_gcm_decrypt(quic_key, nonce, aad, aad_len, packet + payload_offset, ciphertext_len, decrypted)) {
        free(aad); free(decrypted); return -1;
    }
    free(aad);
    quic_sessions[session_slot].largest_pn = pn;
    quic_sessions[session_slot].have_pn = 1;
    quic_sessions[session_slot].last_seen = time(NULL);

    hello = (uint8_t *)malloc(8192U);
    if (!hello) { free(decrypted); return -1; }
    /* Stateful extraction reassembles CRYPTO frames across Initial packets. */
    if (!argos_quic_extract_stateful(decrypted, payload_len - 16U, profile.version, packet + dcid_pos, dcid_len, hello, 8192U, &hello_len)) {
        /* Authenticated Initial, but the CRYPTO stream is not complete yet. */
        free(hello);
        free(decrypted);
        return 0;
    }

    if (hello_len + 5 > (size_t)fake_tls_buf_cap) { free(hello); free(decrypted); return -1; }

    fake_tls_buf[0] = 0x16U; fake_tls_buf[1] = 0x03U; fake_tls_buf[2] = 0x01U;
    fake_tls_buf[3] = (uint8_t)(hello_len >> 8); fake_tls_buf[4] = (uint8_t)(hello_len & 0xffU);
    memcpy(fake_tls_buf + 5, hello, hello_len);
    *fake_tls_len = (int)(hello_len + 5);

    free(hello); free(decrypted); return 1;
}
#endif /* ARGOS_QUIC_HEAVY_H */
