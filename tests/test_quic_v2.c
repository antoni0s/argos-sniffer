#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/argos_quic.h"

static int same(const uint8_t *a, const uint8_t *b, size_t n, const char *name) {
    if (memcmp(a, b, n) == 0) return 1;
    fprintf(stderr, "%s mismatch\n", name);
    return 0;
}

int main(void) {
    argos_quic_initial_profile_t v1, v2, unknown, from_packet;
    if (!argos_quic_initial_profile(ARGOS_QUIC_VERSION_V1, &v1) || v1.initial_type != 0U) return 1;
    if (!argos_quic_initial_profile(ARGOS_QUIC_VERSION_V2, &v2) || v2.initial_type != 1U) return 2;
    if (argos_quic_initial_profile(0x12345678U, &unknown)) return 3;

    const uint8_t protected_v2_header[] = {0xd7,0x6b,0x33,0x43,0xcf};
    if (!argos_quic_packet_profile(protected_v2_header, sizeof(protected_v2_header), &from_packet)) return 4;
    if (from_packet.version != ARGOS_QUIC_VERSION_V2 || from_packet.initial_type != 1U) return 5;

    const uint8_t cid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    const uint8_t exp_key[16] = {0x8b,0x1a,0x0b,0xc1,0x21,0x28,0x42,0x90,0xa2,0x9e,0x09,0x71,0xb5,0xcd,0x04,0x5d};
    const uint8_t exp_iv[12] = {0x91,0xf7,0x3e,0x23,0x51,0xd8,0xfa,0x91,0x66,0x0e,0x90,0x9f};
    const uint8_t exp_hp[16] = {0x45,0xb9,0x5e,0x15,0x23,0x5d,0x6f,0x45,0xa6,0xb1,0x9c,0xbc,0xb0,0x29,0x4b,0xa9};
    uint8_t key[16], iv[12], hp[16];
    if (!argos_quic_derive_client_keys(&v2, cid, sizeof(cid), key, iv, hp)) return 6;
    if (!same(key, exp_key, sizeof(key), "v2 key")) return 7;
    if (!same(iv, exp_iv, sizeof(iv), "v2 iv")) return 8;
    if (!same(hp, exp_hp, sizeof(hp), "v2 hp")) return 9;

    puts("QUIC v2 RFC 9369 vectors: PASS");
    return 0;
}
