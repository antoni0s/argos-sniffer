#ifndef ARGOS_RAW_IDENTITY_H
#define ARGOS_RAW_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

/* LINK_RAW_IP (PPP/TUN/WireGuard and similar) has no L2 addresses. Generate
 * deterministic, locally-administered unicast surrogate MACs from the L3
 * endpoints so existing fixed-size identity/state tables can distinguish
 * tunnel clients without allocating memory or changing Ethernet semantics.
 *
 * IPv4 is collision-free within the address family: 02:<IPv4 bytes>:04.
 * IPv6 uses a 40-bit FNV-1a digest behind family marker 06; 06 has the local
 * bit set and multicast bit clear, so it cannot be mistaken for a globally
 * administered hardware address. */
static inline uint64_t argos_raw_id_hash64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    if (!p) return h;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static inline void argos_raw_identity_v4(const uint8_t addr[4], uint8_t mac[6]) {
    mac[0] = 0x02U;
    mac[1] = addr[0]; mac[2] = addr[1]; mac[3] = addr[2]; mac[4] = addr[3];
    mac[5] = 0x04U;
}

static inline void argos_raw_identity_v6(const uint8_t addr[16], uint8_t mac[6]) {
    uint64_t h = argos_raw_id_hash64(addr, 16U);
    mac[0] = 0x06U;
    mac[1] = (uint8_t)(h >> 32); mac[2] = (uint8_t)(h >> 24);
    mac[3] = (uint8_t)(h >> 16); mac[4] = (uint8_t)(h >> 8); mac[5] = (uint8_t)h;
}

#endif /* ARGOS_RAW_IDENTITY_H */
