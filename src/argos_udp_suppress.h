#ifndef ARGOS_UDP_SUPPRESS_H
#define ARGOS_UDP_SUPPRESS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_UDP_SUPPRESS_SLOTS 256U
#define ARGOS_UDP_SUPPRESS_PROBES 2U
#define ARGOS_UDP_SUPPRESS_TTL_SECS 5U

typedef struct {
    uint64_t key;
    uint64_t last_seen_sec;
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t sport;
    uint16_t dport;
    uint8_t ip_version;
    uint8_t msg_class;
    uint8_t valid;
} argos_udp_suppress_entry_t;

static inline uint64_t argos_udp_suppress_hash_update(uint64_t h, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static inline uint64_t argos_udp_suppress_key(uint8_t ip_version,
                                               const uint8_t *src, const uint8_t *dst,
                                               uint16_t sport, uint16_t dport,
                                               uint8_t msg_class) {
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = 1469598103934665603ULL;
    h = argos_udp_suppress_hash_update(h, &ip_version, sizeof(ip_version));
    h = argos_udp_suppress_hash_update(h, src, addr_len);
    h = argos_udp_suppress_hash_update(h, dst, addr_len);
    h = argos_udp_suppress_hash_update(h, &sport, sizeof(sport));
    h = argos_udp_suppress_hash_update(h, &dport, sizeof(dport));
    h = argos_udp_suppress_hash_update(h, &msg_class, sizeof(msg_class));
    return h;
}

/* Returns 1 only for an exact class+5-tuple hit still inside the short TTL.
 * Suppressed hits deliberately do NOT refresh last_seen_sec: a continuous
 * elephant flow is therefore revalidated periodically instead of becoming
 * permanently invisible. First/expired packets return 0 and seed a new epoch. */
static inline int argos_udp_suppress_recent(argos_udp_suppress_entry_t table[ARGOS_UDP_SUPPRESS_SLOTS],
                                            uint8_t ip_version,
                                            const uint8_t *src, const uint8_t *dst,
                                            uint16_t sport, uint16_t dport,
                                            uint8_t msg_class, uint64_t now_sec) {
    if (!table || !src || !dst || (ip_version != 4U && ip_version != 6U)) return 0;
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    const uint64_t key = argos_udp_suppress_key(ip_version, src, dst, sport, dport, msg_class);
    const size_t base = (size_t)(key & (ARGOS_UDP_SUPPRESS_SLOTS - 1U));
    size_t replace = base;
    uint64_t oldest = UINT64_MAX;

    for (size_t probe = 0; probe < ARGOS_UDP_SUPPRESS_PROBES; ++probe) {
        const size_t slot = (base + probe) & (ARGOS_UDP_SUPPRESS_SLOTS - 1U);
        argos_udp_suppress_entry_t *e = &table[slot];
        if (e->valid && e->key == key && e->ip_version == ip_version &&
            e->sport == sport && e->dport == dport && e->msg_class == msg_class &&
            memcmp(e->src, src, addr_len) == 0 && memcmp(e->dst, dst, addr_len) == 0) {
            if (now_sec >= e->last_seen_sec &&
                now_sec - e->last_seen_sec <= ARGOS_UDP_SUPPRESS_TTL_SECS) return 1;
            e->valid = 0;
            replace = slot;
            break;
        }
        if (!e->valid) { replace = slot; oldest = 0; break; }
        if (e->last_seen_sec < oldest) { oldest = e->last_seen_sec; replace = slot; }
    }

    argos_udp_suppress_entry_t *e = &table[replace];
    memset(e, 0, sizeof(*e));
    e->key = key;
    e->last_seen_sec = now_sec;
    memcpy(e->src, src, addr_len);
    memcpy(e->dst, dst, addr_len);
    e->sport = sport;
    e->dport = dport;
    e->ip_version = ip_version;
    e->msg_class = msg_class;
    e->valid = 1U;
    return 0;
}

#endif
