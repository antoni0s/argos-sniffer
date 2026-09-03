#ifndef ARGOS_FLOW_STATE_H
#define ARGOS_FLOW_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Fixed, allocation-free TCP application inspection state. This module knows
 * only flow generations and bounded packet budgets; protocol completion policy
 * remains with the caller. */
#define ARGOS_FLOW_SLOTS 1024U
#define ARGOS_FLOW_PROBES 4U
#define ARGOS_FLOW_TTL_SECS 60
#define ARGOS_FLOW_PACKET_BUDGET 8U

typedef struct {
    uint64_t key;
    time_t last_seen;
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t sport;
    uint16_t dport;
    uint8_t ip_version;
    uint8_t payload_packets;
    uint8_t valid;
    uint8_t done;
} argos_flow_entry_t;

typedef struct {
    argos_flow_entry_t table[ARGOS_FLOW_SLOTS];
} argos_flow_state_t;

static inline uint64_t argos_flow_hash_update(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static inline uint64_t argos_flow_key(uint8_t ip_version,
                                      const uint8_t *src, const uint8_t *dst,
                                      uint16_t sport, uint16_t dport) {
    size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = 1469598103934665603ULL;
    h = argos_flow_hash_update(h, &ip_version, sizeof(ip_version));
    h = argos_flow_hash_update(h, src, addr_len);
    h = argos_flow_hash_update(h, dst, addr_len);
    h = argos_flow_hash_update(h, &sport, sizeof(sport));
    h = argos_flow_hash_update(h, &dport, sizeof(dport));
    return h;
}

static inline argos_flow_entry_t *argos_flow_find_at(argos_flow_state_t *state,
                                                      uint8_t ip_version,
                                                      const uint8_t *src, const uint8_t *dst,
                                                      uint16_t sport, uint16_t dport,
                                                      int create, time_t now) {
    if (!state || !src || !dst || (ip_version != 4U && ip_version != 6U)) return NULL;
    size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t key = argos_flow_key(ip_version, src, dst, sport, dport);
    size_t base = (size_t)(key & (ARGOS_FLOW_SLOTS - 1U));
    size_t replace_slot = base;
    time_t oldest = now;

    for (size_t probe = 0; probe < ARGOS_FLOW_PROBES; ++probe) {
        size_t slot = (base + probe) & (ARGOS_FLOW_SLOTS - 1U);
        argos_flow_entry_t *e = &state->table[slot];
        if (e->valid && e->key == key && e->ip_version == ip_version &&
            e->sport == sport && e->dport == dport &&
            memcmp(e->src, src, addr_len) == 0 && memcmp(e->dst, dst, addr_len) == 0) {
            if ((now - e->last_seen) <= ARGOS_FLOW_TTL_SECS) {
                e->last_seen = now;
                return e;
            }
            e->valid = 0;
        }
        if (!e->valid || (now - e->last_seen) > ARGOS_FLOW_TTL_SECS) {
            replace_slot = slot;
            break;
        }
        if (e->last_seen < oldest) {
            oldest = e->last_seen;
            replace_slot = slot;
        }
    }

    if (!create) return NULL;
    argos_flow_entry_t *e = &state->table[replace_slot];
    memset(e, 0, sizeof(*e));
    e->key = key;
    e->last_seen = now;
    e->ip_version = ip_version;
    e->sport = sport;
    e->dport = dport;
    memcpy(e->src, src, addr_len);
    memcpy(e->dst, dst, addr_len);
    e->valid = 1U;
    return e;
}

static inline argos_flow_entry_t *argos_flow_find(argos_flow_state_t *state,
                                                   uint8_t ip_version,
                                                   const uint8_t *src, const uint8_t *dst,
                                                   uint16_t sport, uint16_t dport,
                                                   int create) {
    return argos_flow_find_at(state, ip_version, src, dst, sport, dport, create, time(NULL));
}

static inline int argos_flow_should_skip(argos_flow_state_t *state,
                                         uint8_t ip_version,
                                         const uint8_t *src, const uint8_t *dst,
                                         uint16_t sport, uint16_t dport) {
    argos_flow_entry_t *e = argos_flow_find(state, ip_version, src, dst, sport, dport, 0);
    return e && e->done;
}

/* A fresh SYN is a connection-generation boundary. Invalidate both directions
 * so rapid 5-tuple reuse cannot inherit DONE from an earlier connection. */
static inline void argos_flow_reset_pair(argos_flow_state_t *state,
                                         uint8_t ip_version,
                                         const uint8_t *src, const uint8_t *dst,
                                         uint16_t sport, uint16_t dport) {
    argos_flow_entry_t *forward = argos_flow_find(state, ip_version, src, dst, sport, dport, 0);
    if (forward) forward->valid = 0U;
    argos_flow_entry_t *reverse = argos_flow_find(state, ip_version, dst, src, dport, sport, 0);
    if (reverse) reverse->valid = 0U;
}

static inline void argos_flow_note_payload(argos_flow_state_t *state,
                                           uint8_t ip_version,
                                           const uint8_t *src, const uint8_t *dst,
                                           uint16_t sport, uint16_t dport,
                                           int fingerprint_complete) {
    argos_flow_entry_t *e = argos_flow_find(state, ip_version, src, dst, sport, dport, 1);
    if (!e) return;
    if (fingerprint_complete) {
        e->done = 1U;
        return;
    }
    if (e->payload_packets < 255U) e->payload_packets++;
    if (e->payload_packets >= ARGOS_FLOW_PACKET_BUDGET) e->done = 1U;
}

#endif
