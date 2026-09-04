#ifndef ARGOS_FLOW_STATE_H
#define ARGOS_FLOW_STATE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "argos_dedup.h"
#include "argos_dns_track.h"

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

/* SYN/SYN-ACK correlation has a different identity key, probe budget and
 * microsecond lifetime from application DONE state. It shares lifecycle
 * ownership only; entries are never reused across the two tables. */
#define ARGOS_SYN_TRACK_SLOTS 1024U
#define ARGOS_SYN_TRACK_PROBES 8U
#define ARGOS_SYN_TRACK_TTL_USEC 120000000ULL
#define ARGOS_RUNTIME_DNS_SLOTS 1024U

typedef struct {
    uint8_t mac[6];
    uint16_t sport;
    uint16_t dport;
    uint8_t ip_version;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint64_t ts_usec;
    uint8_t routed;
    uint8_t valid;
} argos_syn_track_t;

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

/* One lifecycle facade, five independent state machines. Initialize with zero;
 * do not copy a live owner. Prepare/destroy only while packet handling is stopped. */
typedef struct {
    argos_flow_state_t application;
    argos_udp_suppress_entry_t udp_suppress[ARGOS_UDP_SUPPRESS_SLOTS];
    argos_syn_track_t *syn_track;
    argos_dns_track_t *dns_track;
    argos_dedup_state_t dedup;
} argos_runtime_state_t;

static inline uint64_t argos_flow_hash_update(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static inline uint64_t argos_flow_hash_bytes(const void *data, size_t len) {
    return argos_flow_hash_update(1469598103934665603ULL, data, len);
}

static inline uint32_t argos_syn_track_key(const uint8_t mac[6],
                                            uint16_t sport, uint16_t dport,
                                            uint8_t ip_version,
                                            const uint8_t *src_addr,
                                            const uint8_t *dst_addr) {
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = argos_flow_hash_bytes(mac, 6);
    h ^= argos_flow_hash_bytes(&sport, sizeof(sport));
    h ^= argos_flow_hash_bytes(&dport, sizeof(dport)) * 0x9e3779b97f4a7c15ULL;
    h ^= argos_flow_hash_bytes(&ip_version, sizeof(ip_version));
    h ^= argos_flow_hash_bytes(src_addr, addr_len);
    h ^= argos_flow_hash_bytes(dst_addr, addr_len) * 0x517cc1b727220a95ULL;
    return (uint32_t)(h ^ (h >> 32));
}

static inline int argos_syn_track_matches(const argos_syn_track_t *e,
                                           const uint8_t mac[6],
                                           uint16_t sport, uint16_t dport,
                                           uint8_t ip_version,
                                           const uint8_t *src_addr,
                                           const uint8_t *dst_addr) {
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    return e->valid && e->ip_version == ip_version &&
           e->sport == sport && e->dport == dport &&
           memcmp(e->mac, mac, 6) == 0 &&
           memcmp(e->src_addr, src_addr, addr_len) == 0 &&
           memcmp(e->dst_addr, dst_addr, addr_len) == 0;
}

/* Caller has gated extended metrics and successfully prepared this table.
 * No lifecycle checks, allocation or shared mutable owner on the packet path. */
static inline argos_syn_track_t *argos_syn_track_find(const argos_runtime_state_t *state,
        const uint8_t mac[6], uint16_t sport, uint16_t dport, uint8_t ip_version,
        const uint8_t *src_addr, const uint8_t *dst_addr,
        uint64_t now_usec, int create) {
    argos_syn_track_t *table = state->syn_track;
    const uint32_t base = argos_syn_track_key(mac, sport, dport, ip_version,
                                               src_addr, dst_addr) &
                          (ARGOS_SYN_TRACK_SLOTS - 1U);
    argos_syn_track_t *empty = NULL, *oldest_entry = NULL;
    uint64_t oldest = UINT64_MAX;
    for (uint32_t p = 0; p < ARGOS_SYN_TRACK_PROBES; ++p) {
        argos_syn_track_t *e = &table[(base + p) & (ARGOS_SYN_TRACK_SLOTS - 1U)];
        if (e->valid && now_usec >= e->ts_usec &&
            now_usec - e->ts_usec > ARGOS_SYN_TRACK_TTL_USEC) e->valid = 0;
        if (argos_syn_track_matches(e, mac, sport, dport, ip_version,
                                    src_addr, dst_addr)) return e;
        if (!e->valid) {
            if (!empty) empty = e;
        } else if (e->ts_usec < oldest) {
            oldest = e->ts_usec;
            oldest_entry = e;
        }
    }
    argos_syn_track_t *replacement = empty ? empty : oldest_entry;
    if (!create || !replacement) return NULL;
    memset(replacement, 0, sizeof(*replacement));
    memcpy(replacement->mac, mac, 6);
    replacement->sport = sport;
    replacement->dport = dport;
    replacement->ip_version = ip_version;
    memcpy(replacement->src_addr, src_addr, ip_version == 6U ? 16U : 4U);
    memcpy(replacement->dst_addr, dst_addr, ip_version == 6U ? 16U : 4U);
    replacement->valid = 1U;
    return replacement;
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

/* Fixed, allocation-free UDP class suppression state. This shares only the
 * generic tuple hashing primitive with TCP state; TTL and refresh semantics
 * remain intentionally independent. */
static inline uint64_t argos_udp_suppress_key(uint8_t ip_version,
                                               const uint8_t *src, const uint8_t *dst,
                                               uint16_t sport, uint16_t dport,
                                               uint8_t msg_class) {
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = 1469598103934665603ULL;
    h = argos_flow_hash_update(h, &ip_version, sizeof(ip_version));
    h = argos_flow_hash_update(h, src, addr_len);
    h = argos_flow_hash_update(h, dst, addr_len);
    h = argos_flow_hash_update(h, &sport, sizeof(sport));
    h = argos_flow_hash_update(h, &dport, sizeof(dport));
    h = argos_flow_hash_update(h, &msg_class, sizeof(msg_class));
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

/* Startup-only preparation stays out-of-line; it is not packet work. The unused
 * annotation allows consumers of other header APIs to omit this lifecycle entry. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline, unused))
#endif
static int argos_runtime_state_enable_extended_metrics(argos_runtime_state_t *state) {
    if (!state) return 0;
    if (state->syn_track && state->dns_track) return 1;
    /* Commit together; a failed attempt leaves pre-existing state untouched. */
    argos_syn_track_t *syn = state->syn_track;
    if (!syn) syn = (argos_syn_track_t *)calloc(ARGOS_SYN_TRACK_SLOTS, sizeof(*syn));
    if (!syn) return 0;
    argos_dns_track_t *dns = state->dns_track;
    if (!dns) dns = (argos_dns_track_t *)calloc(ARGOS_RUNTIME_DNS_SLOTS, sizeof(*dns));
    if (!dns) {
        if (!state->syn_track) free(syn);
        return 0;
    }
    state->syn_track = syn;
    state->dns_track = dns;
    return 1;
}

/* Repeat-safe, also after partial initialization. Borrowed table entries expire
 * here. Clear fixed inline state as well so a reused owner cannot inherit DONE. */
static inline void argos_runtime_state_destroy(argos_runtime_state_t *state) {
    if (!state) return;
    free(state->syn_track);
    free(state->dns_track);
    argos_dedup_destroy(&state->dedup);
    memset(state, 0, sizeof(*state));
}


#endif
