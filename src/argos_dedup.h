#ifndef ARGOS_DEDUP_H
#define ARGOS_DEDUP_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ARGOS_DEDUP_SLOTS 2048U
#define ARGOS_DEDUP_PROBES 8U

typedef struct {
    uint64_t key;
    time_t last_seen;
    uint8_t valid;
} argos_dedup_entry_t;

typedef struct {
    argos_dedup_entry_t *table;
} argos_dedup_state_t;

static inline uint64_t argos_dedup_hash_update(uint64_t h,
                                               const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Deterministic core used by tests and by the wall-clock wrapper below.
 * Allocation is lazy and failure is fail-open: telemetry is never silently
 * suppressed merely because a small cache allocation failed. */
static inline int argos_dedup_should_suppress_at(argos_dedup_state_t *state,
                                                 const char *mac,
                                                 const char *evtype,
                                                 const char *payload,
                                                 int rl_enabled, int ttl,
                                                 int sliding, time_t now) {
    if (!state || !mac || !evtype || !rl_enabled || ttl <= 0) return 0;
    if (!state->table) {
        state->table = (argos_dedup_entry_t *)calloc(ARGOS_DEDUP_SLOTS,
                                                     sizeof(*state->table));
        if (!state->table) return 0;
    }

    static const char sep = '|';
    const char *pl = payload ? payload : "";
    uint64_t h = 1469598103934665603ULL; /* preserve v6 wire-era cache behavior */
    h = argos_dedup_hash_update(h, mac, strlen(mac));
    h = argos_dedup_hash_update(h, &sep, 1U);
    h = argos_dedup_hash_update(h, evtype, strlen(evtype));
    h = argos_dedup_hash_update(h, &sep, 1U);
    h = argos_dedup_hash_update(h, pl, strlen(pl));

    size_t base = (size_t)(h & (ARGOS_DEDUP_SLOTS - 1U));
    size_t replace_slot = base;
    time_t oldest_ts = now;

    for (size_t probe = 0; probe < ARGOS_DEDUP_PROBES; ++probe) {
        size_t slot = (base + probe) & (ARGOS_DEDUP_SLOTS - 1U);
        argos_dedup_entry_t *e = &state->table[slot];
        if (e->valid && e->key == h) {
            if ((now - e->last_seen) < ttl) {
                if (sliding) e->last_seen = now;
                return 1;
            }
            replace_slot = slot;
            break;
        }
        if (!e->valid) {
            replace_slot = slot;
            break;
        }
        if (e->last_seen <= oldest_ts) {
            oldest_ts = e->last_seen;
            replace_slot = slot;
        }
    }

    state->table[replace_slot].key = h;
    state->table[replace_slot].last_seen = now;
    state->table[replace_slot].valid = 1;
    return 0;
}

static inline int argos_dedup_should_suppress(argos_dedup_state_t *state,
                                              const char *mac,
                                              const char *evtype,
                                              const char *payload,
                                              int rl_enabled, int ttl,
                                              int sliding) {
    return argos_dedup_should_suppress_at(state, mac, evtype, payload,
                                          rl_enabled, ttl, sliding, time(NULL));
}

static inline void argos_dedup_destroy(argos_dedup_state_t *state) {
    if (!state) return;
    free(state->table);
    state->table = NULL;
}

#endif
