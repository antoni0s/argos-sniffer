from pathlib import Path
import re

src = Path('src/argos-sniffer.c')
hdr = Path('src/argos_flow_state.h')
test = Path('tests/test_flow_state.c')
s = src.read_text()

hdr.write_text(r'''#ifndef ARGOS_FLOW_STATE_H
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
''')

include_anchor = '#include "argos_dedup.h"\n#include "argos_identity.h"\n'
if s.count(include_anchor) != 1:
    raise SystemExit(f'flow include anchor count={s.count(include_anchor)}')
s = s.replace(include_anchor,
              '#include "argos_dedup.h"\n#include "argos_flow_state.h"\n#include "argos_identity.h"\n', 1)

start = s.find('/* ============================================================================\n * SECTION: Application Flow Suppression')
end = s.find('/* A complete TLS ClientHello is enough to finish TLS fingerprinting.', start)
if start < 0 or end < 0:
    raise SystemExit('application flow state block anchors not found')
replacement = r'''/* ============================================================================
 * SECTION: Application Flow Suppression
 * Generic fixed-size TCP generation/DONE state lives in argos_flow_state.h.
 * Protocol-specific completion policy remains here beside the parsers.
 * ============================================================================ */
static argos_flow_state_t app_flow_state = {0};

/* UDP suppression is intentionally separate from TCP DONE state. It is used
 * only for protocol/message classes proven safe to skip briefly. */
static argos_udp_suppress_entry_t udp_suppress_table[ARGOS_UDP_SUPPRESS_SLOTS];

'''
s = s[:start] + replacement + s[end:]

# Remove the old main-local note_payload implementation; completion policy above stays.
note_re = re.compile(r'''static void app_flow_note_payload\(uint8_t ip_version, const uint8_t \*src, const uint8_t \*dst,\n\s+uint16_t sport, uint16_t dport, int fingerprint_complete\) \{.*?\n\}\n\n''', re.S)
s, n = note_re.subn('', s, count=1)
if n != 1:
    raise SystemExit(f'app_flow_note_payload removal count={n}')

# Route the three runtime operations through the state module.
s = s.replace('app_flow_reset_pair(flow_ip_version, flow_src_addr, flow_dst_addr, sport, dport);',
              'argos_flow_reset_pair(&app_flow_state, flow_ip_version, flow_src_addr, flow_dst_addr, sport, dport);')
s = s.replace('app_flow_should_skip(flow_ip_version, flow_src_addr, flow_dst_addr,\n                                                      sport, dport)',
              'argos_flow_should_skip(&app_flow_state, flow_ip_version, flow_src_addr, flow_dst_addr,\n                                      sport, dport)')
s = s.replace('app_flow_note_payload(flow_ip_version, flow_src_addr, flow_dst_addr,\n                                          sport, dport, fingerprint_complete);',
              'argos_flow_note_payload(&app_flow_state, flow_ip_version, flow_src_addr, flow_dst_addr,\n                                        sport, dport, fingerprint_complete);')

for legacy in ('APP_FLOW_SLOTS', 'APP_FLOW_PROBES', 'APP_FLOW_TTL_SECS',
               'APP_FLOW_PACKET_BUDGET', 'app_flow_entry_t', 'app_flow_table',
               'static uint64_t app_flow_key', 'static app_flow_entry_t *app_flow_find',
               'static int app_flow_should_skip', 'static void app_flow_reset_pair',
               'static void app_flow_note_payload'):
    if legacy in s:
        raise SystemExit(f'legacy flow-state implementation remains: {legacy}')
if s.count('argos_flow_reset_pair(&app_flow_state') != 1:
    raise SystemExit('flow reset call count mismatch')
if s.count('argos_flow_should_skip(&app_flow_state') != 1:
    raise SystemExit('flow skip call count mismatch')
if s.count('argos_flow_note_payload(&app_flow_state') != 1:
    raise SystemExit('flow note call count mismatch')

src.write_text(s)

test.write_text(r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_flow_state.h"

int main(void) {
    argos_flow_state_t state = {0};
    uint8_t a[16] = {10,0,0,10};
    uint8_t b[16] = {10,0,0,20};

    argos_flow_note_payload(&state, 4, a, b, 50000, 443, 1);
    argos_flow_note_payload(&state, 4, b, a, 443, 50000, 1);
    assert(argos_flow_should_skip(&state, 4, a, b, 50000, 443));
    assert(argos_flow_should_skip(&state, 4, b, a, 443, 50000));

    argos_flow_reset_pair(&state, 4, a, b, 50000, 443);
    assert(!argos_flow_should_skip(&state, 4, a, b, 50000, 443));
    assert(!argos_flow_should_skip(&state, 4, b, a, 443, 50000));

    /* Packet budget remains exactly eight incomplete payloads. */
    for (unsigned i = 0; i < ARGOS_FLOW_PACKET_BUDGET - 1U; ++i) {
        argos_flow_note_payload(&state, 4, a, b, 51000, 80, 0);
        assert(!argos_flow_should_skip(&state, 4, a, b, 51000, 80));
    }
    argos_flow_note_payload(&state, 4, a, b, 51000, 80, 0);
    assert(argos_flow_should_skip(&state, 4, a, b, 51000, 80));

    /* IPv6 tuple state is independent. */
    uint8_t a6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t b6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
    argos_flow_note_payload(&state, 6, a6, b6, 52000, 1883, 1);
    assert(argos_flow_should_skip(&state, 6, a6, b6, 52000, 1883));
    assert(!argos_flow_should_skip(&state, 4, a, b, 52000, 1883));

    /* Deterministic clock hook proves expiry without sleeps. */
    argos_flow_state_t expiry = {0};
    argos_flow_entry_t *e = argos_flow_find_at(&expiry, 4, a, b, 53000, 443, 1, 1000);
    assert(e); e->done = 1U;
    assert(argos_flow_find_at(&expiry, 4, a, b, 53000, 443, 0, 1060) != NULL);
    assert(argos_flow_find_at(&expiry, 4, a, b, 53000, 443, 0, 1121) == NULL);

    assert(argos_flow_find_at(&state, 5, a, b, 1, 2, 1, 1) == NULL);
    puts("Flow-state module fixtures: PASS");
    return 0;
}
''')

print('staged generic TCP flow-state module extraction')
