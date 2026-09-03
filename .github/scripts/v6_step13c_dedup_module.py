from pathlib import Path
import re

src=Path('src/argos-sniffer.c')
hdr=Path('src/argos_dedup.h')
test=Path('tests/test_dedup.c')
s=src.read_text()

hdr.write_text(r'''#ifndef ARGOS_DEDUP_H
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
''')

inc='#include "argos_config.h"\n#include "argos_identity.h"\n'
if s.count(inc)!=1: raise SystemExit(f'dedup include anchor count={s.count(inc)}')
s=s.replace(inc,'#include "argos_config.h"\n#include "argos_dedup.h"\n#include "argos_identity.h"\n',1)

start=s.find('#define DEDUP_SLOTS 2048')
if start<0: raise SystemExit('dedup block start missing')
end=s.find('/* Discovery records describe relatively stable ownership/fingerprint state.', start)
if end<0: raise SystemExit('dedup block end missing')
block=s[start:end]
for required in ('DEDUP_PROBES 8','dedup_entry_t','dedup_should_suppress_for','dedup_should_suppress('):
    if required not in block: raise SystemExit(f'dedup block missing {required}')
replacement='''#define ARP_DEDUP_TTL_SECS 900\n#define NDP_DEDUP_TTL_SECS 900\n#define RA_DEDUP_TTL_SECS 1800\nstatic int rate_limit_ttl = 35;\nstatic argos_dedup_state_t dedup_state = {0};\n\nstatic int dedup_should_suppress_for(const char *mac, const char *evtype, const char *payload,\n                                     int rl_enabled, int ttl, int sliding) {\n    return argos_dedup_should_suppress(&dedup_state, mac, evtype, payload,\n                                       rl_enabled, ttl, sliding);\n}\n\nstatic int dedup_should_suppress(const char *mac, const char *evtype, const char *payload, int rl_enabled) {\n    return dedup_should_suppress_for(mac, evtype, payload, rl_enabled, rate_limit_ttl, 1);\n}\n\n'''
s=s[:start]+replacement+s[end:]

count=s.count('free(dedup_table)')
if count != 2: raise SystemExit(f'dedup cleanup replacement count={count}')
s=s.replace('free(dedup_table)', 'argos_dedup_destroy(&dedup_state)')
if 'dedup_table' in s or 'DEDUP_SLOTS' in s or 'DEDUP_PROBES' in s or 'dedup_entry_t' in s:
    raise SystemExit('legacy dedup implementation remains in main')

src.write_text(s)

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include "../src/argos_dedup.h"
static void check(int ok,const char *m){if(!ok){fprintf(stderr,"FAIL: %s\n",m);exit(1);}}
int main(void){
 argos_dedup_state_t s={0};
 check(s.table==NULL,"lazy table");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",0,35,1,100)==0,"disabled fail open");
 check(s.table==NULL,"disabled no allocation");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,100)==0,"first emits");
 check(s.table!=NULL,"first use allocates");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,110)==1,"duplicate suppresses");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,140)==1,"sliding extends window");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,176)==0,"sliding expires from last hit");
 argos_dedup_destroy(&s);
 check(s.table==NULL,"destroy clears table");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","stable",1,30,0,200)==0,"fixed first emits");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","stable",1,30,0,220)==1,"fixed suppresses inside window");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","stable",1,30,0,231)==0,"fixed does not slide");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","changed",1,30,0,232)==0,"changed payload emits");
 check(argos_dedup_should_suppress_at(&s,"bb","ARP","changed",1,30,0,233)==0,"changed identity emits");
 argos_dedup_destroy(&s);
 puts("Dedup module fixtures: PASS");return 0;
}
''')
print('staged generic dedup module extraction')
