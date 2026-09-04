#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reference_dedup.h"

static unsigned calls, frees, live, hot, fail;
static void *tracked_calloc(size_t n, size_t bytes) {
    assert(!hot); ++calls;
    if (fail) return NULL;
    void *p = calloc(n, bytes); assert(p); ++live; return p;
}
static void tracked_free(void *p) {
    assert(!hot);
    if (p) { assert(live); --live; ++frees; free(p); }
}
#define calloc tracked_calloc
#define free tracked_free
#include "../src/argos_dedup.h"
#undef calloc
#undef free

int main(void) {
    argos_dedup_state_t a = {0}, b = {0};
    assert(!argos_dedup_prepare(NULL)); argos_dedup_destroy(NULL);
    /* Missing/failed state must not trigger even one packet-time allocation. */
    for (unsigned phase = 0; phase < 2; ++phase) {
        if (phase) { fail = 1; assert(!argos_dedup_prepare(&a)); fail = 0; }
        unsigned before = calls;
        hot = 1;
        for (unsigned i = 0; i < 1000; ++i)
            assert(!argos_dedup_should_suppress_at(&a, "aa", "TLS", "x", 1, 35, 1, 100));
        hot = 0; assert(calls == before && !a.table && !live);
    }
    assert(argos_dedup_prepare(&a) && argos_dedup_prepare(&b));
    assert(a.table != b.table && live == 2);
    assert(!argos_dedup_should_suppress_at(&a, "aa", "TLS", "x", 1, 35, 1, 100));
    unsigned before = calls; fail = 1;
    for (unsigned i = 0; i < 100; ++i) assert(argos_dedup_prepare(&a));
    fail = 0; assert(calls == before);
    assert(argos_dedup_should_suppress_at(&a, "aa", "TLS", "x", 1, 35, 1, 101));
    assert(!argos_dedup_should_suppress_at(&b, "aa", "TLS", "x", 1, 35, 1, 101));
    argos_dedup_destroy(&a); argos_dedup_destroy(&a);
    argos_dedup_destroy(&b); assert(!live);

    /* Every decision and every stored byte must match the prior algorithm for
     * monotonic time. Saturation/collisions, fixed/sliding TTL, unrated, zero
     * TTL, changed keys and duplicate bursts are included. Clock rollback is
     * intentionally fail-open now and has a dedicated contract fixture. */
    reference_dedup_state_t old = {0};
    assert(argos_dedup_prepare(&a));
    (void)reference_dedup_should_suppress_at(&old, "seed", "seed", "", 1, 1, 0, 0);
    memset(old.table, 0, REFERENCE_DEDUP_SLOTS * sizeof(*old.table));
    before = calls; hot = 1;
    for (unsigned i = 0; i < 30000; ++i) {
        char mac[32], payload[32];
        snprintf(mac, sizeof(mac), "device-%u", i / 3U % 4096U);
        snprintf(payload, sizeof(payload), "evidence-%u", i / 7U % 4096U);
        int ttl = i % 97U ? 35 : 0, sliding = (i / 500U) & 1U, enabled = i % 101U != 0;
        time_t now = 1000 + i / 3U;
        int expected = reference_dedup_should_suppress_at(&old, mac, "TLS", payload,
                                                          enabled, ttl, sliding, now);
        assert(argos_dedup_should_suppress_at(&a, mac, "TLS", payload,
                                             enabled, ttl, sliding, now) == expected);
        assert(memcmp(a.table, old.table, ARGOS_DEDUP_SLOTS * sizeof(*a.table)) == 0);
    }
    hot = 0; assert(calls == before);
    reference_dedup_destroy(&old); argos_dedup_destroy(&a); argos_dedup_destroy(&a);
    assert(!live && frees == 3);
    printf("Dedup lifecycle/failure/no packet allocation: PASS; 30000 legacy equivalence cases, cache=%zu bytes\n",
           ARGOS_DEDUP_SLOTS * sizeof(argos_dedup_entry_t));
    return 0;
}
