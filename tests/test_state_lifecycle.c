#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned allocations, releases, fail_at, live, hot;
static void *owned[16];
static void *tracked_calloc(size_t n, size_t bytes) {
    assert(!hot); ++allocations;
    if (allocations == fail_at) return NULL;
    void *p = calloc(n, bytes); assert(p);
    for (unsigned i = 0; i < 16; ++i) if (!owned[i]) {
        owned[i] = p; ++live; return p;
    }
    abort();
}
static void tracked_free(void *p) {
    assert(!hot);
    if (!p) return;
    for (unsigned i = 0; i < 16; ++i) if (owned[i] == p) {
        owned[i] = NULL; --live; ++releases; free(p); return;
    }
    assert(!"double free or foreign owner");
}
#define calloc tracked_calloc
#define free tracked_free
#include "../src/argos_flow_state.h"
#undef calloc
#undef free

static void empty(const argos_runtime_state_t *s) {
    const unsigned char *p = (const unsigned char *)s;
    for (size_t i = 0; i < sizeof(*s); ++i) assert(p[i] == 0);
}
static void lifecycle(void) {
    argos_runtime_state_t a = {0}, b = {0};
    assert(!argos_runtime_state_enable_extended_metrics(NULL));
    argos_runtime_state_destroy(NULL);
    unsigned start = allocations;
    argos_runtime_state_destroy(&a); argos_runtime_state_destroy(&a);
    assert(allocations == start && !live); empty(&a);
    /* Both failure sites must roll back immediately, not wait for destroy. */
    for (unsigned fail = 1; fail <= 2; ++fail) {
        fail_at = allocations + fail;
        assert(!argos_runtime_state_enable_extended_metrics(&a));
        assert(!live); empty(&a);
        argos_runtime_state_destroy(&a); argos_runtime_state_destroy(&a);
        fail_at = 0;
        assert(argos_runtime_state_enable_extended_metrics(&a));
        assert(live == 2);
        argos_runtime_state_destroy(&a); assert(!live); empty(&a);
    }
    assert(argos_runtime_state_enable_extended_metrics(&a));
    assert(argos_runtime_state_enable_extended_metrics(&b));
    assert(live == 4 && a.syn_track != b.syn_track && a.dns_track != b.dns_track);
    a.syn_track[1].valid = 1; a.dns_track[2].valid = 1;
    argos_syn_track_t *syn = a.syn_track; argos_dns_track_t *dns = a.dns_track;
    start = allocations; fail_at = allocations + 1;
    for (unsigned i = 0; i < 100; ++i) assert(argos_runtime_state_enable_extended_metrics(&a));
    assert(allocations == start && a.syn_track == syn && a.dns_track == dns);
    assert(a.syn_track[1].valid && a.dns_track[2].valid);
    argos_runtime_state_destroy(&b); argos_runtime_state_destroy(&b);
    assert(live == 2 && a.syn_track[1].valid && a.dns_track[2].valid);
    /* Destroy also resets independent fixed state; reactivation starts clean. */
    a.application.table[0].done = 1; a.udp_suppress[0].valid = 1;
    argos_runtime_state_destroy(&a); argos_runtime_state_destroy(&a);
    assert(!live); empty(&a); fail_at = 0;
}
static void partial_owner(void) {
    for (int have_syn = 0; have_syn < 2; ++have_syn) {
        argos_runtime_state_t s = {0};
        if (have_syn) s.syn_track = tracked_calloc(ARGOS_SYN_TRACK_SLOTS, sizeof(*s.syn_track));
        else s.dns_track = tracked_calloc(ARGOS_RUNTIME_DNS_SLOTS, sizeof(*s.dns_track));
        void *saved = have_syn ? (void *)s.syn_track : (void *)s.dns_track;
        fail_at = allocations + 1;
        assert(!argos_runtime_state_enable_extended_metrics(&s));
        assert(live == 1 && saved == (have_syn ? (void *)s.syn_track : (void *)s.dns_track));
        fail_at = 0;
        assert(argos_runtime_state_enable_extended_metrics(&s));
        assert(live == 2 && saved == (have_syn ? (void *)s.syn_track : (void *)s.dns_track));
        argos_runtime_state_destroy(&s); argos_runtime_state_destroy(&s); assert(!live);
    }
}
static void evidence(void) {
    argos_runtime_state_t a = {0}, b = {0};
    const uint8_t client[16] = {10,0,0,1}, server[16] = {10,0,0,2};
    const uint8_t mac[6] = {2,1,2,3,4,5};
    assert(argos_runtime_state_enable_extended_metrics(&a));
    assert(argos_runtime_state_enable_extended_metrics(&b));
    unsigned count = allocations;
    hot = 1; /* First evidence and all lookup/expiry work must not allocate/free. */
    for (int version = 4; version <= 6; version += 2) {
        argos_syn_track_t *s = argos_syn_track_find(&a, mac, 50000, 443,
                                                    (uint8_t)version, client, server, 1000, 1);
        assert(s && s->valid); s->ts_usec = 1000;
        assert(!argos_syn_track_find(&b, mac, 50000, 443, (uint8_t)version,
                                     client, server, 1001, 0));
        assert(argos_syn_track_find(&a, mac, 50000, 443, (uint8_t)version,
                                    client, server, 1001, 0) == s);
        assert(!argos_syn_track_find(&a, mac, 50000, 443, (uint8_t)version,
                                     client, server, 1001 + ARGOS_SYN_TRACK_TTL_USEC, 0));
        argos_dns_track_t *d = argos_dns_track_put(a.dns_track, ARGOS_RUNTIME_DNS_SLOTS,
            (uint8_t)version, client, server, 50000, 53, 1, 1, "fixture.invalid", 1000, mac, 1);
        assert(d && d->valid && d->routed);
        assert(argos_dns_track_find_response(a.dns_track, ARGOS_RUNTIME_DNS_SLOTS,
            (uint8_t)version, client, server, 50000, 53, 1, 1, "fixture.invalid", 1001) == d);
        assert(!argos_dns_track_find_response(b.dns_track, ARGOS_RUNTIME_DNS_SLOTS,
            (uint8_t)version, client, server, 50000, 53, 1, 1, "fixture.invalid", 1001));
    }
    hot = 0; assert(count == allocations);
    assert(argos_dedup_prepare(&a.dedup));
    count = allocations; hot = 1;
    assert(!argos_dedup_should_suppress_at(&a.dedup, "aa", "TLS", "x", 1, 35, 1, 100));
    assert(live == 5);
    hot = 0; assert(count == allocations);
    argos_runtime_state_destroy(&a); argos_runtime_state_destroy(&b);
    assert(!live); empty(&a); empty(&b);
}
int main(void) {
    lifecycle(); partial_owner(); evidence();
    printf("State lifecycle/ownership/failure/allocation traps PASS; allocations=%u frees=%u; SYN=%zu DNS=%zu bytes\n",
           allocations, releases, ARGOS_SYN_TRACK_SLOTS * sizeof(argos_syn_track_t),
           ARGOS_RUNTIME_DNS_SLOTS * sizeof(argos_dns_track_t));
    return 0;
}
