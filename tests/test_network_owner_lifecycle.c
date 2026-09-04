#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned calls, live, hot, fail_call;
static void *tracked_calloc(size_t n, size_t bytes) {
    assert(!hot);
    ++calls;
    if (calls == fail_call) return NULL;
    void *p = calloc(n, bytes);
    assert(p);
    ++live;
    return p;
}
static void tracked_free(void *p) {
    assert(!hot);
    if (p) { assert(live); --live; free(p); }
}
#define calloc tracked_calloc
#define free tracked_free
#include "../src/argos_network.h"
#undef calloc
#undef free

int main(void) {
    argos_network_state_t a, b;
    argos_network_init(&a); argos_network_init(&b);
    assert(!argos_network_prepare_owners(NULL, 1, 1));
    assert(argos_network_prepare_owners(&a, 0, 0));
    assert(!calls && !live);

    assert(argos_network_prepare_owners(&a, 1, 0));
    assert(calls == 1 && live == 1 && a.owner4 && !a.owner6);
    assert(argos_network_prepare_owners(&a, 1, 0));
    assert(calls == 1); /* Repeat preparation preserves the table. */

    const uint8_t mac_a[6] = {0x02,1,2,3,4,5};
    const uint8_t mac_b[6] = {0x02,6,7,8,9,10};
    uint32_t ip4 = htonl(0x0a000001U);
    hot = 1;
    argos_network_owner4_note(&a, ip4, mac_a);
    assert(argos_network_owner4_mismatch(&a, ip4, mac_b));
    size_t owner4_slot = (size_t)(argos_network_hash(&ip4, sizeof(ip4)) &
                                  (ARGOS_NETWORK_OWNER4_SLOTS - 1U));
    assert(a.owner4[owner4_slot].valid);
    a.owner4[owner4_slot].last_seen = time(NULL) + 60;
    assert(!argos_network_owner4_mismatch(&a, ip4, mac_b));
    assert(!a.owner4[owner4_slot].valid);
    hot = 0;
    assert(calls == 1);

    /* A failed family remains fail-open and packet evidence never retries it.
     * The other requested family remains independently useful. */
    fail_call = calls + 1;
    assert(!argos_network_prepare_owners(&b, 1, 1));
    assert(!b.owner4 && b.owner6 && calls == 3 && live == 2);
    hot = 1;
    for (unsigned i = 0; i < 1000; ++i)
        argos_network_owner4_note(&b, ip4, mac_a);
    hot = 0;
    assert(calls == 3 && !b.owner4);
    fail_call = 0;
    assert(argos_network_prepare_owners(&b, 1, 1));
    assert(calls == 4 && b.owner4 && b.owner6 && live == 3);

    argos_network_destroy(&a); argos_network_destroy(&a);
    argos_network_destroy(&b); argos_network_destroy(&b);
    assert(!live && !a.owner4 && !a.owner6 && !b.owner4 && !b.owner6);
    printf("Network owner lifecycle/no packet allocation: PASS; IPv4=%zu IPv6=%zu bytes\n",
           ARGOS_NETWORK_OWNER4_SLOTS * sizeof(argos_network_owner4_entry_t),
           ARGOS_NETWORK_OWNER6_SLOTS * sizeof(argos_network_owner6_entry_t));
    return 0;
}
