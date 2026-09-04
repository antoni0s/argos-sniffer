#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_flow_state.h"

int main(void) {
    argos_runtime_state_t state;
    memset(&state, 0, sizeof(state));
    assert(state.dns_track == NULL && state.dedup.table == NULL);
    assert(state.syn_track == NULL);

    const uint8_t a[16] = {10,0,0,1};
    const uint8_t b[16] = {10,0,0,2};
    const uint8_t mac[6] = {0x02,0x11,0x22,0x33,0x44,0x55};
    argos_flow_note_payload(&state.application, 4, a, b, 50000, 443, 1);
    assert(argos_flow_should_skip(&state.application, 4, a, b, 50000, 443));
    assert(!argos_udp_suppress_recent(state.udp_suppress, 4, a, b,
                                      50000, 51820, 4, 100));
    assert(argos_udp_suppress_recent(state.udp_suppress, 4, a, b,
                                     50000, 51820, 4, 101));
    assert(state.dns_track == NULL && state.dedup.table == NULL);

    assert(argos_runtime_state_enable_extended_metrics(&state));
    assert(state.syn_track != NULL && state.dns_track != NULL);
    argos_syn_track_t *syn = argos_syn_track_find(&state, mac, 50000, 443, 4,
                                                   a, b, 1000, 1);
    assert(syn != NULL && syn->valid);
    syn->ts_usec = 1000;
    assert(argos_syn_track_find(&state, mac, 50000, 443, 4, a, b, 1001, 0) == syn);
    assert(argos_syn_track_find(&state, mac, 50000, 443, 4, a, b,
                                1000 + ARGOS_SYN_TRACK_TTL_USEC + 1, 0) == NULL);

    assert(!argos_dedup_should_suppress_at(&state.dedup, "aa", "TLS", "x",
                                           1, 35, 1, 100));
    assert(state.dedup.table != NULL);
    argos_runtime_state_destroy(&state);
    puts("runtime state ownership fixtures: PASS");
    return 0;
}
