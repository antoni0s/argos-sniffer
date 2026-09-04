#include <assert.h>
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

    /* A backward wall-clock correction starts a fresh fail-open epoch. */
    e = argos_flow_find_at(&expiry, 4, a, b, 53001, 443, 1, 2000);
    assert(e); e->done = 1U;
    assert(argos_flow_find_at(&expiry, 4, a, b, 53001, 443, 0, 1999) == NULL);

    assert(argos_flow_find_at(&state, 5, a, b, 1, 2, 1, 1) == NULL);
    puts("Flow-state module fixtures: PASS");
    return 0;
}
