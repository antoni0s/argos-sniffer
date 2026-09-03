#define ARGOS_QUIC_STUB 1
#define main argos_sniffer_embedded_main
#include "../src/argos-sniffer.c"
#undef main

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t a[16] = {10,0,0,10};
    uint8_t b[16] = {10,0,0,20};
    memset(app_flow_table, 0, sizeof(app_flow_table));

    /* Mark both directions DONE, matching a fully fingerprinted TLS session. */
    app_flow_note_payload(4, a, b, 50000, 443, 1);
    app_flow_note_payload(4, b, a, 443, 50000, 1);
    assert(app_flow_should_skip(4, a, b, 50000, 443));
    assert(app_flow_should_skip(4, b, a, 443, 50000));

    /* A new SYN using the same tuple must create a new inspection generation. */
    app_flow_reset_pair(4, a, b, 50000, 443);
    assert(!app_flow_should_skip(4, a, b, 50000, 443));
    assert(!app_flow_should_skip(4, b, a, 443, 50000));

    /* The next payload can be tracked and completed normally again. */
    app_flow_note_payload(4, a, b, 50000, 443, 0);
    assert(!app_flow_should_skip(4, a, b, 50000, 443));
    app_flow_note_payload(4, a, b, 50000, 443, 1);
    assert(app_flow_should_skip(4, a, b, 50000, 443));

    /* IPv6 keys are independently reset with the same helper. */
    uint8_t a6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t b6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
    app_flow_note_payload(6, a6, b6, 51000, 1883, 1);
    assert(app_flow_should_skip(6, a6, b6, 51000, 1883));
    app_flow_reset_pair(6, a6, b6, 51000, 1883);
    assert(!app_flow_should_skip(6, a6, b6, 51000, 1883));

    puts("TCP inspect-once generation reset fixtures: PASS");
    return 0;
}
