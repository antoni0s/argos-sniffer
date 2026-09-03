from pathlib import Path


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)

p = Path('src/argos-sniffer.c')
s = p.read_text()

old = '''static int app_flow_should_skip(uint8_t ip_version, const uint8_t *src, const uint8_t *dst,\n                                uint16_t sport, uint16_t dport) {\n    app_flow_entry_t *e = app_flow_find(ip_version, src, dst, sport, dport, 0);\n    return e && e->done;\n}\n\n'''
new = '''static int app_flow_should_skip(uint8_t ip_version, const uint8_t *src, const uint8_t *dst,\n                                uint16_t sport, uint16_t dport) {\n    app_flow_entry_t *e = app_flow_find(ip_version, src, dst, sport, dport, 0);\n    return e && e->done;\n}\n\n/* A fresh TCP SYN starts a new connection even when the kernel reuses the same\n * 5-tuple inside APP_FLOW_TTL_SECS. Clear both directional cache entries so a\n * completed previous connection can never suppress the new handshake or its\n * first application fingerprint. No allocation occurs on this reset path. */\nstatic void app_flow_reset_pair(uint8_t ip_version, const uint8_t *src, const uint8_t *dst,\n                                uint16_t sport, uint16_t dport) {\n    app_flow_entry_t *forward = app_flow_find(ip_version, src, dst, sport, dport, 0);\n    if (forward) forward->valid = 0;\n    app_flow_entry_t *reverse = app_flow_find(ip_version, dst, src, dport, sport, 0);\n    if (reverse) reverse->valid = 0;\n}\n\n'''
s = replace_once(s, old, new, 'app-flow reset helper')

old = '''                int enterprise_tcp = opt_enterprise && argos_enterprise_tcp_port(sport, dport);\n                int app_track = payload_len > 0 &&\n'''
new = '''                /* SYN is the connection-generation boundary for inspect-once state.\n                 * Reset before consulting DONE so rapid 5-tuple reuse is re-inspected. */\n                if (tcp->syn && !tcp->ack)\n                    app_flow_reset_pair(flow_ip_version, flow_src_addr, flow_dst_addr, sport, dport);\n\n                int enterprise_tcp = opt_enterprise && argos_enterprise_tcp_port(sport, dport);\n                int app_track = payload_len > 0 &&\n'''
s = replace_once(s, old, new, 'SYN reset integration')
p.write_text(s)

Path('tests/test_app_flow.c').write_text(r'''#define ARGOS_QUIC_STUB 1
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
''')
