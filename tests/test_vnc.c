#define main argos_vnc_unused_main
#define fwrite vnc_fwrite
#define calloc vnc_calloc
#define ARGOS_QUIC_STUB
#include "../src/argos-sniffer.c"
#undef calloc
#undef fwrite
#undef main
#include <assert.h>
extern void *calloc(size_t, size_t);

static unsigned allocations, writes;
static int fail_allocation;
static char output[2048];
void *vnc_calloc(size_t n, size_t size) {
    ++allocations;
    return fail_allocation ? NULL : calloc(n, size);
}
size_t vnc_fwrite(const void *p, size_t size, size_t n, FILE *stream) {
    (void)stream; assert(size * n < sizeof(output));
    memcpy(output, p, size * n); output[size * n] = 0; ++writes; return n;
}

static int step(ae_vnc_state_t *s, uint32_t seq[2], int server,
                  const unsigned char *p, int n, argos_enterprise_result_t *r) {
    /* Every cut and wrong-direction message must fail closed at this phase. */
    for (int cut = 1; cut < n; ++cut) {
        ae_vnc_state_t copy = *s; argos_enterprise_result_t bad;
        assert(!ae_vnc(&copy, server, seq[server], p, cut, &bad));
        assert(copy.phase == AE_VNC_DONE && !bad.emit);
    }
    ae_vnc_state_t wrong = *s;
    assert(!ae_vnc(&wrong, !server, seq[!server], p, n, r));
    assert(wrong.phase == AE_VNC_DONE);
    int emitted = ae_vnc(s, server, seq[server], p, n, r);
    seq[server] += (uint32_t)n;
    assert(s->phase != AE_VNC_DONE || r->complete);
    assert(!strstr(r->detail, "SECRET"));
    return emitted;
}

static int server_init(unsigned char p[160]) {
    memset(p, 0, 160);
    p[0] = 3; p[1] = 32; p[2] = 2; p[3] = 88; /* 800 x 600 */
    p[4] = 32; p[5] = 24; p[7] = 1;
    p[9] = p[11] = p[13] = 255; p[14] = 16; p[15] = 8;
    const char *name = "host|= test";
    p[23] = (unsigned char)strlen(name); memcpy(p + 24, name, strlen(name));
    return 24 + (int)strlen(name);
}

static void handshakes(void) {
    const unsigned char zero[4] = {0}, init[1] = {1};
    const unsigned char secret[16] = "SECRET_AUTH_DATA";
    for (unsigned minor = 3; minor <= 8; ++minor) {
        if (minor != 3 && minor != 7 && minor != 8) continue;
        for (unsigned security = 1; security <= 2; ++security) {
            ae_vnc_state_t s = {0}; uint32_t seq[2] = {40, UINT32_MAX - 5U};
            argos_enterprise_result_t r;
            unsigned char banner[] = "RFB 003.008\n";
            assert(step(&s, seq, 1, banner, 12, &r));
            banner[10] = (unsigned char)('0' + minor);
            assert(step(&s, seq, 0, banner, 12, &r));
            if (minor == 3) {
                unsigned char offer[4] = {0,0,0,(unsigned char)security};
                assert(step(&s, seq, 1, offer, 4, &r));
            } else {
                const unsigned char offer[3] = {2,1,2};
                assert(step(&s, seq, 1, offer, 3, &r));
                assert(strstr(r.detail, "security_types=1,2"));
                unsigned char selected = (unsigned char)security;
                assert(step(&s, seq, 0, &selected, 1, &r));
            }
            if (security == 2) {
                assert(!step(&s, seq, 1, secret, 16, &r));
                assert(!step(&s, seq, 0, secret, 16, &r));
            }
            if (security == 2 || minor == 8) assert(!step(&s, seq, 1, zero, 4, &r));
            assert(!step(&s, seq, 0, init, 1, &r));
            unsigned char packet[160]; int n = server_init(packet);
            ae_vnc_state_t copy = s;
            packet[14] = 0; /* Overlapping true-colour masks. */
            assert(!ae_vnc(&copy, 1, seq[1], packet, n, &r) && copy.phase == AE_VNC_DONE);
            server_init(packet);
            assert(step(&s, seq, 1, packet, n, &r));
            assert(strstr(r.detail, "server_name=host___test width=800 height=600"));
            assert(r.complete && s.phase == AE_VNC_DONE);
            for (unsigned tail = 0; tail < 10000; ++tail)
                assert(!ae_vnc(&s, 1, seq[1], secret, sizeof(secret), &r));
        }
    }
}

static void adversarial(void) {
    argos_enterprise_result_t r; ae_vnc_state_t s = {0};
    const unsigned char banner[] = "RFB 003.008\n";
    const unsigned char malformed_banner[] = "RFB 00x.008\n";
    assert(!ae_vnc(&s, 1, 1, malformed_banner, 12, &r));
    memset(&s, 0, sizeof(s));
    unsigned char packet[160]; int n = server_init(packet);
    assert(!ae_vnc(&s, 1, 1, packet, n, &r)); /* Old ServerInit shape false positive. */
    memset(&s, 0, sizeof(s));
    const unsigned char offer[] = {2,1,2};
    assert(!ae_vnc(&s, 1, 1, offer, 3, &r)); /* No version handshake. */
    memset(&s, 0, sizeof(s));
    assert(ae_vnc(&s, 1, 100, banner, 12, &r));
    assert(!ae_vnc(&s, 1, 100, banner, 12, &r)); /* Replay emits nothing. */
    assert(s.phase == AE_VNC_CLIENT_BANNER);
    for (unsigned repeat = 0; repeat < 8; ++repeat) (void)ae_vnc(&s, 1, 100, banner, 12, &r);
    assert(s.phase == AE_VNC_DONE); /* Replays consume the safety budget. */
    memset(&s, 0, sizeof(s));
    assert(ae_vnc(&s, 1, 100, banner, 12, &r));
    assert(ae_vnc(&s, 0, 200, banner, 12, &r));
    ae_vnc_state_t copy = s;
    assert(!ae_vnc(&copy, 1, 113, offer, 3, &r) && copy.phase == AE_VNC_DONE);
    assert(ae_vnc(&s, 1, 112, offer, 3, &r));
    const unsigned char extended = 19;
    assert(!ae_vnc(&s, 0, 212, &extended, 1, &r) && s.phase == AE_VNC_DONE);
    memset(&s, 0, sizeof(s));
    assert(!ae_vnc(&s, 1, 0, banner, 1025, &r)); /* Bound checked before reading. */
    memset(&s, 0, sizeof(s));
    assert(!ae_vnc(&s, 1, 0, NULL, 12, &r));
    assert(!ae_vnc(NULL, 1, 0, banner, 12, &r));
}

static void lifecycle_and_wire(void) {
    argos_cli_selection_t cli; argos_dispatch_plan_t plan;
    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "vnc"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(plan.l4_routes & ARGOS_DISPATCH_L4_TCP);
    assert(argos_dispatch_vnc_enabled(&plan, 50000, 5900));
    assert(argos_dispatch_vnc_enabled(&plan, 5999, 50000));
    assert(!argos_dispatch_vnc_enabled(&plan, 50000, 5899));
    assert(!argos_dispatch_vnc_enabled(&plan, 5900, 5901));
    assert(argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_VNC));
    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "VNC"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(!argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_VNC));
    argos_runtime_state_t state = {0};
    fail_allocation = 1; assert(!argos_flow_prepare_context(&state.application));
    assert(!state.application.context);
    fail_allocation = 0; assert(argos_flow_prepare_context(&state.application));
    unsigned prepared = allocations;
    assert(argos_flow_prepare_context(&state.application) && allocations == prepared);
    const uint8_t a[16] = {192,0,2,1}, b[16] = {192,0,2,2}, mac[6] = {2,0,0,0,0,1};
    const unsigned char banner[] = "RFB 003.008\n";
    argos_enterprise_result_t r;
    for (unsigned ip = 4; ip <= 6; ip += 2) {
        assert(parse_vnc_flow(&state.application, ip, a, b, 5900, 50000, 100, banner, 12, &r));
        emit_enterprise_result(ARGOS_PROTOCOL_VNC, &r, mac, "a", "b", "|routed", 0);
        assert(!strcmp(output, "VNC|02:00:00:00:00:01|a|b|protocol=rfb version=3.8 security_types=- selected_security=- server_name=- width=- height=-|routed\n"));
        assert(!parse_vnc_flow(&state.application, ip, a, b, 5900, 50000, 100, banner, 12, &r));
        assert(parse_vnc_flow(&state.application, ip, b, a, 50000, 5900, 200, banner, 12, &r));
        argos_flow_reset_pair(&state.application, ip, b, a, 50000, 5900);
        assert(parse_vnc_flow(&state.application, ip, a, b, 5900, 50000, 300, banner, 12, &r));
    }
    assert(allocations == prepared); /* Parser, lookup, reset and wire: no allocation. */
    argos_flow_entry_t *e = argos_flow_find_at(&state.application, 4, a, b, 5901, 50001, 1, 100);
    unsigned char *context = argos_flow_context(&state.application, e); memset(context, 255, 16);
    e = argos_flow_find_at(&state.application, 4, a, b, 5901, 50001, 1, 161);
    context = argos_flow_context(&state.application, e);
    for (unsigned i = 0; i < 16; ++i) assert(context[i] == 0);
    size_t base = (size_t)(argos_flow_key(4, a, b, 5902, 1) & (ARGOS_FLOW_SLOTS - 1));
    unsigned found = 0;
    for (unsigned port = 1; port <= 65535 && found < 5; ++port) {
        if ((argos_flow_key(4, a, b, 5902, (uint16_t)port) & (ARGOS_FLOW_SLOTS - 1)) != base) continue;
        e = argos_flow_find_at(&state.application, 4, a, b, 5902, (uint16_t)port, 1, 200 + found);
        context = argos_flow_context(&state.application, e);
        for (unsigned i = 0; i < 16; ++i) assert(context[i] == 0);
        memset(context, 255, 16); ++found;
    }
    assert(found == 5);
    argos_runtime_state_destroy(&state); argos_runtime_state_destroy(&state);
    assert(!state.application.context);
    assert(!parse_vnc_flow(&state.application, 4, a, b, 5900, 50000, 100, banner, 12, &r));
}

int main(void) { handshakes(); adversarial(); lifecycle_and_wire(); return 0; }
