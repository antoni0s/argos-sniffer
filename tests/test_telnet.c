#define main argos_telnet_unused_main
#define fwrite telnet_fwrite
#define ARGOS_QUIC_STUB
#include "../src/argos-sniffer.c"
#undef fwrite
#undef main
#include <assert.h>

static char output[2048];
static unsigned writes;
size_t telnet_fwrite(const void *p, size_t size, size_t count, FILE *stream) {
    (void)stream;
    assert(size * count < sizeof(output));
    memcpy(output, p, size * count); output[size * count] = 0;
    ++writes; return count;
}

static void parser_cases(void) {
    argos_enterprise_result_t r;
    unsigned char p[2048];
    for (unsigned cmd = 251; cmd <= 254; ++cmd) for (unsigned opt = 0; opt < 256; ++opt) {
        p[0] = 255; p[1] = (unsigned char)cmd; p[2] = (unsigned char)opt;
        assert(ae_telnet(p, 3, &r) && r.emit && r.complete);
        assert(!strcmp(r.proto, "telnet"));
        char wanted[120];
        const char *name = cmd == 251 ? "will" : cmd == 252 ? "wont" : cmd == 253 ? "do" : "dont";
        snprintf(wanted, sizeof(wanted), "command=%s option=%u negotiation=%s:%u username=-", name, opt, name, opt);
        assert(!strcmp(r.detail, wanted));
        for (int cut = 0; cut < 3; ++cut) {
            assert(!ae_telnet(p, cut, &r)); assert(!r.emit && !r.complete);
        }
    }
    for (unsigned cmd = 0; cmd < 256; ++cmd) {
        p[0] = 255; p[1] = (unsigned char)cmd;
        assert(ae_telnet(p, 2, &r) == (cmd >= 241 && cmd <= 249));
    }
    static const unsigned char negotiation[] = {255,251,1,255,253,3,255,250,24,'S','E','C','R','E','T',255,255,255,240};
    assert(ae_telnet(negotiation, sizeof(negotiation), &r));
    assert(!strcmp(r.detail, "command=will option=1 negotiation=will:1,do:3,sb:24 username=-"));
    for (int cut = 7; cut < (int)sizeof(negotiation); ++cut)
        assert(!ae_telnet(negotiation, cut, &r));
    static const unsigned char bad[] = {255,250,24,'x',255,251,1,255,240};
    assert(!ae_telnet(bad, sizeof(bad), &r));
    static const unsigned char ordinary[] = {'x',255,251,1};
    assert(!ae_telnet(ordinary, sizeof(ordinary), &r));
    static const unsigned char escaped[] = {255,255,255,251,1};
    assert(!ae_telnet(escaped, sizeof(escaped), &r));
    static const unsigned char tail[] = {255,251,1,'S','E','C','R','E','T',255,253,3};
    assert(ae_telnet(tail, sizeof(tail), &r));
    assert(!strcmp(r.detail, "command=will option=1 negotiation=will:1 username=-"));
    memset(p, 'x', sizeof(p)); p[0] = 255; p[1] = 250; p[2] = 24;
    p[1022] = 255; p[1023] = 240;
    assert(ae_telnet(p, sizeof(p), &r));
    assert(!strcmp(r.detail, "command=sb option=24 negotiation=sb:24 username=-"));
    p[1022] = 'x'; p[1023] = 255; p[1024] = 240;
    assert(!ae_telnet(p, sizeof(p), &r));
    for (unsigned i = 0; i < 16; ++i) { p[i * 3] = 255; p[i * 3 + 1] = 254; p[i * 3 + 2] = 255; }
    p[48] = 255; p[49] = 0; /* Beyond the explicit 16-command prefix. */
    assert(ae_telnet(p, 50, &r));
    unsigned commas = 0;
    for (const char *s = r.detail; *s; ++s) commas += *s == ',';
    assert(commas == 15 && strlen(r.detail) < sizeof(r.detail) - 1);
    assert(!ae_telnet(NULL, 4, &r)); assert(!ae_telnet(p, -1, &r));
    assert(!ae_telnet(p, 4, NULL));
}

static void runtime_contract(void) {
    argos_cli_selection_t cli; argos_dispatch_plan_t plan;
    for (unsigned mode = 0; mode < 2; ++mode) {
        argos_cli_selection_init(&cli);
        assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, mode ? "TELNET" : "telnet"));
        argos_dispatch_plan_compile(&plan, &cli);
        assert(plan.l4_routes & ARGOS_DISPATCH_L4_TCP);
        assert(argos_dispatch_telnet_enabled(&plan, 50000, 23));
        assert(argos_dispatch_telnet_enabled(&plan, 23, 50000));
        assert(!argos_dispatch_telnet_enabled(&plan, 50000, 22));
        assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_SSH));
        assert(argos_dispatch_udp_port_engine(&plan, 50000, 23) == ARGOS_PROTOCOL_COUNT);
        assert(argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_TELNET) == !mode);
    }
    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "ssh"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(!argos_dispatch_telnet_enabled(&plan, 23, 22));
    assert(argos_dispatch_tcp_port_engine(&plan, 22, 23) == ARGOS_PROTOCOL_SSH);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "telnet"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_tcp_port_engine(&plan, 22, 23) == ARGOS_PROTOCOL_SSH);
    const uint8_t a[16] = {192,0,2,1}, b[16] = {192,0,2,2}, mac[6] = {2,0,0,0,0,1};
    for (unsigned ip = 4; ip <= 6; ip += 2) {
        argos_flow_state_t flow = {0};
        assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 23));
        argos_flow_note_payload(&flow, ip, a, b, 50000, 23, 1);
        for (unsigned i = 0; i < 10000; ++i) assert(argos_flow_should_skip(&flow, ip, a, b, 50000, 23));
        assert(!argos_flow_should_skip(&flow, ip, b, a, 23, 50000));
        argos_flow_reset_pair(&flow, ip, a, b, 50000, 23);
        assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 23));
    }
    static const unsigned char offer[] = {255,251,1};
    argos_enterprise_result_t r;
    assert(ae_telnet(offer, sizeof(offer), &r));
    assert(argos_dedup_prepare(&runtime_state.dedup));
    emit_enterprise_result(ARGOS_PROTOCOL_TELNET, &r, mac, "a", "b", "|routed", 1);
    assert(writes == 1);
    assert(!strcmp(output, "TELNET|02:00:00:00:00:01|a|b|command=will option=1 negotiation=will:1 username=-|routed\n"));
    emit_enterprise_result(ARGOS_PROTOCOL_TELNET, &r, mac, "a", "b", "|routed", 1);
    assert(writes == 1);
    emit_enterprise_result(ARGOS_PROTOCOL_TELNET, &r, mac, "a", "b", "", 0);
    assert(writes == 2 && !strstr(output, "ENT|"));
    argos_dedup_destroy(&runtime_state.dedup);
}

int main(void) { parser_cases(); runtime_contract(); return 0; }
