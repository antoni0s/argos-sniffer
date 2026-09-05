/* Production parser, completion and sink serializer; no capture or network I/O. */
#define main argos_lpd_unused_main
#define fwrite lpd_fwrite
#define ARGOS_QUIC_STUB
#include "../src/argos-sniffer.c"
#undef fwrite
#undef main
#include <assert.h>

static char output[2048];
static unsigned writes;
size_t lpd_fwrite(const void *p, size_t size, size_t count, FILE *stream) {
    (void)stream;
    assert(size * count < sizeof(output));
    memcpy(output, p, size * count); output[size * count] = 0;
    ++writes; return count;
}

static void parser_cases(void) {
    static const char *names[] = {"restart", "receive-job", "short-queue", "long-queue", "remove-jobs"};
    argos_enterprise_result_t r;
    unsigned char p[1100];
    for (unsigned cmd = 0; cmd < 256; ++cmd) {
        p[0] = (unsigned char)cmd;
        const char *args = cmd == 5 ? "queue alice 123 bob\n" : "queue\n";
        memcpy(p + 1, args, strlen(args));
        int n = (int)strlen(args) + 1;
        assert(ae_lpd(p, n, &r) == (cmd >= 1 && cmd <= 5));
        if (cmd < 1 || cmd > 5) continue;
        char want[128];
        snprintf(want, sizeof(want), "command=%s queue=queue username=%s", names[cmd - 1], cmd == 5 ? "alice" : "-");
        assert(r.emit && r.complete && !strcmp(r.proto, "lpd") && !strcmp(r.detail, want));
        for (int cut = 0; cut < n; ++cut) assert(!ae_lpd(p, cut, &r));
        memcpy(p + n, "SECRET PRINT BODY\0\xff", 19);
        assert(ae_lpd(p, n + 19, &r));
        assert(!strcmp(r.detail, want));
    }
    static const unsigned char query[] = "\3queue 123 alice\n";
    assert(ae_lpd(query, sizeof(query) - 1, &r));
    assert(!strcmp(r.detail, "command=short-queue queue=queue username=-"));
    static const unsigned char escaped[] = "\5q|;=\\\tal|;=\\\v123\fother\n";
    assert(ae_lpd(escaped, sizeof(escaped) - 1, &r));
    assert(!strcmp(r.detail, "command=remove-jobs queue=q____ username=al____"));
    static const unsigned char *bad[] = {
        (const unsigned char *)"\2\n", (const unsigned char *)"\2 q\n",
        (const unsigned char *)"\2q\r\n", (const unsigned char *)"\2q extra\n",
        (const unsigned char *)"\2" "123 cfA001host\n", /* control-file subcommand */
        (const unsigned char *)"\5q\n", (const unsigned char *)"\5q 123\n"
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(!ae_lpd(bad[i], (int)strlen((const char *)bad[i]), &r));
    memset(p, 'q', sizeof(p)); p[0] = 2; p[96] = '\n';
    assert(ae_lpd(p, 97, &r));
    p[96] = 'q'; p[97] = '\n'; assert(!ae_lpd(p, 98, &r));
    memset(p, 'a', sizeof(p)); p[0] = 5; p[1] = 'q'; p[2] = ' ';
    p[66] = '\n'; assert(ae_lpd(p, 67, &r));
    p[66] = 'a'; p[67] = '\n'; assert(!ae_lpd(p, 68, &r));
    memset(p, 'x', sizeof(p)); p[0] = 3; p[1] = 'q'; p[2] = ' ';
    p[1023] = '\n'; assert(ae_lpd(p, sizeof(p), &r));
    p[1023] = 'x'; p[1024] = '\n'; assert(!ae_lpd(p, sizeof(p), &r));
    for (unsigned c = 0; c < 256; ++c) {
        unsigned char token[] = {2, 'q', (unsigned char)c, 'x', '\n'};
        if (c < 32 || c > 126) {
            if (c != '\n') assert(!ae_lpd(token, sizeof(token), &r));
        }
    }
    assert(!ae_lpd(NULL, 4, &r)); assert(!ae_lpd(query, -1, &r));
    assert(!ae_lpd(query, 4, NULL));
}

static void runtime_contract(void) {
    static const unsigned char request[] = "\2q\n";
    const uint8_t a[16] = {192,0,2,1}, b[16] = {192,0,2,2};
    const uint8_t mac[6] = {2,0,0,0,0,1};
    argos_enterprise_result_t r;
    argos_cli_selection_t cli;
    argos_dispatch_plan_t plan;
    for (unsigned mode = 0; mode < 2; ++mode) {
        argos_cli_selection_init(&cli);
        assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, mode ? "LPD" : "lpd"));
        argos_dispatch_plan_compile(&plan, &cli);
        assert(argos_dispatch_tcp_port_engine(&plan, 50000, 515) == ARGOS_PROTOCOL_LPD);
        assert(argos_dispatch_tcp_port_engine(&plan, 515, 50000) == ARGOS_PROTOCOL_LPD);
        assert(argos_dispatch_udp_port_engine(&plan, 50000, 515) == ARGOS_PROTOCOL_COUNT);
        assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_IPP));
        assert(argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_LPD) == !mode);
        for (unsigned ip = 4; ip <= 6; ip += 2) {
            argos_flow_state_t flow = {0};
            assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 515));
            assert(argos_enterprise_parse_tcp(50000, 515, request, sizeof(request) - 1, &r));
            int complete = app_flow_payload_complete(ARGOS_PROTOCOL_LPD, 50000, 515, request, sizeof(request) - 1);
            assert(complete);
            argos_flow_note_payload(&flow, ip, a, b, 50000, 515, complete);
            for (unsigned tail = 0; tail < 10000; ++tail)
                assert(argos_flow_should_skip(&flow, ip, a, b, 50000, 515));
            argos_flow_reset_pair(&flow, ip, a, b, 50000, 515);
            assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 515));
            /* A malformed first payload also exhausts the safety budget. */
            assert(app_flow_payload_complete(ARGOS_PROTOCOL_LPD, 50000, 515, request, 1));
            argos_flow_note_payload(&flow, ip, a, b, 50000, 515,
                app_flow_payload_complete(ARGOS_PROTOCOL_LPD, 50000, 515, request, 1));
            assert(argos_flow_should_skip(&flow, ip, a, b, 50000, 515));
            assert(!app_flow_payload_complete(ARGOS_PROTOCOL_LPD, 50000, 515, request, 0));
        }
    }
    assert(!argos_enterprise_parse_tcp(515, 50000, request, sizeof(request) - 1, &r));
    assert(argos_enterprise_parse_tcp(50000, 515, request, sizeof(request) - 1, &r));
    assert(argos_dedup_prepare(&runtime_state.dedup));
    emit_enterprise_result(ARGOS_PROTOCOL_LPD, &r, mac, "192.0.2.1", "192.0.2.2", "|routed", 1);
    assert(writes == 1);
    assert(!strcmp(output, "LPD|02:00:00:00:00:01|192.0.2.1|192.0.2.2|command=receive-job queue=q username=-|routed\n"));
    emit_enterprise_result(ARGOS_PROTOCOL_LPD, &r, mac, "192.0.2.1", "192.0.2.2", "|routed", 1);
    assert(writes == 1);
    emit_enterprise_result(ARGOS_PROTOCOL_LPD, &r, mac, "192.0.2.1", "192.0.2.2", "", 0);
    assert(writes == 2 && !strstr(output, "ENT|"));
    /* The shared boundary preserves untouched legacy wire records. */
    ae_set(&r, "ssh", 1, "banner=SSH-2.0-test");
    emit_enterprise_result(ARGOS_PROTOCOL_SSH, &r, mac, "a", "b", "", 0);
    assert(!strcmp(output, "ENT|02:00:00:00:00:01|a|b|ssh|banner=SSH-2.0-test\n"));
    static const struct { argos_protocol_id_t id; const char *name; } native[] = {
        {ARGOS_PROTOCOL_SYSLOG, "SYSLOG"}, {ARGOS_PROTOCOL_NETFLOW, "NETFLOW"},
        {ARGOS_PROTOCOL_IPFIX, "IPFIX"}, {ARGOS_PROTOCOL_SFLOW, "SFLOW"}
    };
    for (unsigned i = 0; i < sizeof(native) / sizeof(native[0]); ++i) {
        ae_set(&r, native[i].name, 1, "header=only");
        emit_enterprise_result(native[i].id, &r, mac, "a", "b", "", 0);
        char want[160];
        snprintf(want, sizeof(want), "%s|02:00:00:00:00:01|a|b|header=only\n", native[i].name);
        assert(!strcmp(output, want));
    }
    argos_dedup_destroy(&runtime_state.dedup);
}

int main(void) {
    parser_cases(); runtime_contract(); return 0;
}
