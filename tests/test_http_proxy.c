/* Exercise production parser and sink, including credential non-disclosure. */
#define main argos_proxy_unused_main
#define fwrite proxy_fwrite
#define ARGOS_QUIC_STUB
#include "../src/argos-sniffer.c"
#undef fwrite
#undef main
#include <assert.h>

static char output[2048];
static unsigned writes;
size_t proxy_fwrite(const void *p, size_t size, size_t count, FILE *stream) {
    (void)stream;
    assert(size * count < sizeof(output));
    memcpy(output, p, size * count); output[size * count] = 0;
    ++writes; return count;
}

static void parser_cases(void) {
    argos_enterprise_result_t r;
    static const char *good[] = {
        "CONNECT Proxy.Example:443 HTTP/1.1\r\n\r\n",
        "GET http://Example.test/private?SECRET HTTP/1.0\r\nProxy-Authorization: Basic SECRET\r\nVia: SECRET\r\nForwarded: SECRET\r\nX-Forwarded-For: SECRET\r\n\r\n",
        "GET https://[2001:db8::1]/SECRET HTTP/1.1\r\n\r\n",
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate SECRET\r\n\r\n",
        "POST /SECRET HTTP/1.1\r\nx-forwarded-for: SECRET\r\n\r\n"
    };
    static const char *detail[] = {
        "method=CONNECT mode=connect target_host=proxy.example target_port=443 username=- proxy_auth=0 auth_scheme=- via=0 forwarded=0 xff=0",
        "method=GET mode=absolute target_host=example.test target_port=80 username=- proxy_auth=1 auth_scheme=basic via=1 forwarded=1 xff=1",
        "method=GET mode=absolute target_host=[2001:db8::1] target_port=443 username=- proxy_auth=0 auth_scheme=- via=0 forwarded=0 xff=0",
        "method=- mode=forwarded target_host=- target_port=- username=- proxy_auth=1 auth_scheme=negotiate via=0 forwarded=0 xff=0",
        "method=POST mode=forwarded target_host=- target_port=- username=- proxy_auth=0 auth_scheme=- via=0 forwarded=0 xff=1"
    };
    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        int n = (int)strlen(good[i]);
        assert(ae_http_proxy((const unsigned char *)good[i], n, &r));
        assert(r.emit && r.complete && !strcmp(r.proto, "http-proxy"));
        assert(!strcmp(r.detail, detail[i]) && !strstr(r.detail, "SECRET"));
        for (int cut = 0; cut < n; ++cut) {
            assert(!ae_http_proxy((const unsigned char *)good[i], cut, &r));
            assert(!r.emit && !r.complete);
        }
    }
    static const char *bad[] = {
        "GET / HTTP/1.1\r\nHost: example\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\n",
        "CONNECT example:0 HTTP/1.1\r\n\r\n",
        "CONNECT example:65536 HTTP/1.1\r\n\r\n",
        "CONNECT example HTTP/1.1\r\n\r\n",
        "CONNECT [abc]:443 HTTP/1.1\r\n\r\n",
        "CONNECT [::1]evil:443 HTTP/1.1\r\n\r\n",
        "GET http://alice:SECRET@example/ HTTP/1.1\r\n\r\n",
        "GET http://bad|host/ HTTP/1.1\r\n\r\n",
        "GET http://example/ HTTP/2.0\r\n\r\n",
        "GET http://example/ HTTP/1.1\r\n Via: x\r\n\r\n",
        "GET http://example/ HTTP/1.1\r\nVia : x\r\n\r\n",
        "GET http://example/ HTTP/1.1\r\nVia: x\1y\r\n\r\n"
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(!ae_http_proxy((const unsigned char *)bad[i], (int)strlen(bad[i]), &r));
    unsigned char p[8192];
    const char *prefix = "CONNECT example:65535 HTTP/1.1\r\nX: ";
    size_t n = strlen(prefix);
    memcpy(p, prefix, n); memset(p + n, 'x', sizeof(p) - n);
    memcpy(p + 4092, "\r\n\r\n", 4);
    assert(ae_http_proxy(p, sizeof(p), &r));
    assert(strstr(r.detail, "target_port=65535"));
    p[4092] = 'x'; memcpy(p + 4093, "\r\n\r\n", 4);
    assert(!ae_http_proxy(p, sizeof(p), &r));
    assert(!ae_http_proxy(NULL, 16, &r));
    assert(!ae_http_proxy(p, -1, &r));
    assert(!ae_http_proxy(p, 16, NULL));
}

static void runtime_contract(void) {
    argos_cli_selection_t cli;
    argos_dispatch_plan_t plan;
    for (unsigned mode = 0; mode < 2; ++mode) {
        argos_cli_selection_init(&cli);
        assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, mode ? "HTTP-PROXY" : "http-proxy"));
        argos_dispatch_plan_compile(&plan, &cli);
        assert(plan.l4_routes & ARGOS_DISPATCH_L4_TCP);
        assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_HTTP));
        assert(argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_HTTP_PROXY) == !mode);
        for (unsigned i = 0; i < sizeof(ARGOS_HTTP_PROXY_TCP_PORTS) / sizeof(ARGOS_HTTP_PROXY_TCP_PORTS[0]); ++i) {
            uint16_t port = ARGOS_HTTP_PROXY_TCP_PORTS[i];
            assert(argos_dispatch_http_proxy_enabled(&plan, 50000, port));
            assert(argos_dispatch_http_proxy_enabled(&plan, port, 50000));
            assert(argos_dispatch_tcp_port_engine(&plan, 50000, port) == ARGOS_PROTOCOL_COUNT);
            assert(argos_dispatch_udp_port_engine(&plan, 50000, port) == ARGOS_PROTOCOL_COUNT);
        }
        assert(!argos_dispatch_http_proxy_enabled(&plan, 50000, 443));
    }
    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "http"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(!argos_dispatch_http_proxy_enabled(&plan, 50000, 80));
    /* Proxy port selection cannot steal destination/source precedence from SSH. */
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "ssh"));
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "http-proxy"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_tcp_port_engine(&plan, 22, 8080) == ARGOS_PROTOCOL_SSH);
    assert(argos_dispatch_tcp_port_engine(&plan, 8080, 22) == ARGOS_PROTOCOL_SSH);
    const uint8_t a[16] = {192,0,2,1}, b[16] = {192,0,2,2}, mac[6] = {2,0,0,0,0,1};
    for (unsigned ip = 4; ip <= 6; ip += 2) {
        argos_flow_state_t flow = {0};
        for (unsigned attempt = 0; attempt < 8; ++attempt) {
            assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 3128));
            argos_flow_note_payload(&flow, ip, a, b, 50000, 3128, 0);
        }
        assert(argos_flow_should_skip(&flow, ip, a, b, 50000, 3128));
        assert(!argos_flow_should_skip(&flow, ip, b, a, 3128, 50000));
        argos_flow_reset_pair(&flow, ip, a, b, 50000, 3128);
        assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 3128));
        argos_flow_note_payload(&flow, ip, a, b, 50000, 3128, 1);
        assert(argos_flow_should_skip(&flow, ip, a, b, 50000, 3128));
    }
    argos_enterprise_result_t r;
    static const unsigned char request[] = "CONNECT proxy.example:443 HTTP/1.1\r\n\r\nSECRET BODY";
    assert(ae_http_proxy(request, sizeof(request) - 1, &r));
    assert(argos_dedup_prepare(&runtime_state.dedup));
    emit_enterprise_result(ARGOS_PROTOCOL_HTTP_PROXY, &r, mac, "a", "b", "|routed", 1);
    assert(writes == 1);
    assert(!strcmp(output, "HTTP-PROXY|02:00:00:00:00:01|a|b|method=CONNECT mode=connect target_host=proxy.example target_port=443 username=- proxy_auth=0 auth_scheme=- via=0 forwarded=0 xff=0|routed\n"));
    emit_enterprise_result(ARGOS_PROTOCOL_HTTP_PROXY, &r, mac, "a", "b", "|routed", 1);
    assert(writes == 1);
    emit_enterprise_result(ARGOS_PROTOCOL_HTTP_PROXY, &r, mac, "a", "b", "", 0);
    assert(writes == 2 && !strstr(output, "ENT|") && !strstr(output, "SECRET"));
    argos_dedup_destroy(&runtime_state.dedup);
}

int main(void) { parser_cases(); runtime_contract(); return 0; }
