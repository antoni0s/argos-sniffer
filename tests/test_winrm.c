#define main argos_winrm_unused_main
#define fwrite winrm_fwrite
#define ARGOS_QUIC_STUB
#include "../src/argos-sniffer.c"
#undef fwrite
#undef main
#include <assert.h>

static char output[2048];
static unsigned writes;
size_t winrm_fwrite(const void *p, size_t size, size_t count, FILE *stream) {
    (void)stream;
    assert(size * count < sizeof(output));
    memcpy(output, p, size * count); output[size * count] = 0;
    ++writes; return count;
}

static void parser_cases(void) {
    argos_enterprise_result_t r;
    static const struct { const char *auth; const char *want; } schemes[] = {
        {"Basic SECRET", "basic"}, {"Digest SECRET", "digest"},
        {"NTLM SECRET", "ntlm"}, {"Negotiate SECRET", "negotiate"},
        {"Kerberos SECRET", "kerberos"}, {"CredSSP SECRET", "credssp"},
        {"Bearer SECRET", "other"}
    };
    for (unsigned i = 0; i < sizeof(schemes) / sizeof(schemes[0]); ++i) {
        char p[512], want[256];
        int n = snprintf(p, sizeof(p),
            "POST /wsman HTTP/1.1\r\nAuthorization: %s\r\nContent-Type: application/soap+xml;charset=UTF-8\r\n\r\nSECRET BODY",
            schemes[i].auth);
        snprintf(want, sizeof(want),
            "transport=http wsman=1 soap=1 method=POST auth=%s username=- encrypted=0",
            schemes[i].want);
        assert(ae_winrm((const unsigned char *)p, n, 0, &r));
        assert(r.emit && r.complete && !strcmp(r.proto, "winrm"));
        assert(!strcmp(r.detail, want) && !strstr(r.detail, "SECRET"));
        const char *body = strstr(p, "SECRET BODY");
        assert(body);
        for (int cut = 0; cut < (int)(body - p); ++cut)
            assert(!ae_winrm((const unsigned char *)p, cut, 0, &r));
    }
    static const char encrypted[] =
        "POST /wsman HTTP/1.1\r\nContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\r\nSECRET";
    assert(ae_winrm((const unsigned char *)encrypted, sizeof(encrypted) - 1, 0, &r));
    assert(!strcmp(r.detail,
        "transport=http wsman=1 soap=0 method=POST auth=- username=- encrypted=1"));
    static const char body_only[] =
        "POST /wsman HTTP/1.1\r\nX-Test: safe\r\n\r\napplication/soap+xml Authorization: Basic SECRET";
    assert(ae_winrm((const unsigned char *)body_only, sizeof(body_only) - 1, 0, &r));
    assert(!strcmp(r.detail,
        "transport=http wsman=1 soap=0 method=POST auth=- username=- encrypted=0"));
    static const char *bad[] = {
        "POST /not-wsman HTTP/1.1\r\nContent-Type: application/soap+xml\r\n\r\n",
        "post /wsman HTTP/1.1\r\n\r\n",
        "POST /wsman HTTP/2.0\r\n\r\n",
        "POST /wsman HTTP/1.1\n\n",
        "POST /wsman HTTP/1.1\r\nBad : value\r\n\r\n"
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(!ae_winrm((const unsigned char *)bad[i], (int)strlen(bad[i]), 0, &r));
    unsigned char hello[] = {0x16,0x03,0x03,0x00,0x08,0x01,0x00,0x00,0x04,0,0,0,0};
    assert(ae_winrm(hello, sizeof(hello), 1, &r));
    assert(!strcmp(r.detail,
        "transport=https wsman=- soap=- method=- auth=- username=- encrypted=1"));
    hello[5] = 0x0b; assert(!ae_winrm(hello, sizeof(hello), 1, &r));
    hello[5] = 0x01; hello[4] = 3; assert(!ae_winrm(hello, sizeof(hello), 1, &r));
    hello[4] = 8; hello[2] = 0; assert(!ae_winrm(hello, sizeof(hello), 1, &r));
    assert(!ae_winrm(NULL, 20, 0, &r));
    assert(!ae_winrm(hello, sizeof(hello), 0, NULL));
}

static void runtime_contract(void) {
    argos_cli_selection_t cli; argos_dispatch_plan_t plan;
    for (unsigned mode = 0; mode < 2; ++mode) {
        argos_cli_selection_init(&cli);
        assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL,
            mode ? "WINRM" : "winrm"));
        argos_dispatch_plan_compile(&plan, &cli);
        assert(plan.l4_routes & ARGOS_DISPATCH_L4_TCP);
        assert(argos_dispatch_winrm_enabled(&plan, 50000, 5985));
        assert(argos_dispatch_winrm_enabled(&plan, 5986, 50000));
        assert(!argos_dispatch_winrm_enabled(&plan, 5985, 5986));
        assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_HTTP));
        assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_TLS));
        assert(argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_WINRM) == !mode);
    }
    const uint8_t a[16] = {192,0,2,1}, b[16] = {192,0,2,2};
    for (unsigned ip = 4; ip <= 6; ip += 2) {
        argos_flow_state_t flow = {0};
        for (unsigned attempt = 0; attempt < 8; ++attempt) {
            assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 5985));
            argos_flow_note_payload(&flow, ip, a, b, 50000, 5985, 0);
        }
        assert(argos_flow_should_skip(&flow, ip, a, b, 50000, 5985));
        assert(!argos_flow_should_skip(&flow, ip, b, a, 5985, 50000));
        argos_flow_reset_pair(&flow, ip, a, b, 50000, 5985);
        assert(!argos_flow_should_skip(&flow, ip, a, b, 50000, 5985));
    }
    static const unsigned char request[] =
        "POST /wsman HTTP/1.1\r\nAuthorization: Negotiate SECRET\r\n\r\nSECRET BODY";
    argos_enterprise_result_t r;
    const uint8_t mac[6] = {2,0,0,0,0,1};
    assert(ae_winrm(request, sizeof(request) - 1, 0, &r));
    assert(argos_dedup_prepare(&runtime_state.dedup));
    emit_enterprise_result(ARGOS_PROTOCOL_WINRM, &r, mac, "a", "b", "|routed", 1);
    assert(writes == 1);
    assert(!strcmp(output,
        "WINRM|02:00:00:00:00:01|a|b|transport=http wsman=1 soap=0 method=POST auth=negotiate username=- encrypted=0|routed\n"));
    assert(!strstr(output, "ENT|") && !strstr(output, "SECRET"));
    argos_dedup_destroy(&runtime_state.dedup);
}

int main(void) { parser_cases(); runtime_contract(); return 0; }
