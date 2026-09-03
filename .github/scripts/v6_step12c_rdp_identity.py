from pathlib import Path

h=Path('src/argos_identity.h')
src=Path('src/argos-sniffer.c')
test=Path('tests/test_identity_rdp.c')

hs=h.read_text()
anchor='''static inline int argos_identity_build(argos_identity_result_t *r,\n                                       const char *protocol, const char *type,\n                                       const unsigned char *value, size_t len,\n                                       int raw_mode) {\n'''
if hs.count(anchor) != 1:
    raise SystemExit(f'identity build anchor count={hs.count(anchor)}')
# Append extractor before #endif to keep generic builder untouched.
end='''\n#endif\n'''
if hs.count(end) != 1:
    raise SystemExit(f'identity header end count={hs.count(end)}')
extractor=r'''
/* RDP identity evidence is limited to the mstshash cookie carried in the
 * initial X.224 Connection Request. It is a user/login hint, not proof of an
 * authenticated principal and never device ownership. No stream scan occurs:
 * only the already-inspected initial RDP handshake payload is considered. */
static inline int argos_identity_rdp_mstshash(const unsigned char *p, size_t len,
                                              int raw_mode,
                                              argos_identity_result_t *r) {
    static const unsigned char prefix[] = "Cookie: mstshash=";
    if (!p || !r || len < 11U || p[0] != 0x03U || p[1] != 0x00U || p[5] != 0xe0U)
        return 0;

    const size_t prefix_len = sizeof(prefix) - 1U;
    const unsigned char *c = NULL;
    for (size_t i = 0; i + prefix_len <= len; ++i) {
        int match = 1;
        for (size_t j = 0; j < prefix_len; ++j) {
            unsigned char a = p[i + j], b = prefix[j];
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b) { match = 0; break; }
        }
        if (match) { c = p + i + prefix_len; break; }
    }
    if (!c || c >= p + len) return 0;

    const unsigned char *end = NULL;
    for (const unsigned char *q = c; q + 1 < p + len; ++q) {
        if (q[0] == '\r' && q[1] == '\n') { end = q; break; }
    }
    if (!end || end <= c) return 0;
    size_t n = (size_t)(end - c);
    if (n > 120U) n = 120U;
    return argos_identity_build(r, "rdp", "mstshash", c, n, raw_mode);
}
'''
h.write_text(hs.replace(end, '\n'+extractor+end, 1))

s=src.read_text()
block='''                argos_enterprise_result_t ent_tcp;\n                int ent_tcp_seen = 0;\n                if (enterprise_tcp && payload_len > 0) {\n                    ent_tcp_seen = argos_enterprise_parse_tcp(sport, dport, buffer + payload_offset, payload_len, &ent_tcp);\n                    if (ent_tcp_seen && ent_tcp.emit) {\n                        char ent_mac[18], ent_sig[768];\n                        format_mac(src_mac, ent_mac);\n                        snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent_tcp.proto, ent_tcp.detail);\n                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                            emit_telemetry("ENT|%s|%s|%s|%s|%s%s\\n", ent_mac, src_ip_str, dst_ip_str, ent_tcp.proto, ent_tcp.detail, routed_str);\n                    }\n                }\n\n'''
if s.count(block) != 1:
    raise SystemExit(f'enterprise TCP emission block count={s.count(block)}')
new=block+r'''                /* Identity is a separate explicit vector. RDP extraction is
                 * attempted only on client->server 3389 handshake payloads that
                 * enterprise mode already admitted; default ENT remains redacted. */
                if (opt_identity && dport == 3389U && payload_len > 0) {
                    argos_identity_result_t ident;
                    if (argos_identity_rdp_mstshash(buffer + payload_offset, (size_t)payload_len,
                                                    opt_identity_raw, &ident)) {
                        char ident_mac[18], ident_sig[320];
                        format_mac(src_mac, ident_mac);
                        snprintf(ident_sig, sizeof(ident_sig), "%s|%s|%s|%s",
                                 src_ip_str, ident.protocol, ident.type, ident.value);
                        if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, opt_enterprise_rl))
                            emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                                           ident_mac, src_ip_str, ident.protocol,
                                           ident.type, ident.value, routed_str);
                    }
                }

'''
src.write_text(s.replace(block,new,1))

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_identity.h"

static void check(int ok, const char *msg) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); }
}

static size_t make_rdp(unsigned char *p, size_t cap, const char *cookie, unsigned x224) {
    const char pre[] = "Cookie: mstshash=";
    size_t n = strlen(cookie);
    size_t need = 11U + sizeof(pre)-1U + n + 2U;
    if (cap < need) return 0U;
    memset(p,0,cap); p[0]=0x03; p[1]=0x00; p[5]=(unsigned char)x224;
    memcpy(p+11,pre,sizeof(pre)-1U);
    memcpy(p+11+sizeof(pre)-1U,cookie,n);
    memcpy(p+11+sizeof(pre)-1U+n,"\r\n",2U);
    return need;
}

int main(void) {
    unsigned char p[320];
    const char *secret="alice.enterprise";
    size_t n=make_rdp(p,sizeof(p),secret,0xe0U);
    argos_identity_result_t hashed, raw;
    check(n>0,"fixture built");
    check(argos_identity_rdp_mstshash(p,n,0,&hashed),"RDP mstshash hash evidence");
    check(strcmp(hashed.protocol,"rdp")==0 && strcmp(hashed.type,"mstshash")==0,"RDP identity labels");
    check(strstr(hashed.value,"hash=")==hashed.value && strstr(hashed.value,secret)==NULL,"hash mode hides raw identity");
    check(argos_identity_rdp_mstshash(p,n,1,&raw),"RDP mstshash raw evidence");
    check(strcmp(raw.value,secret)==0,"raw opt-in returns bounded value");
    check(raw.hash==hashed.hash && raw.value_len==hashed.value_len,"same identity correlation across modes");

    n=make_rdp(p,sizeof(p),"alice|corp\\admin",0xe0U);
    check(argos_identity_rdp_mstshash(p,n,1,&raw),"sanitized raw evidence");
    check(strcmp(raw.value,"alice/corp/admin")==0,"raw telemetry delimiters sanitized");

    n=make_rdp(p,sizeof(p),secret,0xd0U);
    check(!argos_identity_rdp_mstshash(p,n,0,&hashed),"server X224 confirm is not identity evidence");
    n=make_rdp(p,sizeof(p),secret,0xe0U);
    p[0]=0x04;
    check(!argos_identity_rdp_mstshash(p,n,0,&hashed),"non-TPKT rejected");

    memset(p,0,sizeof(p)); p[0]=0x03; p[1]=0x00; p[5]=0xe0;
    check(!argos_identity_rdp_mstshash(p,32,0,&hashed),"no cookie means no identity");

    char long_cookie[200]; memset(long_cookie,'x',sizeof(long_cookie)-1U); long_cookie[sizeof(long_cookie)-1U]='\0';
    n=make_rdp(p,sizeof(p),long_cookie,0xe0U);
    check(argos_identity_rdp_mstshash(p,n,0,&hashed),"long cookie accepted boundedly");
    check(hashed.value_len==120U,"RDP identity bounded to 120 bytes");

    puts("RDP identity fixtures: PASS");
    return 0;
}
''')
print('staged RDP identity extractor')
