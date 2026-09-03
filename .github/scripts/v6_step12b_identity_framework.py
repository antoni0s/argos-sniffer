from pathlib import Path

src = Path('src/argos-sniffer.c')
identity_h = Path('src/argos_identity.h')
test = Path('tests/test_identity_framework.c')

s = src.read_text()

inc_anchor = '#include "argos_wireguard.h"\n'
if s.count(inc_anchor) != 1:
    raise SystemExit(f'identity include anchor count={s.count(inc_anchor)}')
s = s.replace(inc_anchor, inc_anchor + '#include "argos_identity.h"\n', 1)

var_anchor = '    int opt_enterprise = 0, opt_enterprise_rl = 1;\n'
if s.count(var_anchor) != 1:
    raise SystemExit(f'identity var anchor count={s.count(var_anchor)}')
s = s.replace(var_anchor, var_anchor + '    int opt_identity = 0, opt_identity_raw = 0;\n', 1)

enum_old = '    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE, OPT_ENTERPRISE, OPT_ENTERPRISE_VERBOSE, OPT_WIREGUARD_PORT };\n'
enum_new = '    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE, OPT_ENTERPRISE, OPT_ENTERPRISE_VERBOSE, OPT_WIREGUARD_PORT, OPT_IDENTITY, OPT_IDENTITY_RAW };\n'
if s.count(enum_old) != 1:
    raise SystemExit(f'identity enum anchor count={s.count(enum_old)}')
s = s.replace(enum_old, enum_new, 1)

opts_old = '''        {"enterprise-verbose", no_argument, NULL, OPT_ENTERPRISE_VERBOSE},\n        {"wireguard-port", required_argument, NULL, OPT_WIREGUARD_PORT},\n'''
opts_new = '''        {"enterprise-verbose", no_argument, NULL, OPT_ENTERPRISE_VERBOSE},\n        {"wireguard-port", required_argument, NULL, OPT_WIREGUARD_PORT},\n        {"identity", no_argument, NULL, OPT_IDENTITY},\n        {"identity-raw", no_argument, NULL, OPT_IDENTITY_RAW},\n'''
if s.count(opts_old) != 1:
    raise SystemExit(f'identity options anchor count={s.count(opts_old)}')
s = s.replace(opts_old, opts_new, 1)

case_anchor = '''            case OPT_ENTERPRISE: opt_enterprise = 1; opt_enterprise_rl = 1; opt_v6 = 1; break;\n            case OPT_ENTERPRISE_VERBOSE: opt_enterprise = 1; opt_enterprise_rl = 0; opt_v6 = 1; break;\n'''
case_new = case_anchor + '''            case OPT_IDENTITY: opt_identity = 1; break;\n            case OPT_IDENTITY_RAW: opt_identity_raw = 1; break;\n'''
if s.count(case_anchor) != 1:
    raise SystemExit(f'identity switch anchor count={s.count(case_anchor)}')
s = s.replace(case_anchor, case_new, 1)

check_anchor = '''    if (wireguard_port_explicit && !opt_enterprise) {\n        fprintf(stderr, "Error: --wireguard-port requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n\n'''
check_new = check_anchor + '''    if (opt_identity && !opt_enterprise) {\n        fprintf(stderr, "Error: --identity requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n    if (opt_identity_raw && !opt_identity) {\n        fprintf(stderr, "Error: --identity-raw requires --identity.\\n");\n        return 1;\n    }\n\n'''
if s.count(check_anchor) != 1:
    raise SystemExit(f'identity dependency anchor count={s.count(check_anchor)}')
s = s.replace(check_anchor, check_new, 1)

usage_old = '"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose] [--wireguard-port port]\\n"\n'
usage_new = '"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose] [--wireguard-port port] [--identity [--identity-raw]]\\n"\n'
if s.count(usage_old) != 1:
    raise SystemExit(f'identity usage anchor count={s.count(usage_old)}')
s = s.replace(usage_old, usage_new, 1)

help_old = '''"  --wireguard-port <port>  WireGuard UDP port for structural detection (default: 51820).\\n"\n"                          Requires --enterprise; packet structure is validated before emission.\\n"\n'''
help_new = help_old + '''"  --identity      Opt-in observed identity metadata from already-inspected handshake/control fields.\\n"\n"                  Requires --enterprise; values are pseudonymized/hash-only by default.\\n"\n"  --identity-raw  Explicit second opt-in allowing bounded readable identity values where supported.\\n"\n"                  Requires --identity; never exposes passwords, tickets, tokens or auth blobs.\\n"\n'''
if s.count(help_old) != 1:
    raise SystemExit(f'identity help anchor count={s.count(help_old)}')
s = s.replace(help_old, help_new, 1)

wire_anchor = '"  ENT|mac|src_ip|dst_ip|protocol|fingerprint[|routed]\\n"\n'
if s.count(wire_anchor) == 1:
    s = s.replace(wire_anchor, wire_anchor + '"  IDENT|mac|src_ip|protocol|type|identity[|routed]  (--identity only)\\n"\n', 1)
else:
    print(f'warning: IDENT help wire anchor count={s.count(wire_anchor)}; leaving wire help unchanged')

src.write_text(s)

identity_h.write_text(r'''#ifndef ARGOS_IDENTITY_H
#define ARGOS_IDENTITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Optional identity evidence derived only from handshake/control fields that
 * Argos already inspects for protocol fingerprinting. This is not a generic
 * payload scanner. "Observed identity" is evidence, never device ownership.
 */
typedef struct {
    char protocol[24];
    char type[24];
    char value[192];
    uint32_t hash;
    uint16_t value_len;
    uint8_t present;
} argos_identity_result_t;

static inline uint32_t argos_identity_hash32(const unsigned char *p, size_t len) {
    uint32_t h = 2166136261U;
    if (!p) return 0U;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619U;
    }
    return h;
}

static inline size_t argos_identity_clean(const unsigned char *src, size_t len,
                                          char *dst, size_t cap) {
    size_t o = 0U;
    if (!dst || cap == 0U) return 0U;
    if (!src) { dst[0] = '\0'; return 0U; }
    for (size_t i = 0; i < len && o + 1U < cap; ++i) {
        unsigned char c = src[i];
        if (c >= 32U && c <= 126U) {
            dst[o++] = (c == '|' || c == '\\') ? '/' : (char)c;
        } else if (o > 0U && dst[o - 1U] != ' ') {
            dst[o++] = ' ';
        }
    }
    while (o > 0U && dst[o - 1U] == ' ') --o;
    dst[o] = '\0';
    return o;
}

static inline int argos_identity_build(argos_identity_result_t *r,
                                       const char *protocol, const char *type,
                                       const unsigned char *value, size_t len,
                                       int raw_mode) {
    if (!r) return 0;
    memset(r, 0, sizeof(*r));
    if (!protocol || !type || !value || len == 0U) return 0;
    if (len > 160U) len = 160U;
    snprintf(r->protocol, sizeof(r->protocol), "%s", protocol);
    snprintf(r->type, sizeof(r->type), "%s", type);
    r->hash = argos_identity_hash32(value, len);
    r->value_len = (uint16_t)len;
    r->present = 1U;
    if (raw_mode)
        argos_identity_clean(value, len, r->value, sizeof(r->value));
    else
        snprintf(r->value, sizeof(r->value), "hash=%08x,len=%u",
                 r->hash, (unsigned)r->value_len);
    return 1;
}

#endif
''')

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_identity.h"

static void check(int ok, const char *msg) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); }
}

int main(void) {
    const unsigned char v[] = "alice|corp\\admin\n";
    argos_identity_result_t a, b, raw;
    check(argos_identity_build(&a, "rdp", "user", v, sizeof(v)-1U, 0), "hash identity builds");
    check(a.present && a.value_len == sizeof(v)-1U, "presence and bounded length");
    check(strstr(a.value, "hash=") == a.value, "default is hash-only");
    check(strstr(a.value, "alice") == NULL, "default never exposes raw identity");
    check(argos_identity_build(&b, "rdp", "user", v, sizeof(v)-1U, 0), "second hash builds");
    check(a.hash == b.hash && strcmp(a.value, b.value) == 0, "identity hash deterministic");
    check(argos_identity_build(&raw, "rdp", "user", v, sizeof(v)-1U, 1), "raw identity builds");
    check(strstr(raw.value, "alice/corp/admin") != NULL, "raw mode bounded and delimiter-cleaned");
    check(strchr(raw.value, '|') == NULL && strchr(raw.value, '\\') == NULL && strchr(raw.value, '\n') == NULL,
          "raw identity sanitizes telemetry delimiters/control bytes");
    check(!argos_identity_build(&a, "rdp", "user", NULL, 0, 0), "empty identity rejected");
    puts("identity framework fixtures: PASS");
    return 0;
}
''')
print('staged identity framework')
