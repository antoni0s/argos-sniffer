from pathlib import Path
import re

src=Path('src/argos-sniffer.c')
cfg=Path('src/argos_config.h')
test=Path('tests/test_identity_config.c')
s=src.read_text()

cfg.write_text(r'''#ifndef ARGOS_CONFIG_H
#define ARGOS_CONFIG_H

#include <string.h>

/* Runtime modes are explicit state, not combinations of loosely-related
 * booleans. RAW is always an explicit opt-in; HASH remains the safe default. */
typedef enum {
    ARGOS_IDENTITY_OFF = 0,
    ARGOS_IDENTITY_HASH = 1,
    ARGOS_IDENTITY_RAW = 2
} argos_identity_mode_t;

static inline int argos_identity_mode_parse(const char *arg,
                                            argos_identity_mode_t *out) {
    if (!out) return 0;
    if (!arg || !*arg || strcmp(arg, "hash") == 0) {
        *out = ARGOS_IDENTITY_HASH;
        return 1;
    }
    if (strcmp(arg, "raw") == 0) {
        *out = ARGOS_IDENTITY_RAW;
        return 1;
    }
    return 0;
}

static inline int argos_identity_enabled(argos_identity_mode_t mode) {
    return mode != ARGOS_IDENTITY_OFF;
}

static inline int argos_identity_raw(argos_identity_mode_t mode) {
    return mode == ARGOS_IDENTITY_RAW;
}

#endif
''')

# Config module include.
anchor='#include "argos_wireguard.h"\n#include "argos_identity.h"\n'
if s.count(anchor)!=1: raise SystemExit(f'config include anchor count={s.count(anchor)}')
s=s.replace(anchor,'#include "argos_wireguard.h"\n#include "argos_config.h"\n#include "argos_identity.h"\n',1)

# Replace two booleans with one explicit mode.
old='    int opt_identity = 0, opt_identity_raw = 0;\n'
if s.count(old)!=1: raise SystemExit(f'identity vars anchor count={s.count(old)}')
s=s.replace(old,'    argos_identity_mode_t identity_mode = ARGOS_IDENTITY_OFF;\n',1)

# getopt_long: --identity accepts optional =hash|raw. Keep hidden/legacy alias.
old='''        {"identity", no_argument, NULL, OPT_IDENTITY},\n        {"identity-raw", no_argument, NULL, OPT_IDENTITY_RAW},\n'''
new='''        {"identity", optional_argument, NULL, OPT_IDENTITY},\n        {"identity-raw", no_argument, NULL, OPT_IDENTITY_RAW}, /* compatibility alias */\n'''
if s.count(old)!=1: raise SystemExit(f'long option anchor count={s.count(old)}')
s=s.replace(old,new,1)

old='''            case OPT_IDENTITY: opt_identity = 1; break;\n            case OPT_IDENTITY_RAW: opt_identity_raw = 1; break;\n'''
new='''            case OPT_IDENTITY:\n                if (!argos_identity_mode_parse(optarg, &identity_mode)) {\n                    fprintf(stderr, "Error: --identity expects hash or raw (use --identity=hash or --identity=raw).\\n");\n                    return 1;\n                }\n                break;\n            case OPT_IDENTITY_RAW:\n                /* v6 compatibility alias for the former second flag. */\n                identity_mode = ARGOS_IDENTITY_RAW;\n                break;\n'''
if s.count(old)!=1: raise SystemExit(f'identity cases anchor count={s.count(old)}')
s=s.replace(old,new,1)

old='''    if (opt_identity && !opt_enterprise) {\n        fprintf(stderr, "Error: --identity requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n    if (opt_identity_raw && !opt_identity) {\n        fprintf(stderr, "Error: --identity-raw requires --identity.\\n");\n        return 1;\n    }\n'''
new='''    if (argos_identity_enabled(identity_mode) && !opt_enterprise) {\n        fprintf(stderr, "Error: --identity requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n'''
if s.count(old)!=1: raise SystemExit(f'identity dependency anchor count={s.count(old)}')
s=s.replace(old,new,1)

# Help presents one primary option; legacy alias remains accepted but hidden.
old='''"  --identity      Observed identity metadata from already-inspected handshake/control fields.\\n"\n"                  Requires --enterprise; pseudonymized/hash-only by default.\\n"\n"  --identity-raw  Second opt-in for bounded readable identity values where supported.\\n"\n"                  Requires --identity; never passwords, tickets, tokens or auth blobs.\\n\\n"\n'''
new='''"  --identity[=MODE] Observed identity from already-inspected handshake/control fields.\\n"\n"                    MODE is hash (default) or raw; raw is an explicit privacy opt-in.\\n"\n"                    Requires --enterprise; never passwords, tickets, tokens or auth blobs.\\n\\n"\n'''
if s.count(old)!=1: raise SystemExit(f'identity help anchor count={s.count(old)}')
s=s.replace(old,new,1)

# Runtime conditions consume the single state.
s=s.replace('if (opt_identity && dport == 3389U', 'if (argos_identity_enabled(identity_mode) && dport == 3389U')
s=s.replace('if (opt_identity && dport == 445U', 'if (argos_identity_enabled(identity_mode) && dport == 445U')
s=s.replace('if (opt_identity && dport == 88U', 'if (argos_identity_enabled(identity_mode) && dport == 88U')
s=s.replace('if (opt_identity && dport == 1812U', 'if (argos_identity_enabled(identity_mode) && dport == 1812U')
s=s.replace('opt_identity_raw, &ident', 'argos_identity_raw(identity_mode), &ident')
s=s.replace('opt_identity_raw, ids', 'argos_identity_raw(identity_mode), ids')
if 'opt_identity_raw' in s or re.search(r'\bopt_identity\b', s):
    raise SystemExit('legacy identity boolean still referenced after mode conversion')

# Centralize IDENT wire formatting/dedup. This is runtime/telemetry behavior,
# not protocol parser behavior.
dedup_anchor='''static int dedup_should_suppress(const char *mac, const char *evtype, const char *payload, int rl_enabled) {\n    return dedup_should_suppress_for(mac, evtype, payload, rl_enabled, rate_limit_ttl, 1);\n}\n\n'''
helper=r'''static int dedup_should_suppress(const char *mac, const char *evtype, const char *payload, int rl_enabled) {
    return dedup_should_suppress_for(mac, evtype, payload, rl_enabled, rate_limit_ttl, 1);
}

/* One wire-format boundary for all observed identity parsers. Protocol parsers
 * produce bounded evidence; this runtime helper owns MAC formatting, dedup and
 * IDENT serialization so those concerns cannot drift per protocol. */
static void emit_identity_observation(const uint8_t mac[6], const char *src_ip,
                                      const argos_identity_result_t *ident,
                                      const char *routed_str, int rl_enabled) {
    if (!mac || !src_ip || !ident || !ident->present) return;
    char ident_mac[18], ident_sig[320];
    format_mac(mac, ident_mac);
    snprintf(ident_sig, sizeof(ident_sig), "%.45s|%.23s|%.23s|%.191s",
             src_ip, ident->protocol, ident->type, ident->value);
    if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, rl_enabled))
        emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                       ident_mac, src_ip, ident->protocol, ident->type,
                       ident->value, routed_str ? routed_str : "");
}

'''
if s.count(dedup_anchor)!=1: raise SystemExit(f'dedup helper anchor count={s.count(dedup_anchor)}')
s=s.replace(dedup_anchor,helper,1)

# Replace four single-result emit bodies.
single_pattern=re.compile(r'''(?P<indent>\s*)char ident_mac\[18\], ident_sig\[320\];\n(?P=indent)format_mac\(src_mac, ident_mac\);\n(?P=indent)snprintf\(ident_sig, sizeof\(ident_sig\), (?:"%s\|%s\|%s\|%s"|"%\.45s\|%\.23s\|%\.23s\|%\.191s"),\n(?P=indent)         src_ip_str, ident\.protocol, ident\.type, ident\.value\);\n(?P=indent)if \(!dedup_should_suppress\(ident_mac, "IDENT", ident_sig, opt_enterprise_rl\)\)\n(?P=indent)    emit_telemetry\("IDENT\|%s\|%s\|%s\|%s\|%s%s\\n",\n(?P=indent)                   ident_mac, src_ip_str, ident\.protocol,\n(?P=indent)                   ident\.type, ident\.value, routed_str\);''')
s, count = single_pattern.subn(lambda m: m.group('indent')+'emit_identity_observation(src_mac, src_ip_str, &ident, routed_str,\n'+m.group('indent')+'                          opt_enterprise_rl);', s)
if count != 4: raise SystemExit(f'single IDENT emit replacement count={count}')

# NTLM loop has indexed results; replace its duplicated serialization block.
indexed_pattern=re.compile(r'''(?P<indent>\s*)char ident_mac\[18\], ident_sig\[320\];\n(?P=indent)format_mac\(src_mac, ident_mac\);\n(?P=indent)/\* Keep the dedup signature bounded.*?\*/\n(?P=indent)snprintf\(ident_sig, sizeof\(ident_sig\), "%.45s\|%.23s\|%.23s\|%.191s",\n(?P=indent)         src_ip_str, ids\[ii\]\.protocol, ids\[ii\]\.type, ids\[ii\]\.value\);\n(?P=indent)if \(!dedup_should_suppress\(ident_mac, "IDENT", ident_sig, opt_enterprise_rl\)\)\n(?P=indent)    emit_telemetry\("IDENT\|%s\|%s\|%s\|%s\|%s%s\\n",\n(?P=indent)                   ident_mac, src_ip_str, ids\[ii\]\.protocol,\n(?P=indent)                   ids\[ii\]\.type, ids\[ii\]\.value, routed_str\);''', re.S)
s, count = indexed_pattern.subn(lambda m: m.group('indent')+'emit_identity_observation(src_mac, src_ip_str, &ids[ii], routed_str,\n'+m.group('indent')+'                          opt_enterprise_rl);', s)
if count != 1: raise SystemExit(f'indexed IDENT emit replacement count={count}')

if s.count('emit_identity_observation(src_mac') != 5:
    raise SystemExit(f'common identity emitter call count={s.count("emit_identity_observation(src_mac")}')

src.write_text(s)

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_config.h"
static void check(int ok,const char *m){if(!ok){fprintf(stderr,"FAIL: %s\n",m);exit(1);}}
int main(void){
 argos_identity_mode_t m=ARGOS_IDENTITY_OFF;
 check(!argos_identity_enabled(m),"off disabled");
 check(argos_identity_mode_parse(NULL,&m)&&m==ARGOS_IDENTITY_HASH,"bare --identity maps hash");
 check(argos_identity_enabled(m)&&!argos_identity_raw(m),"hash enabled not raw");
 check(argos_identity_mode_parse("hash",&m)&&m==ARGOS_IDENTITY_HASH,"explicit hash");
 check(argos_identity_mode_parse("raw",&m)&&m==ARGOS_IDENTITY_RAW,"explicit raw");
 check(argos_identity_enabled(m)&&argos_identity_raw(m),"raw enabled raw");
 check(!argos_identity_mode_parse("RAW",&m),"mode names exact lowercase");
 check(!argos_identity_mode_parse("unsafe",&m),"unknown mode rejected");
 check(!argos_identity_mode_parse("raw",NULL),"NULL output rejected");
 puts("Identity config fixtures: PASS");return 0;
}
''')
print('staged identity mode/common-emitter refactor')
