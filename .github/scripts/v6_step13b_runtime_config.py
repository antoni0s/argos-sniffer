from pathlib import Path
import re

src=Path('src/argos-sniffer.c')
cfg=Path('src/argos_config.h')
test=Path('tests/test_runtime_config.c')
s=src.read_text()
c=cfg.read_text()

# Extend config module with the tightly related enterprise runtime state only.
anchor='''static inline int argos_identity_raw(argos_identity_mode_t mode) {\n    return mode == ARGOS_IDENTITY_RAW;\n}\n\n#endif\n'''
if c.count(anchor)!=1:
    raise SystemExit(f'config anchor count={c.count(anchor)}')
# Keep the standalone header self-contained for tests and future reuse.
if '#include <stdint.h>\n' not in c:
    c=c.replace('#include <string.h>\n','#include <stdint.h>\n#include <string.h>\n',1)
addition=r'''static inline int argos_identity_raw(argos_identity_mode_t mode) {
    return mode == ARGOS_IDENTITY_RAW;
}

typedef struct {
    int enterprise_enabled;
    int enterprise_rate_limited;
    argos_identity_mode_t identity_mode;
    uint16_t wireguard_port;
    int wireguard_port_explicit;
} argos_runtime_config_t;

static inline void argos_runtime_config_init(argos_runtime_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enterprise_rate_limited = 1;
    cfg->identity_mode = ARGOS_IDENTITY_OFF;
    cfg->wireguard_port = 51820U;
}

static inline void argos_runtime_enable_enterprise(argos_runtime_config_t *cfg,
                                                   int verbose) {
    if (!cfg) return;
    cfg->enterprise_enabled = 1;
    cfg->enterprise_rate_limited = verbose ? 0 : 1;
}

/* Return a stable message owned by this module; NULL means valid. */
static inline const char *argos_runtime_config_validate(const argos_runtime_config_t *cfg) {
    if (!cfg) return "invalid runtime configuration";
    if (cfg->wireguard_port_explicit && !cfg->enterprise_enabled)
        return "--wireguard-port requires --enterprise or --enterprise-verbose.";
    if (argos_identity_enabled(cfg->identity_mode) && !cfg->enterprise_enabled)
        return "--identity requires --enterprise or --enterprise-verbose.";
    return NULL;
}

#endif
'''
cfg.write_text(c.replace(anchor,addition,1))

old='''    int opt_enterprise = 0, opt_enterprise_rl = 1;\n    argos_identity_mode_t identity_mode = ARGOS_IDENTITY_OFF;\n    uint16_t opt_wireguard_port = 51820U;\n    int wireguard_port_explicit = 0;\n'''
new='''    argos_runtime_config_t runtime_cfg;\n    argos_runtime_config_init(&runtime_cfg);\n'''
if s.count(old)!=1:
    raise SystemExit(f'runtime local anchor count={s.count(old)}')
s=s.replace(old,new,1)

old='''            case OPT_ENTERPRISE: opt_enterprise = 1; opt_enterprise_rl = 1; opt_v6 = 1; break;\n            case OPT_ENTERPRISE_VERBOSE: opt_enterprise = 1; opt_enterprise_rl = 0; opt_v6 = 1; break;\n'''
new='''            case OPT_ENTERPRISE: argos_runtime_enable_enterprise(&runtime_cfg, 0); opt_v6 = 1; break;\n            case OPT_ENTERPRISE_VERBOSE: argos_runtime_enable_enterprise(&runtime_cfg, 1); opt_v6 = 1; break;\n'''
if s.count(old)!=1:
    raise SystemExit(f'enterprise cases anchor count={s.count(old)}')
s=s.replace(old,new,1)

repls={
    r'\bidentity_mode\b':'runtime_cfg.identity_mode',
    r'\bopt_wireguard_port\b':'runtime_cfg.wireguard_port',
    r'\bwireguard_port_explicit\b':'runtime_cfg.wireguard_port_explicit',
    r'\bopt_enterprise_rl\b':'runtime_cfg.enterprise_rate_limited',
    r'\bopt_enterprise\b':'runtime_cfg.enterprise_enabled',
}
for pat,val in repls.items():
    s=re.sub(pat,val,s)

old='''    if (runtime_cfg.wireguard_port_explicit && !runtime_cfg.enterprise_enabled) {\n        fprintf(stderr, "Error: --wireguard-port requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n\n    if (argos_identity_enabled(runtime_cfg.identity_mode) && !runtime_cfg.enterprise_enabled) {\n        fprintf(stderr, "Error: --identity requires --enterprise or --enterprise-verbose.\\n");\n        return 1;\n    }\n'''
new='''    const char *runtime_cfg_error = argos_runtime_config_validate(&runtime_cfg);\n    if (runtime_cfg_error) {\n        fprintf(stderr, "Error: %s\\n", runtime_cfg_error);\n        return 1;\n    }\n'''
if s.count(old)!=1:
    raise SystemExit(f'validation block anchor count={s.count(old)}')
s=s.replace(old,new,1)

for legacy in ('opt_enterprise','opt_enterprise_rl','opt_wireguard_port'):
    if re.search(r'\b'+legacy+r'\b',s):
        raise SystemExit(f'legacy runtime identifier remains: {legacy}')
if re.search(r'(?<!\.)\bwireguard_port_explicit\b',s):
    raise SystemExit('standalone wireguard_port_explicit remains')
if re.search(r'(?<!\.)\bidentity_mode\b',s):
    raise SystemExit('standalone identity_mode remains')

src.write_text(s)

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_config.h"
static void check(int ok,const char *m){if(!ok){fprintf(stderr,"FAIL: %s\n",m);exit(1);}}
int main(void){
 argos_runtime_config_t c;
 argos_runtime_config_init(&c);
 check(!c.enterprise_enabled,"enterprise default off");
 check(c.enterprise_rate_limited==1,"enterprise default quiet");
 check(c.identity_mode==ARGOS_IDENTITY_OFF,"identity default off");
 check(c.wireguard_port==51820U&&!c.wireguard_port_explicit,"wireguard defaults");
 check(argos_runtime_config_validate(&c)==NULL,"default config valid");
 c.identity_mode=ARGOS_IDENTITY_HASH;
 check(argos_runtime_config_validate(&c)!=NULL,"identity requires enterprise");
 argos_runtime_enable_enterprise(&c,0);
 check(c.enterprise_enabled&&c.enterprise_rate_limited,"quiet enterprise mode");
 check(argos_runtime_config_validate(&c)==NULL,"identity+enterprise valid");
 argos_runtime_enable_enterprise(&c,1);
 check(c.enterprise_enabled&&!c.enterprise_rate_limited,"verbose enterprise mode");
 c.wireguard_port=44444U;c.wireguard_port_explicit=1;
 check(argos_runtime_config_validate(&c)==NULL,"explicit WG with enterprise valid");
 argos_runtime_config_init(&c);c.wireguard_port_explicit=1;
 check(strstr(argos_runtime_config_validate(&c),"wireguard-port")!=NULL,"WG dependency error");
 check(strstr(argos_runtime_config_validate(NULL),"invalid runtime")!=NULL,"NULL validation");
 puts("Runtime config fixtures: PASS");return 0;
}
''')
print('staged enterprise runtime config consolidation')
