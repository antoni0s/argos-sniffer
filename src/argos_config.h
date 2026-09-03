#ifndef ARGOS_CONFIG_H
#define ARGOS_CONFIG_H

#include <stdint.h>
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
