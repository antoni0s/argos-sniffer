#ifndef ARGOS_CONFIG_H
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
