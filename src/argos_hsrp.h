#ifndef ARGOS_HSRP_H
#define ARGOS_HSRP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t wire_version;
    uint8_t opcode;
    uint8_t state;
    uint8_t hello_time;
    uint8_t hold_time;
    uint8_t priority;
    uint8_t group;
    uint8_t auth_nonzero;
    char detail[256];
} argos_hsrp1_result_t;

static inline const char *ahsrp_opcode(uint8_t v) {
    return v==0U ? "hello" : v==1U ? "coup" : v==2U ? "resign" : "unknown";
}
static inline const char *ahsrp_state(uint8_t v) {
    switch(v) {
        case 0U: return "initial"; case 1U: return "learn"; case 2U: return "listen";
        case 4U: return "speak"; case 8U: return "standby"; case 16U: return "active";
        default: return "unknown";
    }
}

/* Classic HSRP (commonly called HSRPv1) uses wire Version=0 and a fixed
 * 20-byte UDP/1985 payload. The 8-byte cleartext authentication field and
 * virtual IPv4 address are deliberately not emitted. */
static inline int argos_hsrp1_parse(const unsigned char *p, size_t n,
                                    argos_hsrp1_result_t *r) {
    if (!p || !r || n < 20U) return 0;
    memset(r,0,sizeof(*r));
    if (p[0] != 0U || p[1] > 2U) return 0;
    r->wire_version=p[0]; r->opcode=p[1]; r->state=p[2];
    r->hello_time=p[3]; r->hold_time=p[4]; r->priority=p[5]; r->group=p[6];
    for (size_t i=8U;i<16U;i++) if (p[i] != 0U) { r->auth_nonzero=1U; break; }
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=1;wire_version=0;opcode=%s;state=%s;hello_s=%u;hold_s=%u;priority=%u;group=%u;auth_present=%u",
        ahsrp_opcode(r->opcode), ahsrp_state(r->state), (unsigned)r->hello_time,
        (unsigned)r->hold_time, (unsigned)r->priority, (unsigned)r->group,
        (unsigned)r->auth_nonzero);
    return 1;
}

#endif /* ARGOS_HSRP_H */
