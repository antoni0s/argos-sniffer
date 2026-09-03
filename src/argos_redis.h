#ifndef ARGOS_REDIS_H
#define ARGOS_REDIS_H

/* Argos-Sniffer v6 staging engine: Redis RESP.
 * Standalone passive parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    int seen;
    char resp_type[16];
    char command[24];
    char detail[256];
} argos_redis_result_t;

static inline void ard_upper_token(const unsigned char *p, size_t n, char *out, size_t cap) {
    size_t i=0U;
    while (i<n && i+1U<cap && p[i]>0x20U && p[i]<0x7fU) {
        out[i]=(char)toupper((unsigned char)p[i]);
        ++i;
    }
    out[i]='\0';
}

static inline int argos_redis_parse(const unsigned char *p, size_t n,
                                    argos_redis_result_t *r) {
    if (!p || !r || n < 1U) return 0;
    memset(r,0,sizeof(*r));

    switch (p[0]) {
        case '+': (void)snprintf(r->resp_type,sizeof(r->resp_type),"simple"); r->seen=1; break;
        case '-': (void)snprintf(r->resp_type,sizeof(r->resp_type),"error"); r->seen=1; break;
        case ':': (void)snprintf(r->resp_type,sizeof(r->resp_type),"integer"); r->seen=1; break;
        case '$': (void)snprintf(r->resp_type,sizeof(r->resp_type),"bulk"); r->seen=1; break;
        case '*': {
            (void)snprintf(r->resp_type,sizeof(r->resp_type),"array");
            r->seen=1;
            const unsigned char *q = (const unsigned char *)memchr(p,'$',n);
            if (q) {
                const unsigned char *cr = (const unsigned char *)memchr(q,'\n',(size_t)(p+n-q));
                if (cr && cr+1 < p+n) {
                    const unsigned char *cmd = cr+1;
                    size_t rem=(size_t)(p+n-cmd);
                    size_t take=0U;
                    while (take<rem && cmd[take]!='\r' && cmd[take]!='\n' && take<23U) ++take;
                    ard_upper_token(cmd,take,r->command,sizeof(r->command));
                }
            }
            break;
        }
        case '_': (void)snprintf(r->resp_type,sizeof(r->resp_type),"null"); r->seen=1; break;
        case '#': (void)snprintf(r->resp_type,sizeof(r->resp_type),"boolean"); r->seen=1; break;
        case ',': (void)snprintf(r->resp_type,sizeof(r->resp_type),"double"); r->seen=1; break;
        case '(': (void)snprintf(r->resp_type,sizeof(r->resp_type),"bignum"); r->seen=1; break;
        case '!': (void)snprintf(r->resp_type,sizeof(r->resp_type),"blob-error"); r->seen=1; break;
        case '=': (void)snprintf(r->resp_type,sizeof(r->resp_type),"verbatim"); r->seen=1; break;
        case '%': (void)snprintf(r->resp_type,sizeof(r->resp_type),"map"); r->seen=1; break;
        case '~': (void)snprintf(r->resp_type,sizeof(r->resp_type),"set"); r->seen=1; break;
        case '>': (void)snprintf(r->resp_type,sizeof(r->resp_type),"push"); r->seen=1; break;
        default:
            /* Inline command mode. */
            if (isalpha((unsigned char)p[0])) {
                size_t take=0U;
                while (take<n && p[take]!=' ' && p[take]!='\r' && p[take]!='\n' && take<23U) ++take;
                ard_upper_token(p,take,r->command,sizeof(r->command));
                (void)snprintf(r->resp_type,sizeof(r->resp_type),"inline");
                r->seen=1;
            }
            break;
    }

    if (!r->seen) return 0;
    (void)snprintf(r->detail,sizeof(r->detail),"resp=%s;command=%s",r->resp_type,r->command);
    return 1;
}

#endif /* ARGOS_REDIS_H */
