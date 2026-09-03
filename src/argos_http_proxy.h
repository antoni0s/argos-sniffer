#ifndef ARGOS_HTTP_PROXY_H
#define ARGOS_HTTP_PROXY_H

/* Argos-Sniffer v6 staging engine: HTTP proxy detection.
 * Standalone parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int is_connect;
    int have_absolute_uri;
    int have_proxy_auth;
    int have_via;
    int have_forwarded;
    int have_x_forwarded_for;
    char method[16];
    char host[256];
    char via[192];
    char detail[640];
} argos_http_proxy_result_t;

static inline int ahp_ci_prefix(const char *s, const char *pfx) {
    while (*pfx) {
        char a = *s++, b = *pfx++;
        if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
        if (a != b) return 0;
    }
    return 1;
}

static inline void ahp_copy_token(const char *s, size_t n, char *out, size_t cap) {
    if (!out || cap == 0U) return;
    size_t k = n < cap - 1U ? n : cap - 1U;
    memcpy(out, s, k);
    out[k] = '\0';
}

static inline int argos_http_proxy_parse(const unsigned char *p, size_t n,
                                         argos_http_proxy_result_t *r) {
    if (!p || !r || n < 4U) return 0;
    memset(r, 0, sizeof(*r));

    size_t lim = n < 4096U ? n : 4096U;
    char buf[4097];
    memcpy(buf, p, lim);
    buf[lim] = '\0';

    char *line = buf;
    char *eol = strstr(line, "\r\n");
    if (!eol) return 0;
    *eol = '\0';

    char *sp1 = strchr(line, ' ');
    if (!sp1) return 0;
    ahp_copy_token(line, (size_t)(sp1 - line), r->method, sizeof(r->method));

    char *target = sp1 + 1;
    char *sp2 = strchr(target, ' ');
    if (!sp2) return 0;
    *sp2 = '\0';

    if (ahp_ci_prefix(r->method, "CONNECT") && r->method[7] == '\0') {
        r->seen = 1;
        r->is_connect = 1;
        ahp_copy_token(target, strlen(target), r->host, sizeof(r->host));
    } else if (ahp_ci_prefix(target, "http://") || ahp_ci_prefix(target, "https://")) {
        r->seen = 1;
        r->have_absolute_uri = 1;
        const char *h = strstr(target, "://");
        h = h ? h + 3 : target;
        const char *end = h;
        while (*end && *end != '/' && *end != '?' && *end != '#') ++end;
        ahp_copy_token(h, (size_t)(end - h), r->host, sizeof(r->host));
    }

    char *cur = eol + 2;
    while (*cur) {
        char *next = strstr(cur, "\r\n");
        if (!next) break;
        if (next == cur) break;
        *next = '\0';

        if (ahp_ci_prefix(cur, "Proxy-Authorization:")) {
            r->seen = 1; r->have_proxy_auth = 1;
        } else if (ahp_ci_prefix(cur, "Via:")) {
            r->seen = 1; r->have_via = 1;
            const char *v = cur + 4;
            while (*v == ' ' || *v == '\t') ++v;
            ahp_copy_token(v, strlen(v), r->via, sizeof(r->via));
        } else if (ahp_ci_prefix(cur, "Forwarded:")) {
            r->seen = 1; r->have_forwarded = 1;
        } else if (ahp_ci_prefix(cur, "X-Forwarded-For:")) {
            r->seen = 1; r->have_x_forwarded_for = 1;
        }
        cur = next + 2;
    }

    if (!r->seen) return 0;

    (void)snprintf(r->detail, sizeof(r->detail),
                   "method=%s;connect=%u;absolute_uri=%u;proxy_auth=%u;via=%u;forwarded=%u;x_forwarded_for=%u%s%s%s%s",
                   r->method[0] ? r->method : "unknown",
                   (unsigned)r->is_connect,
                   (unsigned)r->have_absolute_uri,
                   (unsigned)r->have_proxy_auth,
                   (unsigned)r->have_via,
                   (unsigned)r->have_forwarded,
                   (unsigned)r->have_x_forwarded_for,
                   r->host[0] ? ";host=" : "", r->host,
                   r->via[0] ? ";via=" : "", r->via);
    return 1;
}

#endif /* ARGOS_HTTP_PROXY_H */
