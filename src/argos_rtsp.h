#ifndef ARGOS_RTSP_H
#define ARGOS_RTSP_H

/* Argos-Sniffer v6 staging engine: RTSP.
 * Lightweight request/response fingerprint parser only.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

typedef struct {
    int request;
    int response;
    char method[24];
    char uri[192];
    char server[128];
    char user_agent[128];
    char transport[160];
    char detail[640];
} argos_rtsp_result_t;

static inline int artsp_starts(const unsigned char *p, size_t n, const char *s) {
    size_t m = strlen(s);
    return n >= m && memcmp(p, s, m) == 0;
}

static inline void artsp_field(const unsigned char *p, size_t n, const char *name,
                               char *out, size_t cap) {
    if (!p || !name || !out || cap == 0U) return;
    out[0] = '\0';
    size_t name_len = strlen(name);
    for (size_t i = 0U; i + name_len + 1U < n; ++i) {
        if ((i == 0U || p[i-1] == '\n') &&
            strncasecmp((const char *)p + i, name, name_len) == 0 &&
            p[i + name_len] == ':') {
            size_t j = i + name_len + 1U;
            while (j < n && (p[j] == ' ' || p[j] == '\t')) ++j;
            size_t k = 0U;
            while (j < n && p[j] != '\r' && p[j] != '\n' && k + 1U < cap) {
                unsigned char c = p[j++];
                out[k++] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
            }
            out[k] = '\0';
            return;
        }
    }
}

static inline int argos_rtsp_parse(const unsigned char *p, size_t n,
                                   argos_rtsp_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));

    if (artsp_starts(p, n, "RTSP/1.0 ")) {
        r->response = 1;
    } else {
        size_t i = 0U, m = 0U;
        while (i < n && p[i] != ' ' && m + 1U < sizeof(r->method)) {
            unsigned char c = p[i++];
            if (c < 'A' || c > 'Z') return 0;
            r->method[m++] = (char)c;
        }
        if (i >= n || p[i] != ' ' || m == 0U) return 0;
        r->method[m] = '\0';
        ++i;
        size_t u = 0U;
        while (i < n && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && u + 1U < sizeof(r->uri)) {
            unsigned char c = p[i++];
            r->uri[u++] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
        }
        r->uri[u] = '\0';
        if (i + 9U > n || memcmp(p + i, " RTSP/1.0", 9U) != 0) return 0;
        r->request = 1;
    }

    artsp_field(p, n, "Server", r->server, sizeof(r->server));
    artsp_field(p, n, "User-Agent", r->user_agent, sizeof(r->user_agent));
    artsp_field(p, n, "Transport", r->transport, sizeof(r->transport));

    (void)snprintf(r->detail, sizeof(r->detail),
                   "kind=%s%s%s%s%s%s%s%s%s",
                   r->request ? "request" : "response",
                   r->method[0] ? ";method=" : "", r->method,
                   r->uri[0] ? ";uri=" : "", r->uri,
                   r->server[0] ? ";server=" : "", r->server,
                   r->user_agent[0] ? ";ua=" : "", r->user_agent);
    return 1;
}

#endif /* ARGOS_RTSP_H */
