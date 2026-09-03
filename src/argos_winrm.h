#ifndef ARGOS_WINRM_H
#define ARGOS_WINRM_H

/* Argos-Sniffer v6 staging engine: WinRM / WS-Management fingerprinting.
 * Standalone parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int is_http;
    int have_wsman;
    int have_soap;
    int have_ntlm;
    int have_negotiate;
    int have_basic;
    char method[16];
    char path[96];
    char detail[320];
} argos_winrm_result_t;

static inline int awr_ci_prefix(const char *s, const char *pfx) {
    while (*pfx) {
        char a = *s++, b = *pfx++;
        if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
        if (a != b) return 0;
    }
    return 1;
}

static inline int awr_ci_contains(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0U) return 1;
    for (const char *p = hay; *p; ++p) {
        size_t i = 0U;
        while (i < nl && p[i]) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
            if (a != b) break;
            ++i;
        }
        if (i == nl) return 1;
    }
    return 0;
}

static inline void awr_copy(const char *s, size_t n, char *out, size_t cap) {
    if (!out || cap == 0U) return;
    size_t k = n < cap - 1U ? n : cap - 1U;
    memcpy(out, s, k);
    out[k] = '\0';
}

static inline int argos_winrm_parse(const unsigned char *p, size_t n,
                                    argos_winrm_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));

    size_t lim = n < 8192U ? n : 8192U;
    char buf[8193];
    memcpy(buf, p, lim);
    buf[lim] = '\0';

    char *eol = strstr(buf, "\r\n");
    if (eol) {
        char saved = *eol;
        *eol = '\0';
        char *sp1 = strchr(buf, ' ');
        if (sp1) {
            char *sp2 = strchr(sp1 + 1, ' ');
            if (sp2 && awr_ci_prefix(sp2 + 1, "HTTP/")) {
                r->is_http = 1;
                awr_copy(buf, (size_t)(sp1 - buf), r->method, sizeof(r->method));
                awr_copy(sp1 + 1, (size_t)(sp2 - (sp1 + 1)), r->path, sizeof(r->path));
                if (strcmp(r->path, "/wsman") == 0 || awr_ci_contains(r->path, "wsman")) {
                    r->seen = 1;
                    r->have_wsman = 1;
                }
            }
        }
        *eol = saved;
    }

    if (awr_ci_contains(buf, "application/soap+xml") ||
        awr_ci_contains(buf, "http://www.w3.org/2003/05/soap-envelope") ||
        awr_ci_contains(buf, "http://schemas.xmlsoap.org/ws/2004/08/addressing") ||
        awr_ci_contains(buf, "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd")) {
        r->seen = 1;
        r->have_soap = 1;
        if (awr_ci_contains(buf, "wsman")) r->have_wsman = 1;
    }

    if (awr_ci_contains(buf, "Authorization: NTLM") ||
        awr_ci_contains(buf, "WWW-Authenticate: NTLM")) {
        r->seen = 1; r->have_ntlm = 1;
    }
    if (awr_ci_contains(buf, "Authorization: Negotiate") ||
        awr_ci_contains(buf, "WWW-Authenticate: Negotiate")) {
        r->seen = 1; r->have_negotiate = 1;
    }
    if (awr_ci_contains(buf, "Authorization: Basic") ||
        awr_ci_contains(buf, "WWW-Authenticate: Basic")) {
        r->seen = 1; r->have_basic = 1;
    }

    if (!r->seen || !r->have_wsman) return 0;

    (void)snprintf(r->detail, sizeof(r->detail),
                   "http=%u;method=%s;path=%s;soap=%u;ntlm=%u;negotiate=%u;basic=%u",
                   (unsigned)r->is_http,
                   r->method[0] ? r->method : "unknown",
                   r->path[0] ? r->path : "unknown",
                   (unsigned)r->have_soap,
                   (unsigned)r->have_ntlm,
                   (unsigned)r->have_negotiate,
                   (unsigned)r->have_basic);
    return 1;
}

#endif /* ARGOS_WINRM_H */
