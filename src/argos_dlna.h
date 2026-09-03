#ifndef ARGOS_DLNA_H
#define ARGOS_DLNA_H

/* Argos-Sniffer v6 staging engine: DLNA / UPnP AV.
 * Lightweight HTTP/SSDP payload fingerprinting for common DLNA markers.
 * Standalone only; no runtime wiring yet.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

typedef struct {
    int detected;
    int dlna_header;
    int upnp_av;
    char server[128];
    char user_agent[128];
    char detail[384];
} argos_dlna_result_t;

static inline int adlna_contains(const unsigned char *p, size_t n,
                                 const char *s) {
    size_t m = strlen(s);
    if (!p || !s || m == 0U || n < m) return 0;
    for (size_t i = 0U; i + m <= n; ++i) {
        if (memcmp(p + i, s, m) == 0) return 1;
    }
    return 0;
}

static inline void adlna_field(const unsigned char *p, size_t n,
                               const char *name, char *out, size_t cap) {
    if (!p || !name || !out || cap == 0U) return;
    out[0] = '\0';

    size_t name_len = strlen(name);
    for (size_t i = 0U; i + name_len + 1U < n; ++i) {
        if ((i == 0U || p[i - 1U] == '\n') &&
            strncasecmp((const char *)p + i, name, name_len) == 0 &&
            p[i + name_len] == ':') {
            size_t j = i + name_len + 1U;
            while (j < n && (p[j] == ' ' || p[j] == '\t')) ++j;

            size_t k = 0U;
            while (j < n && p[j] != '\r' && p[j] != '\n' &&
                   k + 1U < cap) {
                unsigned char c = p[j++];
                out[k++] = (char)((c >= 0x20U && c <= 0x7eU &&
                                   c != '|' && c != ';') ? c : ' ');
            }
            out[k] = '\0';
            return;
        }
    }
}

static inline int argos_dlna_parse(const unsigned char *p, size_t n,
                                   argos_dlna_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));

    if (adlna_contains(p, n, "transferMode.dlna.org") ||
        adlna_contains(p, n, "contentFeatures.dlna.org") ||
        adlna_contains(p, n, "getcontentFeatures.dlna.org") ||
        adlna_contains(p, n, "DLNA.ORG_")) {
        r->dlna_header = 1;
    }

    if (adlna_contains(p, n, "urn:schemas-upnp-org:device:MediaServer") ||
        adlna_contains(p, n, "urn:schemas-upnp-org:device:MediaRenderer") ||
        adlna_contains(p, n, "urn:schemas-upnp-org:service:ContentDirectory") ||
        adlna_contains(p, n, "urn:schemas-upnp-org:service:AVTransport") ||
        adlna_contains(p, n, "urn:schemas-upnp-org:service:RenderingControl")) {
        r->upnp_av = 1;
    }

    adlna_field(p, n, "Server", r->server, sizeof(r->server));
    adlna_field(p, n, "User-Agent", r->user_agent, sizeof(r->user_agent));

    r->detected = r->dlna_header || r->upnp_av;
    if (!r->detected) return 0;

    (void)snprintf(r->detail, sizeof(r->detail),
                   "dlna=1;headers=%u;upnp_av=%u%s%s%s%s",
                   (unsigned)r->dlna_header,
                   (unsigned)r->upnp_av,
                   r->server[0] ? ";server=" : "",
                   r->server[0] ? r->server : "",
                   r->user_agent[0] ? ";ua=" : "",
                   r->user_agent[0] ? r->user_agent : "");
    return 1;
}

#endif /* ARGOS_DLNA_H */
