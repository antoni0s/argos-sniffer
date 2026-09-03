#ifndef ARGOS_AIRPLAY_H
#define ARGOS_AIRPLAY_H

/* Argos-Sniffer v6 staging engine: AirPlay.
 * Lightweight HTTP/RTSP-style fingerprint parser for common AirPlay control
 * endpoints and headers. Standalone only; no runtime wiring yet.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

typedef struct {
    int detected;
    char method[24];
    char path[160];
    char server[128];
    char user_agent[128];
    char apple_device_id[64];
    char active_remote[64];
    char detail[512];
} argos_airplay_result_t;

static inline void aair_field(const unsigned char *p, size_t n, const char *name,
                              char *out, size_t cap) {
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
            while (j < n && p[j] != '\r' && p[j] != '\n' && k + 1U < cap) {
                unsigned char c = p[j++];
                out[k++] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
            }
            out[k] = '\0';
            return;
        }
    }
}

static inline int aair_contains(const unsigned char *p, size_t n, const char *s) {
    size_t m = strlen(s);
    if (!p || !s || m == 0U || n < m) return 0;
    for (size_t i = 0U; i + m <= n; ++i) {
        if (memcmp(p + i, s, m) == 0) return 1;
    }
    return 0;
}

static inline int argos_airplay_parse(const unsigned char *p, size_t n,
                                      argos_airplay_result_t *r) {
    if (!p || !r || n < 8U) return 0;
    memset(r, 0, sizeof(*r));

    size_t i = 0U, m = 0U;
    while (i < n && p[i] != ' ' && m + 1U < sizeof(r->method)) {
        unsigned char c = p[i++];
        if (c < 'A' || c > 'Z') break;
        r->method[m++] = (char)c;
    }
    r->method[m] = '\0';

    if (m > 0U && i < n && p[i] == ' ') {
        ++i;
        size_t j = 0U;
        while (i < n && p[i] != ' ' && p[i] != '\r' && p[i] != '\n' && j + 1U < sizeof(r->path)) {
            unsigned char c = p[i++];
            r->path[j++] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
        }
        r->path[j] = '\0';
    }

    aair_field(p, n, "Server", r->server, sizeof(r->server));
    aair_field(p, n, "User-Agent", r->user_agent, sizeof(r->user_agent));
    aair_field(p, n, "X-Apple-Device-ID", r->apple_device_id, sizeof(r->apple_device_id));
    aair_field(p, n, "Active-Remote", r->active_remote, sizeof(r->active_remote));

    if ((r->path[0] && (
            strcmp(r->path, "/server-info") == 0 ||
            strcmp(r->path, "/play") == 0 ||
            strcmp(r->path, "/scrub") == 0 ||
            strcmp(r->path, "/rate") == 0 ||
            strcmp(r->path, "/photo") == 0 ||
            strcmp(r->path, "/stop") == 0)) ||
        aair_contains(p, n, "AirTunes") ||
        aair_contains(p, n, "AirPlay") ||
        aair_contains(p, n, "X-Apple-Device-ID:")) {
        r->detected = 1;
    }

    if (!r->detected) return 0;

    (void)snprintf(r->detail, sizeof(r->detail),
                   "airplay=1%s%s%s%s%s%s%s%s",
                   r->method[0] ? ";method=" : "", r->method,
                   r->path[0] ? ";path=" : "", r->path,
                   r->server[0] ? ";server=" : "", r->server,
                   r->user_agent[0] ? ";ua=" : "", r->user_agent);
    return 1;
}

#endif /* ARGOS_AIRPLAY_H */
