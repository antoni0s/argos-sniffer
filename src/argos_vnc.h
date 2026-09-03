#ifndef ARGOS_VNC_H
#define ARGOS_VNC_H

/* Argos-Sniffer v6 staging engine: VNC / RFB fingerprinting.
 * Standalone parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int have_banner;
    int have_security_types;
    int have_server_name;
    unsigned major;
    unsigned minor;
    uint8_t security_count;
    uint8_t security_types[16];
    char server_name[128];
    char detail[384];
} argos_vnc_result_t;

static inline uint32_t avnc_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline int avnc_digit(unsigned char c) {
    return c >= '0' && c <= '9';
}

static inline int argos_vnc_parse(const unsigned char *p, size_t n,
                                  argos_vnc_result_t *r) {
    if (!p || !r) return 0;
    memset(r, 0, sizeof(*r));

    if (n >= 12U && memcmp(p, "RFB ", 4) == 0 &&
        avnc_digit(p[4]) && avnc_digit(p[5]) && avnc_digit(p[6]) &&
        p[7] == '.' && avnc_digit(p[8]) && avnc_digit(p[9]) && avnc_digit(p[10]) &&
        p[11] == '\n') {
        r->seen = 1;
        r->have_banner = 1;
        r->major = (unsigned)(p[4]-'0')*100U + (unsigned)(p[5]-'0')*10U + (unsigned)(p[6]-'0');
        r->minor = (unsigned)(p[8]-'0')*100U + (unsigned)(p[9]-'0')*10U + (unsigned)(p[10]-'0');
    }

    /* RFB 3.7/3.8 server security-types message: count byte followed by list. */
    if (n >= 2U && p[0] > 0U && p[0] <= 16U && (size_t)p[0] + 1U <= n) {
        r->seen = 1;
        r->have_security_types = 1;
        r->security_count = p[0];
        memcpy(r->security_types, p + 1, r->security_count);
    }

    /* ServerInit tail: width(2), height(2), pixel-format(16), name-length(4), name. */
    if (n >= 24U) {
        uint32_t name_len = avnc_be32(p + 20);
        if (name_len > 0U && name_len <= 127U && 24U + (size_t)name_len <= n) {
            r->seen = 1;
            r->have_server_name = 1;
            size_t k = name_len;
            for (size_t i = 0U; i < k; ++i) {
                unsigned char c = p[24U + i];
                r->server_name[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
            }
            r->server_name[k] = '\0';
        }
    }

    if (!r->seen) return 0;

    char sec[96];
    size_t used = 0U;
    sec[0] = '\0';
    for (uint8_t i = 0U; i < r->security_count && used + 5U < sizeof(sec); ++i) {
        int w = snprintf(sec + used, sizeof(sec) - used, "%s%u", i ? "," : "", (unsigned)r->security_types[i]);
        if (w < 0) break;
        used += (size_t)w < sizeof(sec) - used ? (size_t)w : sizeof(sec) - used - 1U;
    }

    (void)snprintf(r->detail, sizeof(r->detail),
                   "banner=%u;version=%u.%u;security_types=%s%s%s",
                   (unsigned)r->have_banner, r->major, r->minor,
                   r->have_security_types ? sec : "none",
                   r->server_name[0] ? ";server_name=" : "", r->server_name);
    return 1;
}

#endif /* ARGOS_VNC_H */
