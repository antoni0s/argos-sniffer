#ifndef ARGOS_TELNET_H
#define ARGOS_TELNET_H

/* Argos-Sniffer v6 staging engine: Telnet negotiation fingerprinting.
 * Standalone parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    uint16_t command_count;
    uint16_t option_count;
    int binary;
    int echo;
    int suppress_go_ahead;
    int terminal_type;
    int naws;
    int linemode;
    char detail[320];
} argos_telnet_result_t;

static inline int argos_telnet_parse(const unsigned char *p, size_t n,
                                     argos_telnet_result_t *r) {
    if (!p || !r || n < 2U) return 0;
    memset(r, 0, sizeof(*r));

    size_t i = 0U;
    while (i < n) {
        if (p[i] != 0xffU) { ++i; continue; }
        if (i + 1U >= n) break;

        uint8_t cmd = p[i + 1U];
        if (cmd == 0xffU) { i += 2U; continue; }
        r->seen = 1;
        r->command_count++;

        if ((cmd >= 0xfbU && cmd <= 0xfeU) && i + 2U < n) {
            uint8_t opt = p[i + 2U];
            r->option_count++;
            if (opt == 0U) r->binary = 1;
            else if (opt == 1U) r->echo = 1;
            else if (opt == 3U) r->suppress_go_ahead = 1;
            else if (opt == 24U) r->terminal_type = 1;
            else if (opt == 31U) r->naws = 1;
            else if (opt == 34U) r->linemode = 1;
            i += 3U;
            continue;
        }

        if (cmd == 0xfaU) {
            size_t j = i + 2U;
            if (j < n) {
                uint8_t opt = p[j];
                r->option_count++;
                if (opt == 24U) r->terminal_type = 1;
                else if (opt == 31U) r->naws = 1;
                else if (opt == 34U) r->linemode = 1;
            }
            while (j + 1U < n) {
                if (p[j] == 0xffU && p[j + 1U] == 0xf0U) { j += 2U; break; }
                ++j;
            }
            i = j;
            continue;
        }

        i += 2U;
    }

    if (!r->seen) return 0;
    (void)snprintf(r->detail, sizeof(r->detail),
                   "commands=%u;options=%u;binary=%u;echo=%u;sga=%u;terminal_type=%u;naws=%u;linemode=%u",
                   (unsigned)r->command_count, (unsigned)r->option_count,
                   (unsigned)r->binary, (unsigned)r->echo,
                   (unsigned)r->suppress_go_ahead, (unsigned)r->terminal_type,
                   (unsigned)r->naws, (unsigned)r->linemode);
    return 1;
}

#endif /* ARGOS_TELNET_H */
