#ifndef ARGOS_LPD_H
#define ARGOS_LPD_H

/* Argos-Sniffer v6 staging engine: LPD / RFC 1179.
 * Standalone parser only; no runtime wiring yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t command;
    char queue[96];
    char detail[192];
} argos_lpd_result_t;

static inline int argos_lpd_parse(const unsigned char *p, size_t n,
                                  argos_lpd_result_t *r) {
    if (!p || !r || n < 2U) return 0;
    memset(r, 0, sizeof(*r));

    if (p[0] < 0x01U || p[0] > 0x05U) return 0;
    r->command = p[0];

    size_t i = 1U, j = 0U;
    while (i < n && p[i] != '\n' && p[i] != '\r' && j + 1U < sizeof(r->queue)) {
        unsigned char c = p[i++];
        r->queue[j++] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
    }
    r->queue[j] = '\0';

    const char *name =
        r->command == 0x01U ? "restart" :
        r->command == 0x02U ? "receive-job" :
        r->command == 0x03U ? "short-queue" :
        r->command == 0x04U ? "long-queue" : "remove-jobs";

    (void)snprintf(r->detail, sizeof(r->detail), "cmd=%s;queue=%s",
                   name, r->queue[0] ? r->queue : "unknown");
    return 1;
}

#endif /* ARGOS_LPD_H */
