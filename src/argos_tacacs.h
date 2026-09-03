#ifndef ARGOS_TACACS_H
#define ARGOS_TACACS_H

/* Argos-Sniffer v6 staging engine: TACACS+.
 * Standalone passive header parser only; encrypted body is not decoded.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    uint8_t version;
    uint8_t type;
    uint8_t seq_no;
    uint8_t flags;
    uint32_t session_id;
    uint32_t length;
    char type_name[20];
    char detail[256];
} argos_tacacs_result_t;

static inline uint32_t atac_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline const char *atac_type(uint8_t t) {
    switch (t) {
        case 1U: return "authentication";
        case 2U: return "authorization";
        case 3U: return "accounting";
        default: return "unknown";
    }
}

static inline int argos_tacacs_parse(const unsigned char *p, size_t n,
                                     argos_tacacs_result_t *r) {
    if (!p || !r || n < 12U) return 0;
    memset(r,0,sizeof(*r));

    if ((p[0] & 0xf0U) != 0xc0U) return 0;
    if (p[1] < 1U || p[1] > 3U) return 0;

    r->version=p[0];
    r->type=p[1];
    r->seq_no=p[2];
    r->flags=p[3];
    r->session_id=atac_be32(p+4);
    r->length=atac_be32(p+8);
    if ((size_t)r->length > n-12U) return 0;

    r->seen=1;
    (void)snprintf(r->type_name,sizeof(r->type_name),"%s",atac_type(r->type));
    (void)snprintf(r->detail,sizeof(r->detail),
                   "version=0x%02x;type=%s;seq=%u;flags=0x%02x;session=0x%08x;length=%u;unencrypted=%u",
                   (unsigned)r->version,r->type_name,(unsigned)r->seq_no,(unsigned)r->flags,
                   (unsigned)r->session_id,(unsigned)r->length,(unsigned)((r->flags & 0x01U) != 0U));
    return 1;
}

#endif /* ARGOS_TACACS_H */
