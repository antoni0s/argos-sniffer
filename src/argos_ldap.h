#ifndef ARGOS_LDAP_H
#define ARGOS_LDAP_H

/* Argos-Sniffer v6 staging engine: LDAP.
 * Standalone BER/LDAP message fingerprinting only; not wired into runtime.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    uint32_t message_id;
    uint8_t protocol_op;
    char op_name[28];
    char detail[192];
} argos_ldap_result_t;

static inline int ald_len(const unsigned char *p, size_t n, size_t *used, size_t *len) {
    if (!p || n < 1U || !used || !len) return 0;
    if ((p[0] & 0x80U) == 0U) { *used=1U; *len=p[0]; return 1; }
    unsigned k=p[0]&0x7fU;
    if (k==0U || k>4U || n<1U+k) return 0;
    size_t v=0U;
    for (unsigned i=0;i<k;++i) v=(v<<8)|p[1U+i];
    *used=1U+k; *len=v; return 1;
}

static inline const char *ald_op(uint8_t t) {
    switch (t) {
        case 0x60U: return "bindRequest";
        case 0x61U: return "bindResponse";
        case 0x42U: return "unbindRequest";
        case 0x63U: return "searchRequest";
        case 0x64U: return "searchResultEntry";
        case 0x65U: return "searchResultDone";
        case 0x66U: return "modifyRequest";
        case 0x67U: return "modifyResponse";
        case 0x68U: return "addRequest";
        case 0x69U: return "addResponse";
        case 0x4aU: return "delRequest";
        case 0x6bU: return "delResponse";
        case 0x6cU: return "modifyDNRequest";
        case 0x6dU: return "modifyDNResponse";
        case 0x6eU: return "compareRequest";
        case 0x6fU: return "compareResponse";
        case 0x73U: return "searchResultReference";
        case 0x77U: return "extendedRequest";
        case 0x78U: return "extendedResponse";
        case 0x79U: return "intermediateResponse";
        default: return "unknown";
    }
}

static inline int argos_ldap_parse(const unsigned char *p, size_t n,
                                   argos_ldap_result_t *r) {
    if (!p || !r || n < 7U) return 0;
    memset(r,0,sizeof(*r));
    if (p[0] != 0x30U) return 0;

    size_t u=0U,l=0U;
    if (!ald_len(p+1,n-1,&u,&l)) return 0;
    size_t pos=1U+u;
    if (l > n-pos || pos>=n || p[pos] != 0x02U) return 0;
    ++pos;
    size_t iu=0U,il=0U;
    if (!ald_len(p+pos,n-pos,&iu,&il) || il==0U || il>4U) return 0;
    pos += iu;
    if (pos+il > n) return 0;
    uint32_t id=0U;
    for (size_t i=0;i<il;++i) id=(id<<8)|p[pos+i];
    pos += il;
    if (pos>=n) return 0;

    r->message_id=id;
    r->protocol_op=p[pos];
    const char *name=ald_op(r->protocol_op);
    if (!strcmp(name,"unknown")) return 0;
    r->seen=1;
    (void)snprintf(r->op_name,sizeof(r->op_name),"%s",name);
    (void)snprintf(r->detail,sizeof(r->detail),"message_id=%u;op=0x%02x(%s)",
                   (unsigned)r->message_id,(unsigned)r->protocol_op,r->op_name);
    return 1;
}

#endif /* ARGOS_LDAP_H */
