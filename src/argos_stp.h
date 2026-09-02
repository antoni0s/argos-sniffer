#ifndef ARGOS_STP_H
#define ARGOS_STP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint8_t type;
    uint8_t flags;
    uint16_t root_priority;
    unsigned char root_mac[6];
    uint32_t root_cost;
    uint16_t bridge_priority;
    unsigned char bridge_mac[6];
    uint16_t port_id;
    uint16_t message_age;
    uint16_t max_age;
    uint16_t hello_time;
    uint16_t forward_delay;
    char detail[512];
} argos_stp_result_t;

static inline uint16_t astp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t astp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void astp_mac(char out[18], const unsigned char mac[6]) {
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Classic IEEE 802.1D BPDU over 802.3 LLC: DSAP=0x42, SSAP=0x42, UI=0x03.
 * Version 0 is intentionally handled here; RSTP/MSTP are separate gates. */
static inline int argos_stp_parse(const unsigned char *p, size_t n,
                                  argos_stp_result_t *r) {
    if (!p || !r || n < 7U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x42U || p[1] != 0x42U || p[2] != 0x03U) return 0;
    if (p[3] != 0x00U || p[4] != 0x00U) return 0; /* protocol id */
    r->version = p[5];
    r->type = p[6];
    if (r->version != 0U) return 0;

    if (r->type == 0x80U) {
        (void)snprintf(r->detail, sizeof(r->detail), "version=0;type=tcn");
        return 1;
    }
    if (r->type != 0x00U || n < 38U) return 0;

    r->flags = p[7];
    r->root_priority = astp_be16(p + 8);
    memcpy(r->root_mac, p + 10, 6);
    r->root_cost = astp_be32(p + 16);
    r->bridge_priority = astp_be16(p + 20);
    memcpy(r->bridge_mac, p + 22, 6);
    r->port_id = astp_be16(p + 28);
    r->message_age = astp_be16(p + 30);
    r->max_age = astp_be16(p + 32);
    r->hello_time = astp_be16(p + 34);
    r->forward_delay = astp_be16(p + 36);

    char root[18], bridge[18];
    astp_mac(root, r->root_mac);
    astp_mac(bridge, r->bridge_mac);
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=0;type=config;flags=0x%02x;root_prio=%u;root=%s;cost=%u;"
        "bridge_prio=%u;bridge=%s;port=0x%04x;age=%u;max=%u;hello=%u;fwd=%u",
        (unsigned)r->flags, (unsigned)r->root_priority, root, (unsigned)r->root_cost,
        (unsigned)r->bridge_priority, bridge, (unsigned)r->port_id,
        (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
}

static inline const char *arstp_role(uint8_t flags) {
    switch ((flags >> 2) & 0x03U) {
        case 1U: return "alternate-backup";
        case 2U: return "root";
        case 3U: return "designated";
        default: return "unknown";
    }
}

/* IEEE 802.1w RSTP BPDU: version 2, type 0x02, same common bridge fields
 * as configuration BPDUs plus Version 1 Length (normally zero). */
static inline int argos_rstp_parse(const unsigned char *p, size_t n,
                                   argos_stp_result_t *r) {
    if (!p || !r || n < 39U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x42U || p[1] != 0x42U || p[2] != 0x03U) return 0;
    if (p[3] != 0x00U || p[4] != 0x00U || p[5] != 0x02U || p[6] != 0x02U) return 0;
    if (p[38] != 0x00U) return 0;
    r->version=2U; r->type=0x02U; r->flags=p[7];
    r->root_priority=astp_be16(p+8); memcpy(r->root_mac,p+10,6);
    r->root_cost=astp_be32(p+16);
    r->bridge_priority=astp_be16(p+20); memcpy(r->bridge_mac,p+22,6);
    r->port_id=astp_be16(p+28);
    r->message_age=astp_be16(p+30); r->max_age=astp_be16(p+32);
    r->hello_time=astp_be16(p+34); r->forward_delay=astp_be16(p+36);
    char root[18], bridge[18]; astp_mac(root,r->root_mac); astp_mac(bridge,r->bridge_mac);
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=2;type=rstp;flags=0x%02x;role=%s;proposal=%u;learning=%u;forwarding=%u;agreement=%u;"
        "root_prio=%u;root=%s;cost=%u;bridge_prio=%u;bridge=%s;port=0x%04x;age=%u;max=%u;hello=%u;fwd=%u",
        (unsigned)r->flags, arstp_role(r->flags), (unsigned)((r->flags>>1)&1U),
        (unsigned)((r->flags>>4)&1U), (unsigned)((r->flags>>5)&1U), (unsigned)((r->flags>>6)&1U),
        (unsigned)r->root_priority, root, (unsigned)r->root_cost, (unsigned)r->bridge_priority,
        bridge, (unsigned)r->port_id, (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
}

typedef struct {
    uint16_t version3_length;
    uint16_t config_revision;
    unsigned char config_digest[16];
    uint32_t cist_internal_root_cost;
    uint16_t cist_bridge_priority;
    unsigned char cist_bridge_mac[6];
    uint8_t cist_remaining_hops;
    uint16_t msti_count;
    uint8_t first_msti_flags;
    uint16_t first_msti_root_priority;
    unsigned char first_msti_root_mac[6];
    uint32_t first_msti_root_cost;
    uint8_t first_msti_bridge_priority;
    uint8_t first_msti_port_priority;
    uint8_t first_msti_remaining_hops;
    char detail[640];
} argos_mstp_result_t;

static inline void amstp_digest_hex(char out[33], const unsigned char d[16]) {
    static const char hex[]="0123456789abcdef";
    for (size_t i=0;i<16U;i++) { out[i*2U]=hex[d[i]>>4]; out[i*2U+1U]=hex[d[i]&0x0fU]; }
    out[32]='\0';
}

/* IEEE 802.1s/802.1Q MSTP: version 3, type 0x02. Privacy note: the raw
 * 32-byte MST configuration name is intentionally not emitted. The revision
 * and standardized 16-byte configuration digest identify the region without
 * leaking an internal site/organization label. */
static inline int argos_mstp_parse(const unsigned char *p, size_t n,
                                   argos_mstp_result_t *r) {
    if (!p || !r || n < 105U) return 0;
    memset(r,0,sizeof(*r));
    if (p[0]!=0x42U || p[1]!=0x42U || p[2]!=0x03U) return 0;
    if (p[3]!=0x00U || p[4]!=0x00U || p[5]!=0x03U || p[6]!=0x02U) return 0;
    if (p[38]!=0x00U) return 0;
    r->version3_length=astp_be16(p+39);
    if (r->version3_length < 64U) return 0;
    if ((size_t)r->version3_length > n-41U) return 0;
    if (((r->version3_length-64U) % 16U) != 0U) return 0;
    if (p[41] != 0x00U) return 0; /* MST config format selector */
    r->config_revision=astp_be16(p+74);
    memcpy(r->config_digest,p+76,16);
    r->cist_internal_root_cost=astp_be32(p+92);
    r->cist_bridge_priority=astp_be16(p+96);
    memcpy(r->cist_bridge_mac,p+98,6);
    r->cist_remaining_hops=p[104];
    r->msti_count=(uint16_t)((r->version3_length-64U)/16U);

    if (r->msti_count>0U) {
        const unsigned char *m=p+105;
        r->first_msti_flags=m[0];
        r->first_msti_root_priority=astp_be16(m+1);
        memcpy(r->first_msti_root_mac,m+3,6);
        r->first_msti_root_cost=astp_be32(m+9);
        r->first_msti_bridge_priority=m[13];
        r->first_msti_port_priority=m[14];
        r->first_msti_remaining_hops=m[15];
    }

    char dig[33], cist[18], mroot[18];
    amstp_digest_hex(dig,r->config_digest); astp_mac(cist,r->cist_bridge_mac);
    if (r->msti_count>0U) astp_mac(mroot,r->first_msti_root_mac); else strcpy(mroot,"none");
    (void)snprintf(r->detail,sizeof(r->detail),
        "version=3;v3len=%u;revision=%u;digest=%s;cist_cost=%u;cist_bridge_prio=%u;cist_bridge=%s;cist_hops=%u;msti_count=%u;"
        "msti1_flags=0x%02x;msti1_root_prio=%u;msti1_root=%s;msti1_cost=%u;msti1_bridge_prio=%u;msti1_port_prio=%u;msti1_hops=%u",
        (unsigned)r->version3_length,(unsigned)r->config_revision,dig,(unsigned)r->cist_internal_root_cost,
        (unsigned)r->cist_bridge_priority,cist,(unsigned)r->cist_remaining_hops,(unsigned)r->msti_count,
        (unsigned)r->first_msti_flags,(unsigned)r->first_msti_root_priority,mroot,(unsigned)r->first_msti_root_cost,
        (unsigned)r->first_msti_bridge_priority,(unsigned)r->first_msti_port_priority,(unsigned)r->first_msti_remaining_hops);
    return 1;
}

#endif /* ARGOS_STP_H */
