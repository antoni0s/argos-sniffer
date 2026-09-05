#ifndef ARGOS_L2_H
#define ARGOS_L2_H

/* Argos infrastructure Layer-2 engine.  This module intentionally groups
 * passive switching-control fingerprints that share the same L2 dispatch
 * boundary.  Telemetry, deduplication and capture remain runtime concerns. */

/* ========================================================================== */
/* LLDP-MED                                                                   */
/* ========================================================================== */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int have_capabilities;
    uint16_t capabilities;
    uint8_t device_class;
    int have_policy;
    uint8_t app_type;
    uint8_t policy_unknown;
    uint8_t policy_tagged;
    uint16_t vlan;
    uint8_t priority;
    uint8_t dscp;
    char hardware[64];
    char firmware[64];
    char software[64];
    char manufacturer[96];
    char model[96];
    char detail[768];
} argos_lldp_med_result_t;

static inline uint16_t alm_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t alm_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void alm_text(const unsigned char *p, size_t n, char *out, size_t cap) {
    if (!out || cap == 0U) return;
    size_t take = n < cap - 1U ? n : cap - 1U;
    for (size_t i = 0; i < take; ++i) {
        unsigned char c = p[i];
        out[i] = (char)((c >= 0x21U && c <= 0x7eU && c != '|' && c != ';' &&
                         c != ',' && c != '=') ? c : '_');
    }
    while (take > 0U && out[take - 1U] == '_') --take;
    out[take] = '\0';
}
static inline const char *alm_class(uint8_t v) {
    switch (v) {
        case 1: return "endpoint1";
        case 2: return "endpoint2";
        case 3: return "endpoint3";
        case 4: return "network";
        default: return "unknown";
    }
}
static inline const char *alm_app(uint8_t v) {
    switch (v) {
        case 1: return "voice";
        case 2: return "voice-signaling";
        case 3: return "guest-voice";
        case 4: return "guest-voice-signaling";
        case 5: return "softphone-voice";
        case 6: return "video-conferencing";
        case 7: return "streaming-video";
        case 8: return "video-signaling";
        default: return "reserved";
    }
}
static inline void alm_inventory_add(char *out, size_t cap, const char *key, const char *value) {
    if (!out || !key || !value || !value[0] || cap == 0U) return;
    size_t used = strlen(out);
    if (used >= cap - 1U) return;
    (void)snprintf(out + used, cap - used, "%s%s:%s", used ? "," : "", key, value);
}

/* ANSI/TIA-1057 LLDP-MED organizational TLVs use OUI 00-12-BB. Location
 * Identification (subtype 3) is deliberately ignored: Argos fingerprints
 * equipment and policy, not physical/civic location. Power TLV subtype 4 is
 * likewise left for a later PoE-specific vector. */
static inline int argos_lldp_med_parse(const unsigned char *p, size_t n,
                                       argos_lldp_med_result_t *r) {
    if (!p || !r) return 0;
    memset(r, 0, sizeof(*r));
    size_t pos = 0U;
    while (pos + 2U <= n) {
        uint16_t h = alm_be16(p + pos); pos += 2U;
        unsigned type = h >> 9;
        size_t len = h & 0x01ffU;
        if (type == 0U) break;
        if (len > n - pos) return 0;
        if (type == 127U && len >= 4U &&
            p[pos] == 0x00U && p[pos + 1U] == 0x12U && p[pos + 2U] == 0xbbU) {
            uint8_t subtype = p[pos + 3U];
            const unsigned char *v = p + pos + 4U;
            size_t vlen = len - 4U;
            if (subtype == 1U && vlen >= 3U) {
                r->seen = 1; r->have_capabilities = 1;
                r->capabilities = alm_be16(v);
                r->device_class = v[2];
            } else if (subtype == 2U && vlen == 4U && !r->have_policy) {
                uint32_t w = alm_be32(v);
                r->seen = 1; r->have_policy = 1;
                r->app_type = (uint8_t)(w >> 24);
                r->policy_unknown = (uint8_t)((w >> 23) & 1U);
                r->policy_tagged = (uint8_t)((w >> 22) & 1U);
                r->vlan = (uint16_t)((w >> 9) & 0x0fffU);
                r->priority = (uint8_t)((w >> 6) & 0x07U);
                r->dscp = (uint8_t)(w & 0x3fU);
            } else if ((subtype == 5U || subtype == 6U || subtype == 7U ||
                        subtype == 9U || subtype == 10U) && vlen > 0U) {
                r->seen = 1;
                char *dst = subtype == 5U ? r->hardware : subtype == 6U ? r->firmware :
                            subtype == 7U ? r->software :
                            subtype == 9U ? r->manufacturer : r->model;
                size_t cap = subtype == 9U || subtype == 10U ? 96U : 64U;
                if (!dst[0]) alm_text(v, vlen, dst, cap);
            }
        }
        pos += len;
    }
    if (!r->seen) return 0;

    char capabilities[16] = "-", vlan[16] = "-", priority[16] = "-", dscp[16] = "-";
    const char *device_class = "-", *network_policy = "-", *application = "-";
    if (r->have_capabilities) {
        device_class = alm_class(r->device_class);
        (void)snprintf(capabilities, sizeof(capabilities), "0x%04x", (unsigned)r->capabilities);
    }
    if (r->have_policy) {
        network_policy = r->policy_unknown ?
            (r->policy_tagged ? "unknown-tagged" : "unknown-untagged") :
            (r->policy_tagged ? "defined-tagged" : "defined-untagged");
        application = alm_app(r->app_type);
        (void)snprintf(vlan, sizeof(vlan), "%u", (unsigned)r->vlan);
        (void)snprintf(priority, sizeof(priority), "%u", (unsigned)r->priority);
        (void)snprintf(dscp, sizeof(dscp), "%u", (unsigned)r->dscp);
    }
    char inventory[512] = "";
    alm_inventory_add(inventory, sizeof(inventory), "manufacturer", r->manufacturer);
    alm_inventory_add(inventory, sizeof(inventory), "model", r->model);
    alm_inventory_add(inventory, sizeof(inventory), "hardware", r->hardware);
    alm_inventory_add(inventory, sizeof(inventory), "firmware", r->firmware);
    alm_inventory_add(inventory, sizeof(inventory), "software", r->software);
    (void)snprintf(r->detail, sizeof(r->detail),
        "device_class=%s capabilities=%s network_policy=%s application=%s "
        "vlan=%s priority=%s dscp=%s inventory=%s",
        device_class, capabilities, network_policy, application, vlan, priority, dscp,
        inventory[0] ? inventory : "-");
    return 1;
}

/* ========================================================================== */
/* LACP                                                                       */
/* ========================================================================== */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t version;
    uint16_t actor_system_priority;
    unsigned char actor_system[6];
    uint16_t actor_key;
    uint16_t actor_port_priority;
    uint16_t actor_port;
    uint8_t actor_state;
    uint16_t partner_system_priority;
    unsigned char partner_system[6];
    uint16_t partner_key;
    uint16_t partner_port_priority;
    uint16_t partner_port;
    uint8_t partner_state;
    char detail[512];
} argos_lacp_result_t;

static inline uint16_t alacp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline void alacp_mac(char out[18], const unsigned char mac[6]) {
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* IEEE 802.1AX LACPDU on Slow Protocols EtherType 0x8809.
 * Payload begins with Subtype=1, Version, Actor TLV(type=1,len=20), then
 * Partner TLV(type=2,len=20). Only fixed control-plane identity/state is kept. */
static inline int argos_lacp_parse(const unsigned char *p, size_t n,
                                   argos_lacp_result_t *r) {
    if (!p || !r || n < 42U) return 0;
    memset(r, 0, sizeof(*r));
    if (p[0] != 0x01U || (p[1] != 0x01U && p[1] != 0x02U)) return 0;
    if (p[2] != 0x01U || p[3] != 0x14U) return 0;
    if (p[22] != 0x02U || p[23] != 0x14U) return 0;

    r->version = p[1];
    r->actor_system_priority = alacp_be16(p + 4);
    memcpy(r->actor_system, p + 6, 6);
    r->actor_key = alacp_be16(p + 12);
    r->actor_port_priority = alacp_be16(p + 14);
    r->actor_port = alacp_be16(p + 16);
    r->actor_state = p[18];

    r->partner_system_priority = alacp_be16(p + 24);
    memcpy(r->partner_system, p + 26, 6);
    r->partner_key = alacp_be16(p + 32);
    r->partner_port_priority = alacp_be16(p + 34);
    r->partner_port = alacp_be16(p + 36);
    r->partner_state = p[38];

    char amac[18], pmac[18];
    alacp_mac(amac, r->actor_system);
    alacp_mac(pmac, r->partner_system);
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=%u actor_system=%s actor_priority=%u actor_key=%u actor_port=%u "
        "actor_state=0x%02x partner_system=%s partner_priority=%u partner_key=%u "
        "partner_port=%u partner_state=0x%02x",
        (unsigned)r->version, amac, (unsigned)r->actor_system_priority,
        (unsigned)r->actor_key, (unsigned)r->actor_port, (unsigned)r->actor_state,
        pmac, (unsigned)r->partner_system_priority, (unsigned)r->partner_key,
        (unsigned)r->partner_port, (unsigned)r->partner_state);
    return 1;
}

/* ========================================================================== */
/* STP / RSTP / MSTP                                                          */
/* ========================================================================== */
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
        (void)snprintf(r->detail, sizeof(r->detail),
            "type=tcn version=0 flags=- root_id=- root_cost=- bridge_id=- port_id=- "
            "message_age=- max_age=- hello_time=- forward_delay=- mst_revision=- mst_digest=-");
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
        "type=config version=0 flags=0x%02x root_id=%04x.%s root_cost=%u "
        "bridge_id=%04x.%s port_id=0x%04x message_age=%u max_age=%u "
        "hello_time=%u forward_delay=%u mst_revision=- mst_digest=-",
        (unsigned)r->flags, (unsigned)r->root_priority, root, (unsigned)r->root_cost,
        (unsigned)r->bridge_priority, bridge, (unsigned)r->port_id,
        (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
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
        "type=rstp version=2 flags=0x%02x root_id=%04x.%s root_cost=%u "
        "bridge_id=%04x.%s port_id=0x%04x message_age=%u max_age=%u "
        "hello_time=%u forward_delay=%u mst_revision=- mst_digest=-",
        (unsigned)r->flags, (unsigned)r->root_priority, root, (unsigned)r->root_cost,
        (unsigned)r->bridge_priority, bridge, (unsigned)r->port_id,
        (unsigned)r->message_age, (unsigned)r->max_age,
        (unsigned)r->hello_time, (unsigned)r->forward_delay);
    return 1;
}

typedef struct {
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
    r->flags=p[7]; r->root_priority=astp_be16(p+8); memcpy(r->root_mac,p+10,6);
    r->root_cost=astp_be32(p+16); r->bridge_priority=astp_be16(p+20);
    memcpy(r->bridge_mac,p+22,6); r->port_id=astp_be16(p+28);
    r->message_age=astp_be16(p+30); r->max_age=astp_be16(p+32);
    r->hello_time=astp_be16(p+34); r->forward_delay=astp_be16(p+36);
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

    char dig[33], root[18], bridge[18];
    amstp_digest_hex(dig,r->config_digest); astp_mac(root,r->root_mac);
    astp_mac(bridge,r->bridge_mac);
    (void)snprintf(r->detail,sizeof(r->detail),
        "type=mstp version=3 flags=0x%02x root_id=%04x.%s root_cost=%u "
        "bridge_id=%04x.%s port_id=0x%04x message_age=%u max_age=%u "
        "hello_time=%u forward_delay=%u mst_revision=%u mst_digest=%s",
        (unsigned)r->flags,(unsigned)r->root_priority,root,(unsigned)r->root_cost,
        (unsigned)r->bridge_priority,bridge,(unsigned)r->port_id,
        (unsigned)r->message_age,(unsigned)r->max_age,(unsigned)r->hello_time,
        (unsigned)r->forward_delay,(unsigned)r->config_revision,dig);
    return 1;
}

#endif /* ARGOS_L2_H */
