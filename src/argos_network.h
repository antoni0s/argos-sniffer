#ifndef ARGOS_NETWORK_H
#define ARGOS_NETWORK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef ARGOS_PORTABLE_TEST
#include <strings.h>
#endif
#include <time.h>

#ifndef ARGOS_PORTABLE_TEST
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0x8
#endif
#endif

/* Bounded network-context engine. Packet-path lookups are fixed-probe or
 * fixed-capacity scans; prefix discovery and netlink refresh run outside it. */
#define ARGOS_NETWORK_OWNER4_SLOTS 256U
#define ARGOS_NETWORK_OWNER6_SLOTS 128U
#define ARGOS_NETWORK_OWNER_PROBES 4U
#define ARGOS_NETWORK_OWNER_TTL_SECS 180
#define ARGOS_NETWORK_MAX_PREFIXES 64
#define ARGOS_NETWORK_MAX_INTERFACES 8
#define ARGOS_NETWORK_IFNAME_SIZE 16
#define ARGOS_NETWORK_RIP_MAX_MESSAGE 4096U

/* RIP/RIPng control-plane evidence. Route prefixes and authentication
 * material are deliberately neither retained nor emitted. */
typedef enum {
    ARGOS_NETWORK_RIP_NONE = 0,
    ARGOS_NETWORK_RIP_V1 = 1,
    ARGOS_NETWORK_RIP_V2 = 2,
    ARGOS_NETWORK_RIP_NG = 3
} argos_network_rip_kind_t;

typedef enum {
    ARGOS_NETWORK_RIP_AUTH_NONE = 0,
    ARGOS_NETWORK_RIP_AUTH_SIMPLE = 1,
    ARGOS_NETWORK_RIP_AUTH_MD5 = 2,
    ARGOS_NETWORK_RIP_AUTH_UNKNOWN = 3
} argos_network_rip_auth_t;

typedef struct {
    argos_network_rip_kind_t kind;
    argos_network_rip_auth_t auth;
    uint8_t command;
    uint16_t entry_count;
    uint8_t next_hop_present;
    char detail[128];
} argos_network_rip_result_t;

static inline uint16_t argos_network_rip_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline const char *argos_network_rip_command(uint8_t command) {
    return command == 1U ? "request" : "response";
}

static inline const char *argos_network_rip_auth_name(
    argos_network_rip_auth_t auth)
{
    switch (auth) {
        case ARGOS_NETWORK_RIP_AUTH_NONE: return "none";
        case ARGOS_NETWORK_RIP_AUTH_SIMPLE: return "simple";
        case ARGOS_NETWORK_RIP_AUTH_MD5: return "md5";
        default: return "-";
    }
}

/* RIPv1/RIPv2 payload for UDP/520. Fixed-width entries make the scan linear,
 * allocation-free and capped. Authentication type is the only auth field
 * inspected; password, digest, key identifiers and sequence data stay opaque. */
static inline int argos_network_rip_parse(const unsigned char *p, size_t n,
                                           argos_network_rip_result_t *r) {
    if (!p || !r || n < 4U || n > ARGOS_NETWORK_RIP_MAX_MESSAGE ||
        ((n - 4U) % 20U) != 0U) return 0;
    memset(r, 0, sizeof(*r));
    if ((p[0] != 1U && p[0] != 2U) || (p[1] != 1U && p[1] != 2U) ||
        p[2] != 0U || p[3] != 0U) return 0;

    r->kind = p[1] == 1U ? ARGOS_NETWORK_RIP_V1 : ARGOS_NETWORK_RIP_V2;
    r->command = p[0];
    r->auth = ARGOS_NETWORK_RIP_AUTH_NONE;
    size_t slots = (n - 4U) / 20U;
    for (size_t i = 0; i < slots; ++i) {
        const unsigned char *e = p + 4U + i * 20U;
        uint16_t afi = argos_network_rip_be16(e);
        if (afi == 0xffffU) {
            if (p[1] != 2U) return 0;
            if (i == 0U) {
                uint16_t type = argos_network_rip_be16(e + 2U);
                r->auth = type == 2U ? ARGOS_NETWORK_RIP_AUTH_SIMPLE :
                          type == 3U ? ARGOS_NETWORK_RIP_AUTH_MD5 :
                                       ARGOS_NETWORK_RIP_AUTH_UNKNOWN;
            }
            continue;
        }
        uint32_t metric = ((uint32_t)e[16] << 24) | ((uint32_t)e[17] << 16) |
                          ((uint32_t)e[18] << 8) | (uint32_t)e[19];
        if (metric == 0U || metric > 16U) return 0;
        ++r->entry_count;
        if (p[1] == 2U && afi == 2U &&
            (e[12] != 0U || e[13] != 0U || e[14] != 0U || e[15] != 0U))
            r->next_hop_present = 1U;
    }
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=%u command=%s entries=%u auth=%s next_hop_present=%u",
        (unsigned)p[1], argos_network_rip_command(r->command),
        (unsigned)r->entry_count, argos_network_rip_auth_name(r->auth),
        (unsigned)r->next_hop_present);
    return 1;
}

/* RIPng payload for UDP/521. Metric 0xff identifies a next-hop RTE, which is
 * reported as shape evidence but excluded from the route-entry count. */
static inline int argos_network_ripng_parse(const unsigned char *p, size_t n,
                                             argos_network_rip_result_t *r) {
    if (!p || !r || n < 4U || n > ARGOS_NETWORK_RIP_MAX_MESSAGE ||
        ((n - 4U) % 20U) != 0U) return 0;
    memset(r, 0, sizeof(*r));
    if ((p[0] != 1U && p[0] != 2U) || p[1] != 1U ||
        p[2] != 0U || p[3] != 0U) return 0;

    r->kind = ARGOS_NETWORK_RIP_NG;
    r->command = p[0];
    r->auth = ARGOS_NETWORK_RIP_AUTH_UNKNOWN;
    size_t slots = (n - 4U) / 20U;
    for (size_t i = 0; i < slots; ++i) {
        const unsigned char *e = p + 4U + i * 20U;
        if (e[19] == 0xffU) {
            if (e[16] != 0U || e[17] != 0U || e[18] != 0U) return 0;
            r->next_hop_present = 1U;
            continue;
        }
        if (e[18] > 128U || e[19] == 0U || e[19] > 16U) return 0;
        ++r->entry_count;
    }
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=ng command=%s entries=%u auth=- next_hop_present=%u",
        argos_network_rip_command(r->command), (unsigned)r->entry_count,
        (unsigned)r->next_hop_present);
    return 1;
}

/* IEEE 1588-2008 PTPv2 common-header evidence. Native Ethernet and UDP
 * adapters supply the same bounded message slice; payloads/TLVs stay out. */
typedef struct {
    uint8_t transport_specific, message_type, version, domain_number;
    uint16_t message_length, flags, source_port_number, sequence_id;
    int64_t correction_field;
    unsigned char source_clock_identity[8];
    uint8_t control_field;
    int8_t log_message_interval;
    char detail[512];
} argos_network_ptp_result_t;

static inline uint16_t argos_network_ptp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint64_t argos_network_ptp_be64(const unsigned char *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline const char *argos_network_ptp_message_name(uint8_t type) {
    switch (type) {
        case 0x0U: return "sync"; case 0x1U: return "delay-req";
        case 0x2U: return "pdelay-req"; case 0x3U: return "pdelay-resp";
        case 0x8U: return "follow-up"; case 0x9U: return "delay-resp";
        case 0xaU: return "pdelay-resp-follow-up"; case 0xbU: return "announce";
        case 0xcU: return "signaling"; case 0xdU: return "management";
        default: return "reserved";
    }
}

static inline int argos_network_ptp_parse(const unsigned char *p, size_t n,
                                          argos_network_ptp_result_t *r) {
    if (!p || !r || n < 34U) return 0;
    memset(r, 0, sizeof(*r));
    r->transport_specific = (uint8_t)((p[0] >> 4) & 0x0fU);
    r->message_type = (uint8_t)(p[0] & 0x0fU);
    r->version = (uint8_t)(p[1] & 0x0fU);
    if (r->version != 2U) return 0;
    r->message_length = argos_network_ptp_be16(p + 2);
    if (r->message_length < 34U || r->message_length > n) return 0;
    r->domain_number = p[4]; r->flags = argos_network_ptp_be16(p + 6);
    r->correction_field = (int64_t)argos_network_ptp_be64(p + 8);
    memcpy(r->source_clock_identity, p + 20, 8);
    r->source_port_number = argos_network_ptp_be16(p + 28);
    r->sequence_id = argos_network_ptp_be16(p + 30);
    r->control_field = p[32]; r->log_message_interval = (int8_t)p[33];
    char clock_id[24];
    (void)snprintf(clock_id, sizeof(clock_id),
        "%02x%02x%02x.%02x%02x.%02x%02x%02x",
        p[20], p[21], p[22], p[23], p[24], p[25], p[26], p[27]);
    (void)snprintf(r->detail, sizeof(r->detail),
        "version=2 message=%s domain=%u sequence=%u transport_specific=%u "
        "two_step=%u clock_identity=%s",
        argos_network_ptp_message_name(r->message_type),
        (unsigned)r->domain_number, (unsigned)r->sequence_id,
        (unsigned)r->transport_specific,
        (unsigned)((r->flags & 0x0200U) != 0U), clock_id);
    return 1;
}

/* Cheap router-source admission only, not a transport/parser success result.
 * Caller supplies the normalized IP L4 span (never capture padding), behind
 * Ethernet/router-MAC and is_ip gates. Later dispatch still validates framing
 * and drops nonfirst fragments. No state access or allocation here. */
static inline int argos_network_router_exception(uint8_t protocol,
                                                  const unsigned char *l4,
                                                  int available, int source_side) {
    if (protocol == 17U)
        return available >= 8 && l4[0] == 0U && l4[1] == 53U;
    /* Forwarded SYNACK may reach client RTT correlation, never the legacy
     * router-source SYNACK emitter. Keep the existing minimum header gate. */
    return !source_side && protocol == 6U && available >= 20 &&
           (l4[13] & 0x12U) == 0x12U;
}

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    time_t last_seen;
    uint8_t valid;
} argos_network_owner4_entry_t;

typedef struct {
    struct in6_addr ip;
    uint8_t mac[6];
    time_t last_seen;
    uint8_t valid;
} argos_network_owner6_entry_t;

typedef struct {
    int family;
    int ifindex;
    uint32_t v4, v4mask;
    struct in6_addr v6, v6mask;
} argos_network_prefix_t;

typedef struct {
    int ifindex;
    char name[ARGOS_NETWORK_IFNAME_SIZE];
} argos_network_iface_t;

typedef struct {
    argos_network_owner4_entry_t *owner4;
    argos_network_owner6_entry_t *owner6;
    argos_network_prefix_t learned[ARGOS_NETWORK_MAX_PREFIXES];
    argos_network_prefix_t configured[ARGOS_NETWORK_MAX_PREFIXES];
    argos_network_iface_t ifaces[ARGOS_NETWORK_MAX_INTERFACES];
    int learned_count;
    int configured_count;
    int iface_count;
} argos_network_state_t;

static inline void argos_network_init(argos_network_state_t *state) {
    if (state) memset(state, 0, sizeof(*state));
}

static inline void argos_network_destroy(argos_network_state_t *state) {
    if (!state) return;
    free(state->owner4);
    free(state->owner6);
    state->owner4 = NULL;
    state->owner6 = NULL;
}

static inline uint64_t argos_network_hash(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static inline int argos_network_mac_is_unicast(const uint8_t mac[6]) {
    static const uint8_t zero[6] = {0,0,0,0,0,0};
    return mac && memcmp(mac, zero, 6) != 0 && (mac[0] & 1U) == 0U;
}

/* Lifecycle-only preparation. Requested families are independent so one remains
 * useful if the other allocation fails. Repeated calls preserve learned owners. */
static inline int argos_network_prepare_owners(argos_network_state_t *state,
                                                int want4, int want6) {
    if (!state) return 0;
    if (want4 && !state->owner4)
        state->owner4 = (argos_network_owner4_entry_t *)calloc(
            ARGOS_NETWORK_OWNER4_SLOTS, sizeof(*state->owner4));
    if (want6 && !state->owner6)
        state->owner6 = (argos_network_owner6_entry_t *)calloc(
            ARGOS_NETWORK_OWNER6_SLOTS, sizeof(*state->owner6));
    return (!want4 || state->owner4) && (!want6 || state->owner6);
}

static inline void argos_network_owner4_note(argos_network_state_t *state,
                                              uint32_t ip, const uint8_t mac[6]) {
    if (!state || !state->owner4 || ip == 0U ||
        !argos_network_mac_is_unicast(mac)) return;
    size_t base = (size_t)(argos_network_hash(&ip, sizeof(ip)) &
                           (ARGOS_NETWORK_OWNER4_SLOTS - 1U));
    time_t now = time(NULL), oldest = now;
    size_t repl = base;
    for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
        size_t slot = (base + p) & (ARGOS_NETWORK_OWNER4_SLOTS - 1U);
        argos_network_owner4_entry_t *e = &state->owner4[slot];
        if (!e->valid || now < e->last_seen ||
            (now - e->last_seen) > ARGOS_NETWORK_OWNER_TTL_SECS || e->ip == ip) {
            e->ip = ip; memcpy(e->mac, mac, 6); e->last_seen = now; e->valid = 1; return;
        }
        if (e->last_seen < oldest) { oldest = e->last_seen; repl = slot; }
    }
    state->owner4[repl].ip = ip; memcpy(state->owner4[repl].mac, mac, 6);
    state->owner4[repl].last_seen = now; state->owner4[repl].valid = 1;
}

static inline int argos_network_owner4_mismatch(argos_network_state_t *state,
                                                 uint32_t ip, const uint8_t mac[6]) {
    if (!state || ip == 0U || !argos_network_mac_is_unicast(mac) || !state->owner4) return 0;
    size_t base = (size_t)(argos_network_hash(&ip, sizeof(ip)) &
                           (ARGOS_NETWORK_OWNER4_SLOTS - 1U));
    time_t now = time(NULL);
    for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
        argos_network_owner4_entry_t *e =
            &state->owner4[(base + p) & (ARGOS_NETWORK_OWNER4_SLOTS - 1U)];
        if (!e->valid) continue;
        if (now < e->last_seen ||
            (now - e->last_seen) > ARGOS_NETWORK_OWNER_TTL_SECS) { e->valid = 0; continue; }
        if (e->ip == ip) return memcmp(e->mac, mac, 6) != 0;
    }
    return 0;
}

static inline void argos_network_owner6_note(argos_network_state_t *state,
                                              const struct in6_addr *ip, const uint8_t mac[6]) {
    static const struct in6_addr zero = IN6ADDR_ANY_INIT;
    if (!state || !state->owner6 || !ip || IN6_ARE_ADDR_EQUAL(ip, &zero) ||
        !argos_network_mac_is_unicast(mac)) return;
    size_t base = (size_t)(argos_network_hash(ip->s6_addr, 16) &
                           (ARGOS_NETWORK_OWNER6_SLOTS - 1U));
    time_t now = time(NULL), oldest = now;
    size_t repl = base;
    for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
        size_t slot = (base + p) & (ARGOS_NETWORK_OWNER6_SLOTS - 1U);
        argos_network_owner6_entry_t *e = &state->owner6[slot];
        if (!e->valid || now < e->last_seen ||
            (now - e->last_seen) > ARGOS_NETWORK_OWNER_TTL_SECS ||
            IN6_ARE_ADDR_EQUAL(&e->ip, ip)) {
            e->ip = *ip; memcpy(e->mac, mac, 6); e->last_seen = now; e->valid = 1; return;
        }
        if (e->last_seen < oldest) { oldest = e->last_seen; repl = slot; }
    }
    state->owner6[repl].ip = *ip; memcpy(state->owner6[repl].mac, mac, 6);
    state->owner6[repl].last_seen = now; state->owner6[repl].valid = 1;
}

static inline int argos_network_owner6_mismatch(argos_network_state_t *state,
                                                 const struct in6_addr *ip, const uint8_t mac[6]) {
    static const struct in6_addr zero = IN6ADDR_ANY_INIT;
    if (!state || !ip || IN6_ARE_ADDR_EQUAL(ip, &zero) ||
        !argos_network_mac_is_unicast(mac) || !state->owner6) return 0;
    size_t base = (size_t)(argos_network_hash(ip->s6_addr, 16) &
                           (ARGOS_NETWORK_OWNER6_SLOTS - 1U));
    time_t now = time(NULL);
    for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
        argos_network_owner6_entry_t *e =
            &state->owner6[(base + p) & (ARGOS_NETWORK_OWNER6_SLOTS - 1U)];
        if (!e->valid) continue;
        if (now < e->last_seen ||
            (now - e->last_seen) > ARGOS_NETWORK_OWNER_TTL_SECS) { e->valid = 0; continue; }
        if (IN6_ARE_ADDR_EQUAL(&e->ip, ip)) return memcmp(e->mac, mac, 6) != 0;
    }
    return 0;
}

static inline int argos_network_private4(uint32_t ip_be) {
    uint32_t ip = ntohl(ip_be);
    return ip == 0 || (ip & 0xFFFF0000U) == 0xA9FE0000U ||
           (ip & 0xFF000000U) == 0x0A000000U || (ip & 0xFFF00000U) == 0xAC100000U ||
           (ip & 0xFFFF0000U) == 0xC0A80000U || (ip & 0xFFC00000U) == 0x64400000U ||
           (ip & 0xFF000000U) == 0x7F000000U;
}

static inline int argos_network_private6(const struct in6_addr *addr) {
    if (!addr) return 0;
    const unsigned char *a = addr->s6_addr;
    int all_zero = 1;
    for (int i = 0; i < 16; ++i) if (a[i] != 0U) { all_zero = 0; break; }
    return all_zero || (a[0] == 0xfeU && (a[1] & 0xc0U) == 0x80U) ||
           ((a[0] & 0xfeU) == 0xfcU);
}

static inline int argos_network_prefix6_match(const struct in6_addr *addr,
                                               const argos_network_prefix_t *pfx) {
    for (int i = 0; i < 16; ++i)
        if ((addr->s6_addr[i] & pfx->v6mask.s6_addr[i]) != pfx->v6.s6_addr[i]) return 0;
    return 1;
}

static inline int argos_network_is_lan4(const argos_network_state_t *state, uint32_t ip_be) {
    for (int i = 0; i < state->configured_count; ++i)
        if (state->configured[i].family == AF_INET &&
            (ip_be & state->configured[i].v4mask) == state->configured[i].v4) return 1;
    if (argos_network_private4(ip_be)) return 1;
    for (int i = 0; i < state->learned_count; ++i)
        if (state->learned[i].family == AF_INET &&
            (ip_be & state->learned[i].v4mask) == state->learned[i].v4) return 1;
    return 0;
}

static inline int argos_network_is_lan6(const argos_network_state_t *state,
                                         const struct in6_addr *addr) {
    if (!state || !addr) return 0;
    for (int i = 0; i < state->configured_count; ++i)
        if (state->configured[i].family == AF_INET6 &&
            argos_network_prefix6_match(addr, &state->configured[i])) return 1;
    if (argos_network_private6(addr)) return 1;
    for (int i = 0; i < state->learned_count; ++i)
        if (state->learned[i].family == AF_INET6 &&
            argos_network_prefix6_match(addr, &state->learned[i])) return 1;
    return 0;
}

static inline int argos_network_iface_has_family(const argos_network_state_t *state,
                                                  int ifindex, int family) {
    if (!state || ifindex <= 0) return 0;
    for (int i = 0; i < state->learned_count; ++i)
        if (state->learned[i].ifindex == ifindex && state->learned[i].family == family) return 1;
    return 0;
}

static inline int argos_network_direct4(const argos_network_state_t *state,
                                         uint32_t ip_be, int ifindex) {
    if (!state || ifindex <= 0) return 0;
    for (int i = 0; i < state->learned_count; ++i)
        if (state->learned[i].family == AF_INET && state->learned[i].ifindex == ifindex &&
            (ip_be & state->learned[i].v4mask) == state->learned[i].v4) return 1;
    return 0;
}

static inline int argos_network_direct6(const argos_network_state_t *state,
                                         const struct in6_addr *addr, int ifindex) {
    if (!state || !addr || ifindex <= 0) return 0;
    for (int i = 0; i < state->learned_count; ++i)
        if (state->learned[i].family == AF_INET6 && state->learned[i].ifindex == ifindex &&
            argos_network_prefix6_match(addr, &state->learned[i])) return 1;
    return 0;
}

static inline int argos_network_routed4(const argos_network_state_t *state,
                                         uint32_t ip_be, int ifindex) {
    if (!state || ifindex <= 0) return 0;
    uint32_t ip = ntohl(ip_be);
    if (!((ip & 0xFF000000U) == 0x0A000000U || (ip & 0xFFF00000U) == 0xAC100000U ||
          (ip & 0xFFFF0000U) == 0xC0A80000U || (ip & 0xFFC00000U) == 0x64400000U)) return 0;
    int has_family = 0;
    for (int i = 0; i < state->learned_count; ++i) {
        const argos_network_prefix_t *p = &state->learned[i];
        if (p->family != AF_INET || p->ifindex != ifindex) continue;
        has_family = 1;
        if ((ip_be & p->v4mask) == p->v4) return 0;
    }
    return has_family;
}

static inline int argos_network_routed6(const argos_network_state_t *state,
                                         const struct in6_addr *addr, int ifindex) {
    if (!state || !addr || ifindex <= 0) return 0;
    int ula = (addr->s6_addr[0] & 0xFEU) == 0xFCU;
    if (!ula && (addr->s6_addr[0] & 0xE0U) != 0x20U) return 0;
    int routed = 0;
    for (int i = 0; i < state->learned_count; ++i) {
        const argos_network_prefix_t *p = &state->learned[i];
        if (p->family != AF_INET6 || p->ifindex != ifindex) continue;
        /* A later direct prefix must override an earlier routed candidate. */
        if (argos_network_prefix6_match(addr, p)) return 0;
        if (ula || ((p->v6.s6_addr[0] & 0xE0U) == 0x20U &&
                    memcmp(addr->s6_addr, p->v6.s6_addr, 6) == 0)) routed = 1;
    }
    return routed;
}

static inline int argos_network_prefix_context(int capture_ifindex, int packet_ifindex) {
    return capture_ifindex > 0 ? capture_ifindex : packet_ifindex;
}

/* Per-packet policy, not packet bytes, flow state or observation storage.
 * source_side means the source belongs to the monitored side, not PACKET_OUTGOING.
 * routed is source evidence, initially off-link and later optionally confirmed
 * by the existing gated owner-cache lookup. L2 callers start with both zero. */
typedef struct {
    int source_side;
    int routed;
} argos_network_packet_context_t;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline int argos_network_context4(const argos_network_state_t *state,
                                         uint32_t src, uint32_t dst, int ifindex,
                                         argos_network_packet_context_t *out) {
    int src_lan = argos_network_is_lan4(state, src);
    out->routed = argos_network_routed4(state, src, ifindex);
    out->source_side = src_lan || out->routed;
    /* A source-side match already admits the packet; destination membership
     * cannot change source-side selection or routed evidence. */
    return out->source_side || argos_network_is_lan4(state, dst);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline int argos_network_context6(const argos_network_state_t *state,
                                         const struct in6_addr *src,
                                         const struct in6_addr *dst, int ifindex,
                                         argos_network_packet_context_t *out) {
    int src_lan = argos_network_is_lan6(state, src);
    out->routed = argos_network_routed6(state, src, ifindex);
    out->source_side = src_lan || out->routed;
    return out->source_side || argos_network_is_lan6(state, dst);
}

static inline int argos_network_add_iface(argos_network_state_t *state,
                                           const char *name, int ifindex) {
    if (!state || !name || state->iface_count >= ARGOS_NETWORK_MAX_INTERFACES) return 0;
    argos_network_iface_t *iface = &state->ifaces[state->iface_count++];
    iface->ifindex = ifindex;
    snprintf(iface->name, sizeof(iface->name), "%s", name);
    return 1;
}

static inline int argos_network_parse_prefix_bits(const char *text, int max_bits,
                                                   int *bits_out) {
    if (!text || !*text || !bits_out) return 0;
    unsigned value = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10U + (unsigned)(*p - '0');
        if (value > (unsigned)max_bits) return 0;
    }
    *bits_out = (int)value;
    return 1;
}

static inline int argos_network_add_inside(argos_network_state_t *state, const char *spec) {
    if (!state || !spec || !*spec || state->configured_count >= ARGOS_NETWORK_MAX_PREFIXES) return 0;
    char buf[INET6_ADDRSTRLEN + 8];
    size_t n = strlen(spec);
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, spec, n + 1U);
    char *slash = strchr(buf, '/');
    if (slash) { *slash++ = '\0'; if (!*slash || strchr(slash, '/')) return 0; }
    argos_network_prefix_t e; memset(&e, 0, sizeof(e));
    int bits;
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        bits = 32;
        if (slash && !argos_network_parse_prefix_bits(slash, 32, &bits)) return 0;
        uint32_t mask = bits == 0 ? 0U : (uint32_t)(0xffffffffU << (32 - bits));
        e.family = AF_INET; e.v4mask = htonl(mask); e.v4 = a4.s_addr & e.v4mask;
    } else if (inet_pton(AF_INET6, buf, &a6) == 1) {
        bits = 128;
        if (slash && !argos_network_parse_prefix_bits(slash, 128, &bits)) return 0;
        e.family = AF_INET6; e.v6 = a6;
        int remain = bits;
        for (int i = 0; i < 16; ++i) {
            if (remain >= 8) { e.v6mask.s6_addr[i] = 0xffU; remain -= 8; }
            else if (remain > 0) { e.v6mask.s6_addr[i] = (uint8_t)(0xffU << (8 - remain)); remain = 0; }
            e.v6.s6_addr[i] &= e.v6mask.s6_addr[i];
        }
    } else return 0;
    state->configured[state->configured_count++] = e;
    return 1;
}

static inline int argos_network_netlink_prefix_event(uint16_t type) {
#ifndef ARGOS_PORTABLE_TEST
    return type == RTM_NEWADDR || type == RTM_DELADDR;
#else
    (void)type;
    return 0;
#endif
}

#ifndef ARGOS_PORTABLE_TEST
static inline int argos_network_iface_captured(const argos_network_state_t *state,
                                                const char *ifname) {
    if (state->iface_count == 0) return 1;
    for (int i = 0; i < state->iface_count; ++i)
        if (strcasecmp(state->ifaces[i].name, "any") == 0 ||
            strcmp(state->ifaces[i].name, ifname) == 0) return 1;
    return 0;
}

static inline void argos_network_learn_prefixes(argos_network_state_t *state) {
    struct ifaddrs *ifa = NULL;
    state->learned_count = 0;
    if (getifaddrs(&ifa) != 0) {
        fprintf(stderr, "warning: getifaddrs() failed (%s); falling back to RFC1918/ULA heuristics only.\n", strerror(errno));
        return;
    }
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || !p->ifa_netmask || (p->ifa_flags & IFF_LOOPBACK) ||
            !argos_network_iface_captured(state, p->ifa_name) ||
            state->learned_count >= ARGOS_NETWORK_MAX_PREFIXES) continue;
        argos_network_prefix_t *e = &state->learned[state->learned_count];
        memset(e, 0, sizeof(*e));
        e->ifindex = (int)if_nametoindex(p->ifa_name);
        if (p->ifa_addr->sa_family == AF_INET) {
            e->family = AF_INET;
            e->v4 = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
            e->v4mask = ((struct sockaddr_in *)p->ifa_netmask)->sin_addr.s_addr;
            e->v4 &= e->v4mask; state->learned_count++;
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            e->family = AF_INET6;
            e->v6 = ((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
            e->v6mask = ((struct sockaddr_in6 *)p->ifa_netmask)->sin6_addr;
            for (int i = 0; i < 16; ++i) e->v6.s6_addr[i] &= e->v6mask.s6_addr[i];
            state->learned_count++;
        }
    }
    freeifaddrs(ifa);
    fprintf(stderr, "argos: learned %d LAN prefix(es) from captured interfaces\n", state->learned_count);
}

static inline int argos_network_netlink_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl addr; memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    return fd;
}

static inline int argos_network_netlink_drain(int fd) {
    int refresh = 0;
    unsigned char buf[8192];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == ENOBUFS) refresh = 1;
            break;
        }
        if (n == 0) break;
        int rem = (int)n;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, rem);
             nh = NLMSG_NEXT(nh, rem)) {
            if (nh->nlmsg_type == NLMSG_ERROR ||
                argos_network_netlink_prefix_event((uint16_t)nh->nlmsg_type)) refresh = 1;
        }
    }
    return refresh;
}
#endif

#endif /* ARGOS_NETWORK_H */
