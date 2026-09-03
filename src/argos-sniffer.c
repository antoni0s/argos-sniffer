/* ============================================================================
 * SUMMARY AND OPERATIONAL OVERVIEW OF ARGOS-SNIFFER
 * ============================================================================
 * The argos-sniffer is a passive LAN traffic fingerprinter and live inspector
 * designed for resource-constrained OpenWrt routers AND generic Linux gateways
 * (nftables boxes, Debian/Ubuntu routers, Proxmox hosts, Raspberry Pi, etc.).
 * Its core functionality and system architecture comprise several subsystems:
 *
 * - Capture and Layer 2 Engine: Binds to multiple network interfaces via epoll 
 *   event loops, strips link-layer headers seamlessly across Ethernet, 
 *   cooked packets, and raw IP modes, and prevents silent truncation of 
 *   jumbo frames by implementing MSG_TRUNC with consistent length clamping.
 * - Filtering Subsystem: Compiles text-based rules into Reverse Polish Notation (RPN) 
 *   programs for traffic exclusion (-x), live sniffer Mode 1 (-z), and targeted 
 *   telemetry Mode 2 (-Z), issuing warnings rather than silent truncations for 
 *   overlong expressions.
 * - Protocol Parsing and JA4 Engine: Analyzes TLS ClientHellos to extract SNI, 
 *   ALPN, and cipher suites, dynamically derives TLS versions from 
 *   extensions, applies RFC 8701-compliant GREASE family exclusions, 
 *   caps cipher/extension counts to 2 digits to avoid format overflows, 
 *   and utilizes stack-buffered MD5 computations to optimize the JA4 hot path.
 * - Stateful QUIC Inspection: Enabled via the -W flag, it allocates memory to track 
 *   and reassemble fragmented UDP packets using an 8KB buffer, successfully 
 *   extracting large Post-Quantum (Kyber) ClientHellos and outputting decrypted 
 *   sessions as standard TLS records with 'h3' ALPN.
 * - Gateway and Routed Traffic Detection: Learns directly-connected prefixes,
 *   correlates lightweight ARP/NDP address ownership, and tags LAN-side source
 *   identities observed behind a next-hop router without a growing flow table.
 * - Extended Metrics and Performance Controls: Manages the -E flag toggle to 
 *   optionally enable CPU-intensive calculations like Shannon entropy and RTT/latency 
 *   memory tracking to save CPU cycles on smaller routers, implements 
 *   full-address flow hashing to eliminate synchronization table collisions, 
 *   and incorporates a deduplication engine with configurable TTL windows.
 * ============================================================================ */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <math.h>

#ifdef ARGOS_PORTABLE_TEST
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strdup _strdup
#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT {{{0}}}
#endif
#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a, b) (memcmp((a), (b), sizeof(struct in6_addr)) == 0)
#endif
#ifndef ND_ROUTER_SOLICIT
#define ND_ROUTER_SOLICIT 133
#define ND_ROUTER_ADVERT 134
#define ND_NEIGHBOR_SOLICIT 135
#define ND_NEIGHBOR_ADVERT 136
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif
#else
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#ifndef ARGOS_QUIC_STUB
#include "argos_quic.h"
#endif
#include "argos_tls_ports.h"
#include "argos_tls.h"
#include "argos_l2.h"
#include "argos_fhrp.h"
#include "argos_multicast_membership.h"
#include "argos_wireguard.h"
#include "argos_config.h"
#include "argos_telemetry.h"
#include "argos_packet.h"
#include "argos_discovery.h"
#include "argos_dedup.h"
#include "argos_flow_state.h"
#include "argos_identity.h"
#include "argos_dns_track.h"
#include "argos_enterprise.h"
#include "argos_raw_identity.h"
#ifndef ARGOS_PORTABLE_TEST
#include "argos_netlink.h"
#include "argos_bpf.h"
#endif

/* ============================================================================
 * SECTION: Global Configuration & Version Constants
 * ============================================================================ */
int opt_quic_heavy = 0;          /* Flag to enable heavy stateful QUIC reassembly */
int opt_ext_metrics = 0;         /* Default: Heavy metrics (entropy, RTT, latency) disabled */


#ifdef ARGOS_QUIC_STUB
/* Built-in no-ops so a gateway image can ship without the QUIC decrypt object.
 * Stateless decrypt returns 0 (not decrypted). Stateful decrypt returns -1
 * (failure); a real stateful implementation uses 0 for reassembly pending and
 * 1 for a complete ClientHello. */
static int decrypt_quic_sni(const unsigned char *payload, int len, int pos, uint8_t dcid_len,
                            uint8_t *out, int out_max, int *out_len) {
    (void)payload; (void)len; (void)pos; (void)dcid_len; (void)out; (void)out_max;
    if (out_len) *out_len = 0;
    return 0;
}
static int decrypt_quic_sni_stateful(const unsigned char *payload, int len, int pos, uint8_t dcid_len,
                                     uint8_t *out, int out_max, int *out_len) {
    (void)payload; (void)len; (void)pos; (void)dcid_len; (void)out; (void)out_max;
    if (out_len) *out_len = 0;
    return -1;
}
static void quic_heavy_gc(void) {}
#endif

#define VERSION "6.0.0-dev"

/* ============================================================================
 * SECTION: Gateway/Routed Traffic Detection & Address Ownership
 *
 * `|routed` describes LAN-side source identity, not generic multi-interface
 * forwarding. A source is routed when it is off-link for the captured LAN
 * interface (RFC1918/CGNAT for IPv4; ULA or a sibling GUA prefix for IPv6),
 * or when recent ARP/NDP evidence says the source IP belongs to another MAC.
 * The small fixed tables are evidence caches only; they never emit by themselves.
 * ============================================================================ */

static uint64_t hash_update(uint64_t h, const void *data, size_t len) {
    const unsigned char *p = data;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/** Hashes raw binary data using FNV-1a. */
static uint64_t hash_bytes(const void *data, size_t len) {
    return hash_update(1469598103934665603ULL, data, len);
}

#define OWNER4_SLOTS 256U
#define OWNER6_SLOTS 128U
#define OWNER_PROBES 4U
#define OWNER_TTL_SECS 180

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    time_t last_seen;
    uint8_t valid;
} owner4_entry_t;

typedef struct {
    struct in6_addr ip;
    uint8_t mac[6];
    time_t last_seen;
    uint8_t valid;
} owner6_entry_t;

static owner4_entry_t *owner4_table = NULL;
static owner6_entry_t *owner6_table = NULL;

static int owner4_ensure(void) {
    if (owner4_table) return 1;
    owner4_table = (owner4_entry_t *)calloc(OWNER4_SLOTS, sizeof(*owner4_table));
    return owner4_table != NULL;
}

static int owner6_ensure(void) {
    if (owner6_table) return 1;
    owner6_table = (owner6_entry_t *)calloc(OWNER6_SLOTS, sizeof(*owner6_table));
    return owner6_table != NULL;
}

static int mac_is_unicast_nonzero(const uint8_t mac[6]) {
    static const uint8_t zero[6] = {0,0,0,0,0,0};
    return mac && memcmp(mac, zero, 6) != 0 && (mac[0] & 1U) == 0U;
}

static void owner4_note(uint32_t ip, const uint8_t mac[6]) {
    if (ip == 0U || !mac_is_unicast_nonzero(mac) || !owner4_ensure()) return;
    uint64_t h = hash_bytes(&ip, sizeof(ip));
    size_t base = (size_t)(h & (OWNER4_SLOTS - 1U));
    time_t now = time(NULL);
    size_t repl = base;
    time_t oldest = now;
    for (size_t p = 0; p < OWNER_PROBES; ++p) {
        size_t slot = (base + p) & (OWNER4_SLOTS - 1U);
        owner4_entry_t *e = &owner4_table[slot];
        if (!e->valid || (now - e->last_seen) > OWNER_TTL_SECS || e->ip == ip) {
            e->ip = ip; memcpy(e->mac, mac, 6); e->last_seen = now; e->valid = 1; return;
        }
        if (e->last_seen < oldest) { oldest = e->last_seen; repl = slot; }
    }
    owner4_table[repl].ip = ip; memcpy(owner4_table[repl].mac, mac, 6);
    owner4_table[repl].last_seen = now; owner4_table[repl].valid = 1;
}

static int owner4_mismatch(uint32_t ip, const uint8_t mac[6]) {
    if (ip == 0U || !mac_is_unicast_nonzero(mac) || !owner4_table) return 0;
    uint64_t h = hash_bytes(&ip, sizeof(ip));
    size_t base = (size_t)(h & (OWNER4_SLOTS - 1U));
    time_t now = time(NULL);
    for (size_t p = 0; p < OWNER_PROBES; ++p) {
        owner4_entry_t *e = &owner4_table[(base + p) & (OWNER4_SLOTS - 1U)];
        if (!e->valid) continue;
        if ((now - e->last_seen) > OWNER_TTL_SECS) { e->valid = 0; continue; }
        if (e->ip == ip) return memcmp(e->mac, mac, 6) != 0;
    }
    return 0;
}

static void owner6_note(const struct in6_addr *ip, const uint8_t mac[6]) {
    static const struct in6_addr zero = IN6ADDR_ANY_INIT;
    if (!ip || IN6_ARE_ADDR_EQUAL(ip, &zero) || !mac_is_unicast_nonzero(mac) || !owner6_ensure()) return;
    uint64_t h = hash_bytes(ip->s6_addr, 16);
    size_t base = (size_t)(h & (OWNER6_SLOTS - 1U));
    time_t now = time(NULL);
    size_t repl = base;
    time_t oldest = now;
    for (size_t p = 0; p < OWNER_PROBES; ++p) {
        size_t slot = (base + p) & (OWNER6_SLOTS - 1U);
        owner6_entry_t *e = &owner6_table[slot];
        if (!e->valid || (now - e->last_seen) > OWNER_TTL_SECS || IN6_ARE_ADDR_EQUAL(&e->ip, ip)) {
            e->ip = *ip; memcpy(e->mac, mac, 6); e->last_seen = now; e->valid = 1; return;
        }
        if (e->last_seen < oldest) { oldest = e->last_seen; repl = slot; }
    }
    owner6_table[repl].ip = *ip; memcpy(owner6_table[repl].mac, mac, 6);
    owner6_table[repl].last_seen = now; owner6_table[repl].valid = 1;
}

static int owner6_mismatch(const struct in6_addr *ip, const uint8_t mac[6]) {
    static const struct in6_addr zero = IN6ADDR_ANY_INIT;
    if (!ip || IN6_ARE_ADDR_EQUAL(ip, &zero) || !mac_is_unicast_nonzero(mac) || !owner6_table) return 0;
    uint64_t h = hash_bytes(ip->s6_addr, 16);
    size_t base = (size_t)(h & (OWNER6_SLOTS - 1U));
    time_t now = time(NULL);
    for (size_t p = 0; p < OWNER_PROBES; ++p) {
        owner6_entry_t *e = &owner6_table[(base + p) & (OWNER6_SLOTS - 1U)];
        if (!e->valid) continue;
        if ((now - e->last_seen) > OWNER_TTL_SECS) { e->valid = 0; continue; }
        if (IN6_ARE_ADDR_EQUAL(&e->ip, ip)) return memcmp(e->mac, mac, 6) != 0;
    }
    return 0;
}

/* ============================================================================
 * SECTION: TCP & DNS Trackers
 * Maintains lookup structures for active TCP connections and DNS transaction 
 * correlation for latency and entropy measurements.
 * ============================================================================ */
#define TRACK_SLOTS 1024
#define SYN_TRACK_PROBES 8U
#define SYN_TRACK_TTL_USEC 120000000ULL
typedef struct {
    uint8_t mac[6];
    uint16_t sport; uint16_t dport;
    uint8_t ip_version;
    uint8_t src_addr[16], dst_addr[16];
    uint64_t ts_usec;
    uint8_t routed;
    uint8_t valid;
} syn_track_t;
static syn_track_t *syn_table = NULL;

static argos_dns_track_t *dns_table = NULL;

/**
 * Retrieves the current system timestamp in microseconds.
 */
static uint64_t get_current_usec(void) {
#ifdef ARGOS_PORTABLE_TEST
    return (uint64_t)time(NULL) * 1000000ULL;
#else
    struct timeval tv; gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
#endif
}

/**
 * Generates a hash over the complete client identity and endpoint tuple.
 * Equality is always checked against the stored full IPv4/IPv6 addresses;
 * the hash is only an index hint and can never establish a match by itself.
 */
static uint32_t hash_flow(const uint8_t *mac, uint16_t p1, uint16_t p2,
                          uint8_t ip_version, const uint8_t *ip_a, const uint8_t *ip_b) {
    size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = hash_bytes(mac, 6);
    h ^= hash_bytes(&p1, sizeof(p1));
    h ^= hash_bytes(&p2, sizeof(p2)) * 0x9e3779b97f4a7c15ULL;
    h ^= hash_bytes(&ip_version, sizeof(ip_version));
    h ^= hash_bytes(ip_a, addr_len);
    h ^= hash_bytes(ip_b, addr_len) * 0x517cc1b727220a95ULL;
    return (uint32_t)(h ^ (h >> 32));
}

static int syn_track_matches(const syn_track_t *e, const uint8_t mac[6],
                             uint16_t sport, uint16_t dport, uint8_t ip_version,
                             const uint8_t *src_addr, const uint8_t *dst_addr) {
    size_t addr_len = ip_version == 6U ? 16U : 4U;
    return e->valid && e->ip_version == ip_version && e->sport == sport && e->dport == dport &&
           memcmp(e->mac, mac, 6) == 0 && memcmp(e->src_addr, src_addr, addr_len) == 0 &&
           memcmp(e->dst_addr, dst_addr, addr_len) == 0;
}

static syn_track_t *syn_track_find(const uint8_t mac[6], uint16_t sport, uint16_t dport,
                                   uint8_t ip_version, const uint8_t *src_addr,
                                   const uint8_t *dst_addr, uint64_t now_usec, int create) {
    uint32_t base = hash_flow(mac, sport, dport, ip_version, src_addr, dst_addr) & (TRACK_SLOTS - 1U);
    syn_track_t *empty = NULL, *oldest_entry = NULL;
    uint64_t oldest = UINT64_MAX;
    for (uint32_t p = 0; p < SYN_TRACK_PROBES; ++p) {
        syn_track_t *e = &syn_table[(base + p) & (TRACK_SLOTS - 1U)];
        if (e->valid && now_usec >= e->ts_usec && now_usec - e->ts_usec > SYN_TRACK_TTL_USEC)
            e->valid = 0;
        if (syn_track_matches(e, mac, sport, dport, ip_version, src_addr, dst_addr)) return e;
        if (!e->valid) {
            if (!empty) empty = e;
        } else if (e->ts_usec < oldest) {
            oldest = e->ts_usec; oldest_entry = e;
        }
    }
    syn_track_t *replacement = empty ? empty : oldest_entry;
    if (!create || !replacement) return NULL;
    memset(replacement, 0, sizeof(*replacement));
    memcpy(replacement->mac, mac, 6);
    replacement->sport = sport; replacement->dport = dport; replacement->ip_version = ip_version;
    memcpy(replacement->src_addr, src_addr, ip_version == 6U ? 16U : 4U);
    memcpy(replacement->dst_addr, dst_addr, ip_version == 6U ? 16U : 4U);
    replacement->valid = 1;
    return replacement;
}

/**
 * Calculates Shannon entropy for a given string to detect DGA or tunneling activity.
 */
static float calculate_entropy(const char *str) {
    int counts[256] = {0}, len = 0;
    while (*str) { counts[(unsigned char)*str]++; len++; str++; }
    if (len == 0) return 0.0f;
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) { float p = (float)counts[i] / (float)len; entropy -= p * log2f(p); }
    }
    return entropy;
}

/* ============================================================================
 * SECTION: Multi-Interface & Graceful Shutdown
 * Manages multiple socket descriptors via epoll and handles termination signals.
 * ============================================================================ */
#define MAX_INTERFACES 8
#define MAX_EPOLL_EVENTS 16
#define CAPTURE_BUF 65535  /* one full IPv4/IPv6 datagram; PQ ClientHellos need this */
#ifdef ARGOS_PORTABLE_TEST
typedef struct { int fd; int ifindex; link_type_t type; char name[16]; uint64_t total_packets, total_drops; } capture_iface_t;
#else
typedef struct { int fd; int ifindex; link_type_t type; char name[IFNAMSIZ]; uint64_t total_packets, total_drops; } capture_iface_t;
#endif
static capture_iface_t active_ifaces[MAX_INTERFACES];
static int num_ifaces = 0;

static int prefix_context_ifindex(const capture_iface_t *capture, int packet_ifindex) {
    return capture && capture->ifindex > 0 ? capture->ifindex : packet_ifindex;
}

/* Forward declarations used by LAN-prefix classification. */
static int is_private_ipv4(uint32_t ip_be);
static int is_private_ipv6(const struct in6_addr *addr);

/* ============================================================================
 * SECTION: LAN prefix learning
 * RFC1918 / ULA heuristics are OpenWrt-shaped. A dual-stack Linux gateway
 * typically numbers the LAN with IPv6 GUA (2000::/3), which those heuristics
 * classify as "internet" and drop. We learn the prefixes actually configured
 * on the interfaces we capture on (getifaddrs) and treat those as inside too.
 * ============================================================================ */
#define MAX_LAN_PFX 64
typedef struct {
    int family;                 /* AF_INET or AF_INET6 */
    int ifindex;                /* interface owning this connected prefix */
    uint32_t v4, v4mask;        /* network order */
    struct in6_addr v6, v6mask;
} lan_pfx_t;
static lan_pfx_t lan_pfx[MAX_LAN_PFX];
static int lan_pfx_count = 0;
static lan_pfx_t configured_inside[MAX_LAN_PFX];
static int configured_inside_count = 0;

static int lan_pfx_on_captured_iface(const char *ifname) {
    if (num_ifaces == 0) return 1;
    for (int i = 0; i < num_ifaces; i++) {
        if (strcasecmp(active_ifaces[i].name, "any") == 0) return 1;
        if (strcmp(active_ifaces[i].name, ifname) == 0) return 1;
    }
    return 0;
}

#ifndef ARGOS_PORTABLE_TEST
static void learn_lan_prefixes(void) {
    struct ifaddrs *ifa = NULL, *p;
    lan_pfx_count = 0;
    if (getifaddrs(&ifa) != 0) {
        fprintf(stderr, "warning: getifaddrs() failed (%s); falling back to RFC1918/ULA heuristics only.\n", strerror(errno));
        return;
    }
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || !p->ifa_netmask) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        if (!lan_pfx_on_captured_iface(p->ifa_name)) continue;
        if (lan_pfx_count >= MAX_LAN_PFX) break;
        lan_pfx_t *e = &lan_pfx[lan_pfx_count];
        e->ifindex = (int)if_nametoindex(p->ifa_name);
        if (p->ifa_addr->sa_family == AF_INET) {
            e->family = AF_INET;
            e->v4 = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
            e->v4mask = ((struct sockaddr_in *)p->ifa_netmask)->sin_addr.s_addr;
            e->v4 &= e->v4mask;
            lan_pfx_count++;
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            e->family = AF_INET6;
            e->v6 = ((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
            e->v6mask = ((struct sockaddr_in6 *)p->ifa_netmask)->sin6_addr;
            for (int i = 0; i < 16; i++) e->v6.s6_addr[i] &= e->v6mask.s6_addr[i];
            lan_pfx_count++;
        }
    }
    freeifaddrs(ifa);
    fprintf(stderr, "argos: learned %d LAN prefix(es) from captured interfaces\n", lan_pfx_count);
}

/* Route-netlink is integrated into the same epoll loop as AF_PACKET capture.
 * The socket subscribes only to IPv4/IPv6 address changes. A readable burst is
 * drained completely and collapsed into one getifaddrs() refresh, keeping this
 * work out of the per-packet hot path. */
static unsigned char lan_netlink_epoll_tag;

static int lan_netlink_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int lan_netlink_drain(int fd) {
    int refresh = 0;
    unsigned char buf[8192];

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            /* ENOBUFS means notifications may have been dropped. Force a
             * full resnapshot so stale prefixes cannot persist silently. */
            if (errno == ENOBUFS) refresh = 1;
            break;
        }
        if (n == 0) break;

        int rem = (int)n;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, rem);
             nh = NLMSG_NEXT(nh, rem)) {
            if (nh->nlmsg_type == NLMSG_ERROR) {
                refresh = 1;
                continue;
            }
            if (argos_netlink_prefix_event_type((uint16_t)nh->nlmsg_type)) refresh = 1;
        }
    }
    return refresh;
}
#endif

static int is_lan_ipv4(uint32_t ip_be) {
    for (int i = 0; i < configured_inside_count; i++) {
        if (configured_inside[i].family == AF_INET &&
            (ip_be & configured_inside[i].v4mask) == configured_inside[i].v4) return 1;
    }
    if (is_private_ipv4(ip_be)) return 1;
    for (int i = 0; i < lan_pfx_count; i++) {
        if (lan_pfx[i].family == AF_INET && (ip_be & lan_pfx[i].v4mask) == lan_pfx[i].v4) return 1;
    }
    return 0;
}

static int is_lan_ipv6(const struct in6_addr *addr) {
    for (int i = 0; i < configured_inside_count; i++) {
        if (configured_inside[i].family != AF_INET6) continue;
        int ok = 1;
        for (int b = 0; b < 16; b++) {
            if ((addr->s6_addr[b] & configured_inside[i].v6mask.s6_addr[b]) !=
                configured_inside[i].v6.s6_addr[b]) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    if (is_private_ipv6(addr)) return 1;
    for (int i = 0; i < lan_pfx_count; i++) {
        if (lan_pfx[i].family != AF_INET6) continue;
        int ok = 1;
        for (int b = 0; b < 16; b++) {
            if ((addr->s6_addr[b] & lan_pfx[i].v6mask.s6_addr[b]) != lan_pfx[i].v6.s6_addr[b]) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}


static int iface_has_prefix_family(int ifindex, int family) {
    if (ifindex <= 0) return 0;
    for (int i = 0; i < lan_pfx_count; ++i) {
        if (lan_pfx[i].ifindex == ifindex && lan_pfx[i].family == family) return 1;
    }
    return 0;
}

static int is_direct_ipv4_on_iface(uint32_t ip_be, int ifindex) {
    if (ifindex <= 0) return 0;
    for (int i = 0; i < lan_pfx_count; ++i) {
        if (lan_pfx[i].family == AF_INET && lan_pfx[i].ifindex == ifindex &&
            (ip_be & lan_pfx[i].v4mask) == lan_pfx[i].v4) return 1;
    }
    return 0;
}

static int is_direct_ipv6_on_iface(const struct in6_addr *addr, int ifindex) {
    if (!addr || ifindex <= 0) return 0;
    for (int i = 0; i < lan_pfx_count; ++i) {
        if (lan_pfx[i].family != AF_INET6 || lan_pfx[i].ifindex != ifindex) continue;
        int ok = 1;
        for (int b = 0; b < 16; ++b) {
            if ((addr->s6_addr[b] & lan_pfx[i].v6mask.s6_addr[b]) != lan_pfx[i].v6.s6_addr[b]) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

/* IPv4 off-link routing evidence is deliberately restricted to address spaces
 * normally used behind home/edge routers, preventing ordinary WAN replies from
 * being tagged routed when capture uses `any`. */
static int is_routed_source_ipv4(uint32_t ip_be, int ifindex) {
    if (!iface_has_prefix_family(ifindex, AF_INET) || is_direct_ipv4_on_iface(ip_be, ifindex)) return 0;
    uint32_t ip = ntohl(ip_be);
    return ((ip & 0xFF000000U) == 0x0A000000U ||
            (ip & 0xFFF00000U) == 0xAC100000U ||
            (ip & 0xFFFF0000U) == 0xC0A80000U ||
            (ip & 0xFFC00000U) == 0x64400000U);
}

/* ULA is unambiguous. For GUA, accept a sibling subnet only when it shares the
 * first 48 bits with a connected GUA on the same interface, which matches the
 * common delegated-prefix layout while avoiding arbitrary Internet sources. */
static int is_routed_source_ipv6(const struct in6_addr *addr, int ifindex) {
    if (!addr || !iface_has_prefix_family(ifindex, AF_INET6) || is_direct_ipv6_on_iface(addr, ifindex)) return 0;
    if ((addr->s6_addr[0] & 0xFEU) == 0xFCU) return 1; /* ULA */
    if ((addr->s6_addr[0] & 0xE0U) != 0x20U) return 0; /* not GUA */
    for (int i = 0; i < lan_pfx_count; ++i) {
        if (lan_pfx[i].family != AF_INET6 || lan_pfx[i].ifindex != ifindex) continue;
        const uint8_t *pfx = lan_pfx[i].v6.s6_addr;
        if ((pfx[0] & 0xE0U) == 0x20U && memcmp(addr->s6_addr, pfx, 6) == 0) return 1;
    }
    return 0;
}

#ifndef ARGOS_PORTABLE_TEST
static link_type_t hatype_to_link(unsigned short hatype) {
    switch (hatype) {
        case ARPHRD_ETHER:
#ifdef ARPHRD_IEEE802
        case ARPHRD_IEEE802:
#endif
            return LINK_ETHERNET;
        case ARPHRD_NONE:
        case ARPHRD_PPP:
#ifdef ARPHRD_TUNNEL
        case ARPHRD_TUNNEL:
#endif
#ifdef ARPHRD_TUNNEL6
        case ARPHRD_TUNNEL6:
#endif
#ifdef ARPHRD_SIT
        case ARPHRD_SIT:
#endif
#ifdef ARPHRD_IPGRE
        case ARPHRD_IPGRE:
#endif
            return LINK_RAW_IP;
        default:
            /* Unknown link-layer formats are rejected instead of guessing a
             * header layout and risking mis-parsing arbitrary bytes. */
            return LINK_UNSUPPORTED;
    }
}

static volatile sig_atomic_t running = 1;
static void handle_signal(int sig) { (void)sig; running = 0; }
static void install_signal_handlers(void) {
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal; sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = SIG_IGN; sigaction(SIGPIPE, &sa, NULL);
}
#endif

/* ============================================================================
 * SECTION: Deduplication & Privacy Filters
 * Suppresses repetitive log entries within a sliding TTL time window and 
 * sanitizes payloads.
 * ============================================================================ */
#define ARP_DEDUP_TTL_SECS 900
#define NDP_DEDUP_TTL_SECS 900
#define RA_DEDUP_TTL_SECS 1800
static int rate_limit_ttl = 35;
static argos_dedup_state_t dedup_state = {0};

static int dedup_should_suppress_for(const char *mac, const char *evtype, const char *payload,
                                     int rl_enabled, int ttl, int sliding) {
    return argos_dedup_should_suppress(&dedup_state, mac, evtype, payload,
                                       rl_enabled, ttl, sliding);
}

static int dedup_should_suppress(const char *mac, const char *evtype, const char *payload, int rl_enabled) {
    return dedup_should_suppress_for(mac, evtype, payload, rl_enabled, rate_limit_ttl, 1);
}

/* format_mac is implemented with the packet/flow helpers below; declare it
 * here because the telemetry runtime uses the same canonical formatter. */
static void format_mac(const uint8_t mac[6], char out[18]);

/* One wire-format boundary for all observed identity parsers. Protocol parsers
 * produce bounded evidence; this runtime helper owns MAC formatting, dedup and
 * IDENT serialization so those concerns cannot drift per protocol. */
static void emit_identity_observation(const uint8_t mac[6], const char *src_ip,
                                      const argos_identity_result_t *ident,
                                      const char *routed_str, int rl_enabled) {
    if (!mac || !src_ip || !ident || !ident->present) return;
    char ident_mac[18], ident_sig[320];
    format_mac(mac, ident_mac);
    snprintf(ident_sig, sizeof(ident_sig), "%.45s|%.23s|%.23s|%.191s",
             src_ip, ident->protocol, ident->type, ident->value);
    if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, rl_enabled))
        emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                       ident_mac, src_ip, ident->protocol, ident->type,
                       ident->value, routed_str ? routed_str : "");
}

/* Discovery records describe relatively stable ownership/fingerprint state.
 * In quiet mode, unchanged records use a fixed (not sliding) refresh window:
 * changes emit immediately and continuously repeated state is still refreshed
 * eventually. The normal -f value can lengthen, but not shorten, these floors. */
static int dedup_should_suppress_discovery(const char *mac, const char *evtype,
                                           const char *payload, int rl_enabled) {
    int ttl = rate_limit_ttl;
    int floor = strcmp(evtype, "RA") == 0 ? RA_DEDUP_TTL_SECS :
                (strcmp(evtype, "NDP") == 0 ? NDP_DEDUP_TTL_SECS : ARP_DEDUP_TTL_SECS);
    if (ttl > 0 && ttl < floor) ttl = floor;
    return dedup_should_suppress_for(mac, evtype, payload, rl_enabled, ttl, 0);
}

/* Include source identity and routed state in internal dedup keys. This is
 * especially important for multiple off-link clients sharing one next-hop MAC;
 * it does not alter any externally visible vector field. */
static void source_dedup_signature(char *out, size_t out_cap, const char *src_ip,
                                   const char *payload, const char *routed_str) {
    if (!out || out_cap == 0U) return;
    snprintf(out, out_cap, "%s|%s|%s", src_ip ? src_ip : "",
             payload ? payload : "", (routed_str && routed_str[0]) ? "routed" : "direct");
}

/* ============================================================================
 * SECTION: Application Flow Suppression
 * Generic fixed-size TCP generation/DONE state lives in argos_flow_state.h.
 * Protocol-specific completion policy remains here beside the parsers.
 * ============================================================================ */
static argos_flow_state_t app_flow_state = {0};

/* UDP suppression is intentionally separate from TCP DONE state. It is used
 * only for protocol/message classes proven safe to skip briefly. */
static argos_udp_suppress_entry_t udp_suppress_table[ARGOS_UDP_SUPPRESS_SLOTS];

/* A complete TLS ClientHello is enough to finish TLS fingerprinting. HTTP is
 * complete once the request header terminator is present in the captured
 * payload. The packet that completes the fingerprint is still parsed; DONE is
 * applied only to subsequent packets. */
static int app_flow_payload_complete(uint16_t sport, uint16_t dport, const unsigned char *payload, int payload_len) {
    if (!payload || payload_len <= 0) return 0;

    if (argos_tls_tcp_port(sport)) {
        argos_tls_server_result_t server;
        return argos_tls_server_parse(payload, (size_t)payload_len, &server);
    }

    if (argos_tls_tcp_port(dport)) {
        if (payload_len < 9 || payload[0] != 0x16 || payload[5] != 0x01) return 0;
        uint32_t hs_len = ((uint32_t)payload[6] << 16) |
                          ((uint32_t)payload[7] << 8) |
                          (uint32_t)payload[8];
        return hs_len <= (uint32_t)(payload_len - 9);
    }

    if (dport == 80U || dport == 8080U) {
        for (int i = 0; i + 3 < payload_len; ++i) {
            if (payload[i] == '\r' && payload[i + 1] == '\n' &&
                payload[i + 2] == '\r' && payload[i + 3] == '\n') return 1;
        }
    }
    return 0;
}

static void format_mac(const uint8_t mac[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * Case-insensitive needle search in a byte array haystack.
 */
static const unsigned char *find_bytes_ci(const unsigned char *haystack, size_t haystacklen, const char *needle, size_t needlelen) {
    if (needlelen == 0 || haystacklen < needlelen) return NULL;
    size_t last = haystacklen - needlelen;
    for (size_t i = 0; i <= last; i++) {
        size_t j = 0;
        for (; j < needlelen; j++) { if (tolower(haystack[i + j]) != tolower((unsigned char)needle[j])) break; }
        if (j == needlelen) return haystack + i;
    }
    return NULL;
}

/**
 * Exact byte sequence search in a byte array haystack.
 */
static const unsigned char *find_bytes(const unsigned char *haystack, size_t haystacklen, const unsigned char *needle, size_t needlelen) {
    if (needlelen == 0 || haystacklen < needlelen) return NULL;
    size_t last = haystacklen - needlelen;
    for (size_t i = 0; i <= last; i++) {
        if (haystack[i] == needle[0] && memcmp(haystack + i, needle, needlelen) == 0) return haystack + i;
    }
    return NULL;
}

/**
 * Validates if an IPv4 address belongs to a private/local range.
 */
static int is_private_ipv4(uint32_t ip_be) {
    uint32_t ip = ntohl(ip_be);
    return (ip == 0 || (ip & 0xFFFF0000) == 0xA9FE0000 || (ip & 0xFF000000) == 0x0A000000 ||
            (ip & 0xFFF00000) == 0xAC100000 || (ip & 0xFFFF0000) == 0xC0A80000 ||
            (ip & 0xFFC00000) == 0x64400000 ||   /* 100.64.0.0/10 CGNAT -- common on ISP CPEs */
            (ip & 0xFF000000) == 0x7F000000);    /* 127.0.0.0/8 */
}

/**
 * Validates if an IPv6 address belongs to a private/local range.
 */
static int is_private_ipv6(const struct in6_addr *addr) {
    const unsigned char *a = addr->s6_addr;
    int all_zero = 1; for (int i = 0; i < 16; i++) if (a[i] != 0) { all_zero = 0; break; }
    return (all_zero || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) || ((a[0] & 0xfe) == 0xfc));
}

/* LAN prefix table + is_lan_* live after active_ifaces[] is declared
 * (they need capture_iface_t). See "SECTION: LAN prefix learning". */

/**
 * Sanitizes extracted field strings, replacing unprintable characters and pipe symbols.
 */
static void sanitize_field(const unsigned char *src, int len, char *dst, int max_dst, int to_lower) {
    int out = 0;
    for (int i = 0; i < len && out < max_dst - 1; i++) {
        unsigned char c = src[i];
        if (c < 32 || c > 126 || c == '|') c = ' ';
        else if (to_lower) c = (unsigned char)tolower(c);
        dst[out++] = (char)c;
    }
    dst[out] = '\0';
}

/* ============================================================================
 * SECTION: Shunting-Yard Filter Engine
 * Parses and evaluates filter expressions for selective packet capturing and logging.
 * ============================================================================ */
#define MAX_FILTER_TOKENS 64
typedef enum { TOK_NONE, TOK_AND, TOK_OR, TOK_NOT, TOK_LPAREN, TOK_RPAREN, TOK_MAC, TOK_IPV4, TOK_IPV6 } filter_tok_type;

typedef struct {
    filter_tok_type type;
    union {
        uint8_t mac[6];
        struct { uint32_t ip; uint32_t mask; } ipv4;
        struct { struct in6_addr ip; struct in6_addr mask; } ipv6;
    } val;
} filter_token_t;

typedef struct { filter_token_t rpn[MAX_FILTER_TOKENS]; int count; int is_active; } filter_program_t;

/* Operator precedence table used by the shunting-yard algorithm below:
 * NOT binds tightest, then AND, then OR (same convention as most languages). */
static int precedence(filter_tok_type op) {
    if (op == TOK_NOT) return 3;
    if (op == TOK_AND) return 2;
    if (op == TOK_OR) return 1;
    return 0;
}

/**
 * Checks whether `addr` matches an IPv6 filter token, i.e. whether
 * (addr & mask) == (token.ip & mask), compared 16 bytes at a time.
 */
static int ipv6_masked_match(const struct in6_addr *addr, const struct in6_addr *filter_ip, const struct in6_addr *filter_mask) {
    for (int i = 0; i < 16; i++) {
        if ((addr->s6_addr[i] & filter_mask->s6_addr[i]) != (filter_ip->s6_addr[i] & filter_mask->s6_addr[i])) return 0;
    }
    return 1;
}

/**
 * Compiles a text filter expression (e.g. "192.168.1.5 and not 00:11:22:33:44:55")
 * into Reverse Polish Notation (RPN) using the classic shunting-yard algorithm:
 * operands (MAC/IPv4/IPv6 literals) go straight to the output program,
 * operators are pushed onto a local stack and popped into the output program
 * once a lower/equal-precedence operator or a closing paren is seen.
 */
static int parse_mac_address(const char *text, uint8_t out[6]) {
    unsigned int v[6]; char tail;
    if (!text || !out) return 0;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail) != 6) return 0;
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xffU) return 0;
        out[i] = (uint8_t)v[i];
    }
    return 1;
}

static int parse_cidr_bits(const char *text, int max_bits, int *bits_out) {
    char *end = NULL; long v;
    if (!text || !*text || !bits_out) return 0;
    errno = 0;
    v = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || v < 0 || v > max_bits) return 0;
    *bits_out = (int)v;
    return 1;
}

static int append_filter_rpn(filter_program_t *prog, const filter_token_t *tok) {
    if (prog->count >= MAX_FILTER_TOKENS) {
        fprintf(stderr, "Filter parse error: expression is too complex\n");
        return 0;
    }
    prog->rpn[prog->count++] = *tok;
    return 1;
}

static int compile_filter(const char *expr_in, filter_program_t *prog) {
    prog->count = 0;
    prog->is_active = 0;
    if (!expr_in || !*expr_in) return 0;

    if (strlen(expr_in) >= 512U) {
        fprintf(stderr, "Filter parse error: expression exceeds 511 characters\n");
        return -1;
    }

    char expr[512];
    memcpy(expr, expr_in, strlen(expr_in) + 1U);
    filter_token_t op_stack[MAX_FILTER_TOKENS];
    int op_sp = 0;
    int expect_operand = 1;
    char *p = expr;

    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (*p == '(') {
            if (!expect_operand) {
                fprintf(stderr, "Filter parse error: missing operator before '('\n");
                return -1;
            }
            if (op_sp >= MAX_FILTER_TOKENS) {
                fprintf(stderr, "Filter parse error: expression is too complex\n");
                return -1;
            }
            filter_token_t t = {0};
            t.type = TOK_LPAREN;
            op_stack[op_sp++] = t;
            p++;
            continue;
        }

        if (*p == ')') {
            if (expect_operand) {
                fprintf(stderr, "Filter parse error: unexpected ')'\n");
                return -1;
            }
            int found_lparen = 0;
            while (op_sp > 0) {
                if (op_stack[op_sp - 1].type == TOK_LPAREN) {
                    found_lparen = 1;
                    op_sp--;
                    break;
                }
                if (!append_filter_rpn(prog, &op_stack[--op_sp])) return -1;
            }
            if (!found_lparen) {
                fprintf(stderr, "Filter parse error: unmatched ')'\n");
                return -1;
            }
            p++;
            expect_operand = 0;
            continue;
        }

        filter_token_t t = {0};
        if (*p == '!' && p[1] != '=') {
            t.type = TOK_NOT;
            if (!expect_operand) {
                fprintf(stderr, "Filter parse error: unexpected '!'\n");
                return -1;
            }
            p++;
        } else if (*p == '&' && p[1] == '&') {
            t.type = TOK_AND;
            if (expect_operand) {
                fprintf(stderr, "Filter parse error: unexpected '&&'\n");
                return -1;
            }
            p += 2;
        } else if (*p == '|' && p[1] == '|') {
            t.type = TOK_OR;
            if (expect_operand) {
                fprintf(stderr, "Filter parse error: unexpected '||'\n");
                return -1;
            }
            p += 2;
        } else {
            char word[64]; size_t w = 0;
            while (*p && !isspace((unsigned char)*p) && *p != '(' && *p != ')') {
                if (w >= sizeof(word) - 1U) {
                    fprintf(stderr, "Filter parse error: token exceeds 63 characters\n");
                    return -1;
                }
                word[w++] = *p++;
            }
            word[w] = '\0';
            if (w == 0) continue;

            if (strcasecmp(word, "and") == 0) t.type = TOK_AND;
            else if (strcasecmp(word, "or") == 0) t.type = TOK_OR;
            else if (strcasecmp(word, "not") == 0) t.type = TOK_NOT;
            else {
                if (!expect_operand) {
                    fprintf(stderr, "Filter parse error: missing operator before '%s'\n", word);
                    return -1;
                }
                if (parse_mac_address(word, t.val.mac)) {
                    t.type = TOK_MAC;
                } else {
                    char ip_str[64];
                    size_t wlen = strlen(word);
                    if (wlen >= sizeof(ip_str)) {
                        fprintf(stderr, "Filter parse error: IP token too long\n");
                        return -1;
                    }
                    memcpy(ip_str, word, wlen + 1U);
                    char *slash = strchr(ip_str, '/');
                    int cidr;
                    if (slash) {
                        *slash++ = '\0';
                    }
                    if (slash) {
                        if (strchr(slash, '/')) {
                            fprintf(stderr, "Filter parse error: invalid CIDR '%s'\n", word);
                            return -1;
                        }
                    }
                    struct in_addr a4;
                    struct in6_addr a6;
                    if (inet_pton(AF_INET, ip_str, &a4) == 1) {
                        cidr = 32;
                        if (slash && !parse_cidr_bits(slash, 32, &cidr)) {
                            fprintf(stderr, "Filter parse error: invalid IPv4 CIDR '%s'\n", word);
                            return -1;
                        }
                        t.type = TOK_IPV4;
                        t.val.ipv4.ip = a4.s_addr;
                        uint32_t mask_host = (cidr == 0) ? 0U : (uint32_t)(0xffffffffU << (32 - cidr));
                        t.val.ipv4.mask = htonl(mask_host);
                        t.val.ipv4.ip &= t.val.ipv4.mask;
                    } else if (inet_pton(AF_INET6, ip_str, &a6) == 1) {
                        cidr = 128;
                        if (slash && !parse_cidr_bits(slash, 128, &cidr)) {
                            fprintf(stderr, "Filter parse error: invalid IPv6 CIDR '%s'\n", word);
                            return -1;
                        }
                        t.type = TOK_IPV6;
                        t.val.ipv6.ip = a6;
                        memset(&t.val.ipv6.mask, 0, sizeof(t.val.ipv6.mask));
                        int bits = cidr;
                        for (int bi = 0; bi < 16; bi++) {
                            if (bits >= 8) { t.val.ipv6.mask.s6_addr[bi] = 0xff; bits -= 8; }
                            else if (bits > 0) { t.val.ipv6.mask.s6_addr[bi] = (uint8_t)(0xffU << (8 - bits)); bits = 0; }
                        }
                        for (int bi = 0; bi < 16; bi++) t.val.ipv6.ip.s6_addr[bi] &= t.val.ipv6.mask.s6_addr[bi];
                    } else {
                        fprintf(stderr, "Filter parse error: unrecognized token '%s'\n", word);
                        return -1;
                    }
                }
            }
        }

        if (t.type == TOK_NOT) {
            if (!expect_operand) {
                fprintf(stderr, "Filter parse error: unexpected NOT operator\n");
                return -1;
            }
            /* NOT is right-associative; equal-precedence NOT operators stay on the stack. */
            while (op_sp > 0 && op_stack[op_sp - 1].type != TOK_LPAREN &&
                   (precedence(op_stack[op_sp - 1].type) > precedence(t.type) ||
                    (precedence(op_stack[op_sp - 1].type) == precedence(t.type) && t.type != TOK_NOT))) {
                if (!append_filter_rpn(prog, &op_stack[--op_sp])) return -1;
            }
            if (op_sp >= MAX_FILTER_TOKENS) {
                fprintf(stderr, "Filter parse error: expression is too complex\n");
                return -1;
            }
            op_stack[op_sp++] = t;
            expect_operand = 1;
        } else if (t.type == TOK_AND || t.type == TOK_OR) {
            if (expect_operand) {
                fprintf(stderr, "Filter parse error: binary operator without left operand\n");
                return -1;
            }
            while (op_sp > 0 && op_stack[op_sp - 1].type != TOK_LPAREN &&
                   precedence(op_stack[op_sp - 1].type) >= precedence(t.type)) {
                if (!append_filter_rpn(prog, &op_stack[--op_sp])) return -1;
            }
            if (op_sp >= MAX_FILTER_TOKENS) {
                fprintf(stderr, "Filter parse error: expression is too complex\n");
                return -1;
            }
            op_stack[op_sp++] = t;
            expect_operand = 1;
        } else {
            if (!append_filter_rpn(prog, &t)) return -1;
            expect_operand = 0;
        }
    }

    if (expect_operand) {
        fprintf(stderr, "Filter parse error: expression ends with an operator or is empty\n");
        return -1;
    }
    while (op_sp > 0) {
        if (op_stack[op_sp - 1].type == TOK_LPAREN) {
            fprintf(stderr, "Filter parse error: unmatched '('\n");
            return -1;
        }
        if (!append_filter_rpn(prog, &op_stack[--op_sp])) return -1;
    }

    prog->is_active = (prog->count > 0);
    return 0;
}

/**
 * Evaluates the compiled RPN filter program against packet metadata.
 * A MAC/IPv4/IPv6 token matches if it equals EITHER the source or the
 * destination (so a filter like "10.0.0.5" matches traffic to or from
 * that host). AND/OR/NOT combine matches using a small evaluation stack.
 *
 * src_ip6/dst_ip6 may be NULL when the current packet is not IPv6 (e.g. an
 * IPv4 or ARP packet) -- in that case any TOK_IPV6 token in the program
 * simply evaluates to "no match" instead of dereferencing a NULL pointer.
 */
static inline int evaluate_filter(filter_program_t *prog, const uint8_t *src_mac, const uint8_t *dst_mac,
                                   uint32_t src_ip, uint32_t dst_ip,
                                   const struct in6_addr *src_ip6, const struct in6_addr *dst_ip6) {
    if (!prog->is_active) return 1; 
    int stack[MAX_FILTER_TOKENS], sp = 0;
    for (int i = 0; i < prog->count; i++) {
        filter_token_t *t = &prog->rpn[i];
        if (sp >= MAX_FILTER_TOKENS) return 0;
        if (t->type == TOK_MAC) stack[sp++] = (memcmp(src_mac, t->val.mac, 6) == 0 || memcmp(dst_mac, t->val.mac, 6) == 0);
        else if (t->type == TOK_IPV4) stack[sp++] = ((src_ip & t->val.ipv4.mask) == t->val.ipv4.ip || (dst_ip & t->val.ipv4.mask) == t->val.ipv4.ip);
        else if (t->type == TOK_IPV6) {
            int match = (src_ip6 && ipv6_masked_match(src_ip6, &t->val.ipv6.ip, &t->val.ipv6.mask)) ||
                        (dst_ip6 && ipv6_masked_match(dst_ip6, &t->val.ipv6.ip, &t->val.ipv6.mask));
            stack[sp++] = match;
        }
        else if (t->type == TOK_AND) { if (sp < 2) return 0; int b = stack[--sp]; int a = stack[--sp]; stack[sp++] = (a && b); }
        else if (t->type == TOK_OR) { if (sp < 2) return 0; int b = stack[--sp]; int a = stack[--sp]; stack[sp++] = (a || b); }
        else if (t->type == TOK_NOT) { if (sp < 1) return 0; int a = stack[--sp]; stack[sp++] = !a; }
    }
    return sp == 1 ? stack[0] : 0;
}

/* ============================================================================
 * SECTION: Protocol Parsers
 * Parsers for TLS/JA4, QUIC, LLDP, NetBIOS, DHCP, DNS, and mDNS traffic.
 * ============================================================================ */
static void parse_tls_sni(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport, const char *routed_str, int rl_enabled) {
    argos_tls_client_result_t tls;
    if (!argos_tls_client_parse(payload, len, &tls)) return;
    char fp_payload[512], fp_sig[640];
    snprintf(fp_payload, sizeof(fp_payload), "%s|%s", tls.sni, tls.ja4);
    source_dedup_signature(fp_sig, sizeof(fp_sig), src_ip, fp_payload, routed_str);
    if (!dedup_should_suppress(mac, "TLS", fp_sig, rl_enabled)) {
        emit_telemetry("TLS|%s|%s|%s|%u|%s|%s|%s%s\n", mac, src_ip, dst_ip, dport, tls.sni, tls.ja4, tls.alpn, routed_str);
    }
    if (dport == 853U && !dedup_should_suppress(mac, "DOT", fp_sig, rl_enabled)) {
        emit_telemetry("DOT|%s|%s|%s|%s|%s|%s%s\n", mac, src_ip, dst_ip, tls.sni, tls.ja4, tls.alpn, routed_str);
    }
}

/**
 * Parses QUIC initial packets and decrypts/inspects payloads (stateless or stateful).
 */
static int quic_read_varint_local(const unsigned char *buf, int len, int *pos, uint64_t *value) {
    if (!buf || !pos || !value || *pos < 0 || *pos >= len) return 0;
    unsigned prefix = (unsigned)(buf[*pos] >> 6);
    int n = 1 << prefix;
    if (*pos + n > len) return 0;
    uint64_t v = (uint64_t)(buf[*pos] & 0x3fU);
    for (int i = 1; i < n; ++i) v = (v << 8) | buf[*pos + i];
    *pos += n;
    *value = v;
    return 1;
}

/* Returns the complete byte span of a supported QUIC Initial packet inside
 * a UDP datagram. QUIC v1 uses long-header type 00; RFC 9369 QUIC v2 uses
 * type 01, so packet-type validation is version-specific. */
static int quic_initial_span(const unsigned char *payload, int len, int offset,
                             int *dcid_pos, uint8_t *dcid_len, int *packet_span,
                             uint32_t *quic_version) {
    if (!payload || !dcid_pos || !dcid_len || !packet_span || !quic_version ||
        offset < 0 || len - offset < 7) return 0;
    const unsigned char *p = payload + offset;
    int rem = len - offset;
    if ((p[0] & 0xc0U) != 0xc0U) return 0;
    uint32_t version = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) |
                       ((uint32_t)p[3] << 8) | (uint32_t)p[4];
    unsigned initial_type;
    if (version == 0x00000001U) initial_type = 0U;
    else if (version == 0x6b3343cfU) initial_type = 1U;
    else return 0;
    if (((p[0] & 0x30U) >> 4) != initial_type) return 0;

    int pos = 5;
    uint8_t dlen = p[pos++];
    if (dlen > 20U || pos + (int)dlen >= rem) return 0;
    int dpos = pos;
    pos += (int)dlen;
    uint8_t slen = p[pos++];
    if (slen > 20U || pos + (int)slen > rem) return 0;
    pos += (int)slen;

    uint64_t token_len = 0, packet_length = 0;
    if (!quic_read_varint_local(p, rem, &pos, &token_len)) return 0;
    if (token_len > (uint64_t)(rem - pos)) return 0;
    pos += (int)token_len;
    if (!quic_read_varint_local(p, rem, &pos, &packet_length)) return 0;
    if (packet_length > (uint64_t)(rem - pos)) return 0;

    *dcid_pos = dpos;
    *dcid_len = dlen;
    *packet_span = pos + (int)packet_length;
    *quic_version = version;
    return *packet_span > 0 && *packet_span <= rem;
}


#define QUIC_SUCCESS_SLOTS 64U
#define QUIC_SUCCESS_TTL_SECS 15
typedef struct { uint64_t key; time_t last_seen; uint8_t valid; } quic_success_entry_t;
static quic_success_entry_t quic_success_cache[QUIC_SUCCESS_SLOTS];

static uint64_t quic_flow_key(const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport) {
    char keybuf[160];
    int n = snprintf(keybuf, sizeof(keybuf), "%s|%s|%s|%u", mac, src_ip, dst_ip, (unsigned)dport);
    if (n < 0) return 0;
    if (n >= (int)sizeof(keybuf)) n = (int)sizeof(keybuf) - 1;
    return hash_bytes(keybuf, (size_t)n);
}

static int quic_success_recent(uint64_t key) {
    size_t slot = (size_t)(key & (QUIC_SUCCESS_SLOTS - 1U));
    quic_success_entry_t *e = &quic_success_cache[slot];
    time_t now = time(NULL);
    if (!e->valid || e->key != key) return 0;
    if ((now - e->last_seen) > QUIC_SUCCESS_TTL_SECS) { e->valid = 0; return 0; }
    return 1;
}

static void quic_mark_success(uint64_t key) {
    size_t slot = (size_t)(key & (QUIC_SUCCESS_SLOTS - 1U));
    quic_success_cache[slot].key = key;
    quic_success_cache[slot].last_seen = time(NULL);
    quic_success_cache[slot].valid = 1;
}

/**
 * Parses QUIC Initial packets. Stateful mode is deliberately silent while a
 * fragmented ClientHello is incomplete; telemetry is emitted only when a
 * useful TLS fingerprint is ready or when a real decrypt failure survives the
 * configured rate limit.
 */
static void parse_quic(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport, const char *routed_str, int rl_enabled) {
    if (len < 1200) return;

    uint64_t success_key = quic_flow_key(mac, src_ip, dst_ip, dport);
    int offset = 0;
    int saw_initial = 0;
    int saw_failure = 0;
    uint32_t failure_version = 0U;
    while (offset < len) {
        int dcid_pos = 0, packet_span = 0;
        uint8_t dcid_len = 0;
        uint32_t packet_version = 0U;
        if (!quic_initial_span(payload, len, offset, &dcid_pos, &dcid_len, &packet_span, &packet_version)) break;
        saw_initial = 1;

        uint8_t fake_tls_buf[8192];
        int fake_tls_len = 0;
        int result;
        if (opt_quic_heavy) {
            /* Stateful result: 1=ready, 0=pending, -1=real failure. */
            result = decrypt_quic_sni_stateful(payload + offset, packet_span, dcid_pos, dcid_len,
                                                fake_tls_buf, (int)sizeof(fake_tls_buf), &fake_tls_len);
        } else {
            result = decrypt_quic_sni(payload + offset, packet_span, dcid_pos, dcid_len,
                                      fake_tls_buf, (int)sizeof(fake_tls_buf), &fake_tls_len) ? 1 : -1;
        }

        if (result > 0) {
            parse_tls_sni(fake_tls_buf, fake_tls_len, mac, src_ip, dst_ip, dport, routed_str, rl_enabled);
            quic_mark_success(success_key);
            return;
        }
        if (result < 0) { saw_failure = 1; failure_version = packet_version; }
        /* result == 0 is normal stateful reassembly pending: stay silent. */
        offset += packet_span;
    }

    if (saw_initial && saw_failure && !quic_success_recent(success_key)) {
        /* Failure fallback is intentionally coarse and rate-limited per device
         * and QUIC version, so repeated Initial packets cannot spam telemetry. */
        const char *version_label = failure_version == 0x6b3343cfU ? "v2" : "v1";
        char failure_sig[192], failure_kind[32];
        snprintf(failure_kind, sizeof(failure_kind), "%s-failure", version_label);
        source_dedup_signature(failure_sig, sizeof(failure_sig), src_ip, failure_kind, routed_str);
        if (!dedup_should_suppress(mac, "QUIC", failure_sig, rl_enabled)) {
            emit_telemetry("QUIC|%s|%s|%s|%u|encrypted|%s%s\n", mac, src_ip, dst_ip, dport, version_label, routed_str);
        }
    }
}

/**
 * Parses LLDP (Link Layer Discovery Protocol) frames for system name and
 * description. LLDP TLVs are packed as a 16-bit big-endian header: the top
 * 7 bits are the TLV type and the bottom 9 bits are the value length, i.e.
 * `type = tlv >> 9; length = tlv & 0x1FF;` -- followed by that many bytes
 * of value. Type 0 is the "End of LLDPDU" marker.
 */
static void parse_lldp(const unsigned char *payload, int len, const char *mac, const char *routed_str, int rl_enabled) {
    int pos = 0; char sysname_raw[128] = {0}, sysdesc_raw[256] = {0};
    int have_name = 0, have_desc = 0;
    while (pos + 2 <= len) {
        uint16_t tlv = read_be16(payload + pos); int type = tlv >> 9, tlv_len = tlv & 0x01ff; pos += 2;
        if (type == 0 || pos + tlv_len > len) break; /* end-of-LLDPDU marker, or a truncated/malformed TLV */
        if (type == 5) { int n = tlv_len < 127 ? tlv_len : 127; memcpy(sysname_raw, payload + pos, (size_t)n); sysname_raw[n] = '\0'; have_name = 1; } /* type 5 = System Name */
        else if (type == 6) { int n = tlv_len < 255 ? tlv_len : 255; memcpy(sysdesc_raw, payload + pos, (size_t)n); sysdesc_raw[n] = '\0'; have_desc = 1; } /* type 6 = System Description */
        pos += tlv_len; /* skip to the next TLV, whether or not we cared about this one's type */
    }
    if (have_name || have_desc) {
        char sysname[128], sysdesc[256], payload_sig[384];
        sanitize_field((unsigned char*)sysname_raw, (int)strlen(sysname_raw), sysname, sizeof(sysname), 0);
        sanitize_field((unsigned char*)sysdesc_raw, (int)strlen(sysdesc_raw), sysdesc, sizeof(sysdesc), 0);
        snprintf(payload_sig, sizeof(payload_sig), "%s|%s", sysname, sysdesc);
        if (!dedup_should_suppress(mac, "LLDP", payload_sig, rl_enabled)) emit_telemetry("LLDP|%s|%s|%s%s\n", mac, sysname, sysdesc, routed_str);
    }
}

/**
 * Decodes a "compressed" NetBIOS name (as used in NBNS packets) back to
 * plain ASCII. Each original byte is split into two nibbles, and each
 * nibble is encoded as one uppercase letter 'A'-'P' (0x0-0xF -> 'A'-'P'),
 * so every real byte becomes two bytes on the wire -- e.g. NetBIOS name
 * byte 0x20 (space, used as padding) encodes as "CA". This function
 * reverses that: for every pair of encoded bytes, reconstruct the original
 * byte as `((enc[i]-'A')<<4) | (enc[i+1]-'A')`, stopping at the first NUL
 * or the 0x20 (space) padding byte, and trims trailing spaces from the
 * decoded result.
 */
/**
 * Parses NetBIOS Name Service requests.
 */
static void parse_netbios(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *routed_str, int rl_enabled) {
    argos_discovery_nbns_t parsed;
    if (!argos_discovery_nbns_parse(payload, (size_t)len, &parsed)) return;
    char sig[96]; source_dedup_signature(sig, sizeof(sig), src_ip, parsed.name, routed_str);
    if (!dedup_should_suppress(mac, "NBNS", sig, rl_enabled))
        emit_telemetry("NBNS|%s|%s|%s%s\n", mac, src_ip, parsed.name, routed_str);
}


/* Parse an Ethernet/IPv4 ARP payload and update the passive ownership cache. */
static void parse_arp_vector(const unsigned char *payload, int len, int ifindex, int rl_enabled) {
    argos_discovery_arp_t parsed;
    uint32_t spa, tpa;
    if (len < 0 || !argos_discovery_arp_parse(payload, (size_t)len, &parsed)) return;
    memcpy(&spa, parsed.sender_ip, sizeof(spa));
    memcpy(&tpa, parsed.target_ip, sizeof(tpa));

    char mac[18], sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    struct in_addr a;
    format_mac(parsed.sender_mac, mac);
    a.s_addr = spa; if (!inet_ntop(AF_INET, &a, sender_ip, sizeof(sender_ip))) return;
    a.s_addr = tpa; if (!inet_ntop(AF_INET, &a, target_ip, sizeof(target_ip))) return;

    const char *op = parsed.operation == 1U ? "request" : (parsed.operation == 2U ? "reply" : "other");
    const char *routed = is_routed_source_ipv4(spa, ifindex) ? "|routed" : "";
    char sig[128];
    snprintf(sig, sizeof(sig), "%s|%s|%s|%s", sender_ip, target_ip, op, routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "ARP", sig, rl_enabled))
        emit_telemetry("ARP|%s|%s|%s|%s%s\n", mac, sender_ip, target_ip, op, routed);

    /* Learn only after evaluating the event so a stale owner cannot be hidden
     * before this packet is classified. */
    owner4_note(spa, parsed.sender_mac);
}

/* DHCPv6 is emitted as a separate fixed-format vector. Only client-originated
 * messages are passed here, avoiding noisy ADVERTISE/REPLY records that add no
 * client fingerprint value. */
static void parse_dhcp6(const unsigned char *payload, int len, const char *mac,
                        const char *src_ip, const char *routed_str, int rl_enabled) {
    argos_discovery_dhcp6_t parsed;
    if (len < 0 || !argos_discovery_dhcp6_parse(payload, (size_t)len, &parsed)) return;
    char payload_sig[768], sig[896];
    snprintf(payload_sig, sizeof(payload_sig), "%s|%s|%s|%s|%s", parsed.message_type,
             parsed.duid_type, parsed.vendor, parsed.option_request, parsed.fqdn);
    source_dedup_signature(sig, sizeof(sig), src_ip, payload_sig, routed_str);
    if (!dedup_should_suppress(mac, "DHCP6", sig, rl_enabled)) {
        emit_telemetry("DHCP6|%s|%s|%s|%s|%s|%s|%s%s\n",
                       mac, src_ip, parsed.message_type, parsed.duid_type, parsed.vendor,
                       parsed.option_request, parsed.fqdn, routed_str);
    }
}

static void parse_ra_vector(const uint8_t *icmp, int len, const uint8_t frame_src_mac[6],
                            const struct in6_addr *src_addr, const char *src_ip, int ifindex,
                            int rl_enabled) {
    argos_discovery_ra_t parsed;
    if (!frame_src_mac || !src_addr || len < 0 ||
        !argos_discovery_ra_parse(icmp, (size_t)len, &parsed)) return;
    char mac[18]; format_mac(frame_src_mac, mac);
    char prefix[INET6_ADDRSTRLEN] = "none";
    if (parsed.has_prefix) {
        struct in6_addr pfx;
        memcpy(&pfx, parsed.prefix, sizeof(pfx));
        if (!inet_ntop(AF_INET6, &pfx, prefix, sizeof(prefix))) strcpy(prefix, "none");
    }

    int mismatch = owner6_mismatch(src_addr, frame_src_mac);
    const char *routed = (is_routed_source_ipv6(src_addr, ifindex) || mismatch) ? "|routed" : "";
    char sig[256];
    snprintf(sig, sizeof(sig), "%s|%u|%s|%u|%s|%u|%u|%s", src_ip,
             (unsigned)parsed.hop_limit, parsed.flags, (unsigned)parsed.lifetime,
             prefix, (unsigned)parsed.prefix_length, (unsigned)parsed.mtu,
             routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "RA", sig, rl_enabled))
        emit_telemetry("RA|%s|%s|%u|%s|%u|%s|%u|%u%s\n", mac, src_ip,
                       (unsigned)parsed.hop_limit, parsed.flags, (unsigned)parsed.lifetime,
                       prefix, (unsigned)parsed.prefix_length, (unsigned)parsed.mtu, routed);
    owner6_note(src_addr, frame_src_mac);
}

static void parse_ndp_vector(const uint8_t *icmp, int len, const uint8_t frame_src_mac[6],
                             const struct in6_addr *src_addr, const char *src_ip, int ifindex,
                             int rl_enabled) {
    if (!icmp || len < 0 || !frame_src_mac || !src_addr) return;
    if (len > 0 && icmp[0] == ND_ROUTER_ADVERT) {
        parse_ra_vector(icmp, len, frame_src_mac, src_addr, src_ip, ifindex, rl_enabled);
        return;
    }
    argos_discovery_ndp_t parsed;
    if (!argos_discovery_ndp_parse(icmp, (size_t)len, frame_src_mac, &parsed)) return;
    char mac[18]; format_mac(parsed.identity_mac, mac);

    char target[INET6_ADDRSTRLEN] = "none";
    struct in6_addr target_addr; memset(&target_addr, 0, sizeof(target_addr));
    if (parsed.has_target) {
        memcpy(&target_addr, parsed.target, sizeof(target_addr));
        if (!inet_ntop(AF_INET6, &target_addr, target, sizeof(target))) strcpy(target, "none");
    }
    int mismatch = owner6_mismatch(src_addr, parsed.identity_mac);
    const char *routed = (is_routed_source_ipv6(src_addr, ifindex) || mismatch) ? "|routed" : "";
    char sig[320]; snprintf(sig, sizeof(sig), "%s|%s|%s|%s|%s", src_ip, parsed.kind,
                            target, parsed.flags,
                            routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "NDP", sig, rl_enabled))
        emit_telemetry("NDP|%s|%s|%s|%s|%s%s\n", mac, src_ip, parsed.kind,
                       target, parsed.flags, routed);

    /* Source LLA owns the packet's source address. An NA TLLA additionally
     * claims the advertised target address. */
    owner6_note(src_addr, parsed.identity_mac);
    if (parsed.is_advertisement) owner6_note(&target_addr, parsed.identity_mac);
}

/**
 * Parses DHCP packets to extract hostnames, vendor classes, and parameter
 * request lists. After the fixed 236-byte BOOTP header comes the 4-byte
 * "magic cookie" (0x63825363) that marks the start of DHCP options, then a
 * sequence of TLV options: 1-byte code + 1-byte length + that many bytes,
 * terminated by code 0xFF (End) or the end of the packet. Code 0x00 (Pad)
 * has no length/value byte at all and is simply skipped.
 */
static void parse_dhcp(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *routed_str, int rl_enabled) {
    argos_discovery_dhcp4_t parsed;
    if (len < 0 || !argos_discovery_dhcp4_parse(payload, (size_t)len, &parsed)) return;
    char payload_sig[384], sig[512];
    snprintf(payload_sig, sizeof(payload_sig), "%s|%s|%s", parsed.hostname, parsed.vendor,
             parsed.parameter_request_list);
    source_dedup_signature(sig, sizeof(sig), src_ip, payload_sig, routed_str);
    if (!dedup_should_suppress(mac, "DHCP", sig, rl_enabled))
        emit_telemetry("DHCP|%s|%s|%s|%s|%s%s\n", mac, src_ip, parsed.hostname,
                       parsed.vendor, parsed.parameter_request_list, routed_str);
}

/**
 * Decodes a (possibly compressed) DNS name starting at `start_pos` into a
 * lowercase, dot-separated ASCII string. DNS names are a sequence of
 * length-prefixed labels ("\x03www\x07example\x03com\x00"), but to save
 * space a label length byte with its top two bits set (0xC0) is instead a
 * 14-bit *pointer* to another offset in the same packet where the name (or
 * the rest of it) continues -- this is how DNS avoids repeating "example.com"
 * in every answer record.
 *
 * `original_pos` remembers where to resume reading once we've followed a
 * compression pointer and hit that target's terminating zero-length label
 * (a name can only jump through one pointer chain; only the *first* jump's
 * return address needs to be remembered). `guard` bounds the total number
 * of labels/jumps followed, as a safety net against a maliciously crafted
 * pointer loop (e.g. two labels pointing at each other) that would
 * otherwise spin forever.
 */
static int decode_dns_name(const unsigned char *payload, int payload_len, int start_pos, char *out, int out_max) {
    return argos_discovery_dns_name(payload, payload_len, start_pos, out, out_max);
}

/**
 * Reads the QTYPE of a DNS question without expanding the name. The returned
 * offset follows the encoded QNAME, so normal labels and a terminal compression
 * pointer are both handled without allocating or walking unrelated records.
 */
static int dns_question_qtype(const unsigned char *payload, int payload_len, int start_pos, uint16_t *qtype) {
    return argos_discovery_dns_qtype(payload, payload_len, start_pos, qtype);
}

/**
 * Parses mDNS query records.
 */
static void parse_mdns(const unsigned char *payload, int len, const char *mac, const char *src_ip, int dport_or_sport, const char *routed_str, int rl_enabled) {
    argos_discovery_mdns_t parsed;
    char sig[384];
    if (len < 0 || !argos_discovery_mdns_parse(payload, (size_t)len, &parsed)) return;
    source_dedup_signature(sig, sizeof(sig), src_ip, parsed.question, routed_str);
    if (dedup_should_suppress(mac, "MDNS", sig, rl_enabled)) return;
    emit_telemetry("MDNS|%s|%s|%d|%s%s\n", mac, src_ip, dport_or_sport,
                   parsed.question, routed_str);
}

/* ============================================================================
 * SECTION: Mode 1 - Target Packet Inspector
 * Dumps live captured packets in a tcpdump-like format when Mode 1 is active
 * (-z filter given). This is a read-only, best-effort human-readable printer;
 * it re-parses the packet independently of the main telemetry loop.
 * ============================================================================ */
#ifndef ARGOS_PORTABLE_TEST
static void dump_target_packet(const unsigned char *buffer, int len, int l3_offset, uint16_t l3_proto) {
    struct timeval tv; gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    char tmbuf[32]; strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", tm_info);

    if (l3_proto == 0x0800 && len >= l3_offset + 20) {
        int ip_available = len - l3_offset, ip_packet_len = 0, ip_header_len = 0;
        uint16_t ip_total_len = 0;
        if (!ipv4_header_info(buffer + l3_offset, ip_available, &ip_total_len, &ip_header_len)) return;
        ip_packet_len = (int)ip_total_len;
        /* Use aligned local header copies instead of casting the raw,
         * potentially misaligned packet buffer to protocol header structs. */
        struct iphdr ip_hdr; memcpy(&ip_hdr, buffer + l3_offset, sizeof(ip_hdr));
        struct iphdr *ip = &ip_hdr;
        char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, s_ip, sizeof(s_ip)); inet_ntop(AF_INET, &ip->daddr, d_ip, sizeof(d_ip));
        int l4_offset = l3_offset + ip_header_len;

        if (ip->protocol == IPPROTO_TCP && l4_offset >= l3_offset && l4_offset + 20 <= l3_offset + ip_packet_len) {
            struct tcphdr tcp_hdr; memcpy(&tcp_hdr, buffer + l4_offset, sizeof(tcp_hdr));
            struct tcphdr *tcp = &tcp_hdr;
            if (tcp->doff < 5 || l4_offset + tcp->doff * 4 > l3_offset + ip_packet_len) return;
            char flags[16] = {0}; int fi = 0;
            if (tcp->syn) flags[fi++] = 'S';
            if (tcp->ack) flags[fi++] = '.';
            if (tcp->psh) flags[fi++] = 'P';
            if (tcp->fin) flags[fi++] = 'F';
            if (tcp->rst) flags[fi++] = 'R';
            flags[fi] = '\0';
            printf("%s.%06d IP %s.%u > %s.%u: Flags [%s], seq %u, win %u, length %d\n",
                   tmbuf, (int)tv.tv_usec, s_ip, ntohs(tcp->source), d_ip, ntohs(tcp->dest),
                   flags[0] ? flags : "none", (uint32_t)ntohl(tcp->seq), ntohs(tcp->window), (int)(l3_offset + ip_packet_len - l4_offset - (tcp->doff * 4)));
        } else if (ip->protocol == IPPROTO_UDP && l4_offset >= l3_offset && l4_offset + 8 <= l3_offset + ip_packet_len) {
            struct udphdr udp_hdr; memcpy(&udp_hdr, buffer + l4_offset, sizeof(udp_hdr));
            struct udphdr *udp = &udp_hdr;
            printf("%s.%06d IP %s.%u > %s.%u: UDP, length %u\n", tmbuf, (int)tv.tv_usec, s_ip, ntohs(udp->source), d_ip, ntohs(udp->dest), ntohs(udp->len));
        } else if (ip->protocol == IPPROTO_ICMP) {
            printf("%s.%06d IP %s > %s: ICMP, length %d\n", tmbuf, (int)tv.tv_usec, s_ip, d_ip, (int)(l3_offset + ip_packet_len - l4_offset));
        } else {
            printf("%s.%06d IP %s > %s: proto %u, length %d\n", tmbuf, (int)tv.tv_usec, s_ip, d_ip, ip->protocol, ip_packet_len);
        }
    } else if (l3_proto == 0x86dd && len >= l3_offset + 40) {
        int ip6_packet_len = 0;
        if (!ipv6_packet_info(buffer + l3_offset, len - l3_offset, &ip6_packet_len)) return;
        struct ip6_hdr ip6_hdr_local; memcpy(&ip6_hdr_local, buffer + l3_offset, sizeof(ip6_hdr_local));
        struct ip6_hdr *ip6 = &ip6_hdr_local;
        char s_ip6[INET6_ADDRSTRLEN], d_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, s_ip6, sizeof(s_ip6)); inet_ntop(AF_INET6, &ip6->ip6_dst, d_ip6, sizeof(d_ip6));
        printf("%s.%06d IP6 %s > %s: next-hdr %u, length %d\n", tmbuf, (int)tv.tv_usec, s_ip6, d_ip6, ip6->ip6_nxt, ntohs(ip6->ip6_plen));
    } else if (l3_proto == 0x0806) {
        printf("%s.%06d ARP, length %d\n", tmbuf, (int)tv.tv_usec, (int)len - l3_offset);
    } else {
        printf("%s.%06d ethertype 0x%04x, length %d\n", tmbuf, (int)tv.tv_usec, l3_proto, (int)len);
    }
}
#endif

/* ============================================================================
 * SECTION: CLI & Help
 * Manages router MAC exclusion and prints command-line usage information.
 * ============================================================================ */
#define MAX_ROUTER_MACS 8
static unsigned char router_macs[MAX_ROUTER_MACS][6];
static int router_mac_count = 0;
static inline int is_router_mac(const unsigned char *shost) {
    for (int i = 0; i < router_mac_count; i++) if (memcmp(shost, router_macs[i], 6) == 0) return 1;
    return 0;
}

#define MAX_HARD_EXCLUDE_MACS 8
static unsigned char hard_exclude_macs[MAX_HARD_EXCLUDE_MACS][6];
static int hard_exclude_mac_count = 0;
static inline int is_hard_excluded_mac(const unsigned char *shost) {
    for (int i = 0; i < hard_exclude_mac_count; i++) if (memcmp(shost, hard_exclude_macs[i], 6) == 0) return 1;
    return 0;
}

static int valid_sensor_name(const char *name) {
    if (!name || !*name || strlen(name) >= SENSOR_NAME_MAX) return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.')) return 0;
    }
    return 1;
}

static int add_inside_prefix(const char *spec) {
    if (!spec || !*spec || configured_inside_count >= MAX_LAN_PFX) {
        fprintf(stderr, "Error: invalid or too many --inside prefixes\n");
        return 0;
    }
    char buf[INET6_ADDRSTRLEN + 8];
    size_t n = strlen(spec);
    if (n >= sizeof(buf)) {
        fprintf(stderr, "Error: --inside prefix too long: %s\n", spec);
        return 0;
    }
    memcpy(buf, spec, n + 1U);
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash++ = '\0';
        if (!*slash || strchr(slash, '/')) {
            fprintf(stderr, "Error: invalid --inside CIDR: %s\n", spec);
            return 0;
        }
    }

    lan_pfx_t e; memset(&e, 0, sizeof(e));
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, buf, &a4) == 1) {
        int bits = 32;
        if (slash && !parse_cidr_bits(slash, 32, &bits)) {
            fprintf(stderr, "Error: invalid IPv4 --inside CIDR: %s\n", spec);
            return 0;
        }
        uint32_t mask_host = bits == 0 ? 0U : (uint32_t)(0xffffffffU << (32 - bits));
        e.family = AF_INET;
        e.v4mask = htonl(mask_host);
        e.v4 = a4.s_addr & e.v4mask;
    } else if (inet_pton(AF_INET6, buf, &a6) == 1) {
        int bits = 128;
        if (slash && !parse_cidr_bits(slash, 128, &bits)) {
            fprintf(stderr, "Error: invalid IPv6 --inside CIDR: %s\n", spec);
            return 0;
        }
        e.family = AF_INET6;
        e.v6 = a6;
        int remain = bits;
        for (int i = 0; i < 16; i++) {
            if (remain >= 8) { e.v6mask.s6_addr[i] = 0xffU; remain -= 8; }
            else if (remain > 0) { e.v6mask.s6_addr[i] = (uint8_t)(0xffU << (8 - remain)); remain = 0; }
            else e.v6mask.s6_addr[i] = 0U;
            e.v6.s6_addr[i] &= e.v6mask.s6_addr[i];
        }
    } else {
        fprintf(stderr, "Error: invalid --inside address: %s\n", spec);
        return 0;
    }
    configured_inside[configured_inside_count++] = e;
    return 1;
}

/**
 * Prints comprehensive command line help and documentation.
 */
static void print_help(const char *prog) {
    printf(
"argos-sniffer v" VERSION " - Passive LAN traffic fingerprinter & live inspector\n"
"                  for OpenWrt/Linux gateways and SPAN/TAP sensors\n\n"
"USAGE:\n  %s [-i iface] [-r router_mac] [-x filter_expr] [-z filter_expr | -Z filter_expr] [-o path] [-u ip:port] [-U ip:port] [-f sec] [FLAGS...] [-W]\n"
"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose] [--wireguard-port port]\n"
"  OR:     %s [iface] (Automatically sets -i#Žy¶‰žËkºwµçH[ˆÙXÛÛ™È
Y˜][ˆÍJK—ˆ‚ˆˆ]ZY]T”Ó‘\ÙHNLÈ[™HLNÈš^Y™Yœ™\ÚÚ[™ÝÜË—ˆ‚ˆˆ[È]ˆÝ™X[H[[Y]žHÝ]]ÈH[š^ÛXZ[ˆÛØÚÙ]—ˆ‚ˆˆ]H\ŽÜˆÝ™X[H[[Y]žHÈH™[[ÝHQÛÛXÝÜˆÛ›K—ˆ‚ˆˆUH\ŽÜˆÝ™X[H[[Y]žHÈH™[[ÝHQÛÛXÝÜˆ[™ÝÝ]—ˆ‚ˆˆ
K™ËˆUHLŒŒNLMÜˆUHÎŽŒWNLM
K—ˆ‚ˆˆ“ÕNˆ[[Y]žH\ÈÙ[[™[˜Üž\YÝ[˜]][XØ]YKHÛ›Wˆ‚ˆˆÚ[\È]H\ÝYÜÝ™XXÚX›HÝ™\ˆH\ÝY]ˆ‚ˆˆ
X[˜YÙ[Y[“S‹”‹]ÊK—ˆ‚ˆˆKY[\œš\ÙH[˜X›Hˆ[\œš\ÙH[™ÚZÙKÙ\ØÛÝ™\žHš[™Ù\œš[È
˜]K[[Z]Y
K—ˆ‚ˆˆKY[\œš\ÙK]™\˜›ÜÙH[˜X›H[\œš\ÙHš[™Ù\œš[ÈÚ]Ý][[Y]žHY\XØ][Û‹—ˆ‚ˆˆK]Ú\™YÝX\™\ÜÜˆÚ\™QÝX\™QÜ›ÜˆÝXÝ\˜[]XÝ[Ûˆ
Y˜][ˆLNŒ
K—ˆ‚ˆˆ™\]Z\™\ÈKY[\œš\ÙNÈXÚÙ]ÝXÝ\™H\È˜[Y]Y™Y›Ü™H[Z\ÜÚ[Û‹—ˆ‚ˆˆUÈ[˜X›HÝ]Y[URPÈ[œÜXÝ[Ûˆ
™X\ÜÙ[X›\Èœ˜YÛY[YÞX™\ˆÛY[[ÜÊWˆ‚ˆˆQH[˜X›H^[™YY]šXÜÈ
Ô“•”ÑV][˜ÞK”È[›ÜJW—ˆ‚ˆ•SSQU–H‘PÕÔ”È
ÝÙ\˜Ø\ÙHHSP“HÒUUHSRU\\˜Ø\ÙHHSP“H“ÈSRU
N—ˆ‚ˆˆ\ÈÈTÈÔÖSˆ
ˆÔÈš[™Ù\œš[[™ÊKÖSPÒÈ	ˆÔ“][˜ÞH˜XÚÚ[™×ˆ‚ˆˆ[HÈSHQ”È
LÍLÊHÈÔÑ
NL
HÈÔÑ
ÍÌŠH^[ØYÙÙÚ[™×ˆ‚ˆˆYÈQÔ
ÈÔˆÛY[š[™Ù\œš[ÙÙÚ[™×ˆ‚ˆˆ[ˆÈSˆ™]’SÔÈ˜[YHÙ\šXÙH
QLÍÊHÙÙÚ[™×ˆ‚ˆˆ\HÈTH”È]Y\šY\È	ˆ”ÑV][˜ÞKÙ[›ÜH˜XÚÚ[™È
QÜLÊWˆ‚ˆˆZÈR\Ù\‹PYÙ[^˜XÝ[Ûˆ
ÜÎ
Wˆ‚ˆˆ]ÈUÈÛY[[È
ËÍKÎLËÎNLËÎNMKÎÊH
ÈURPÈQÍ×ˆ‚ˆˆÔÎLÈ[ÛÈ[Z]ÈY]]™H”Ë[Ý™\‹UÈ
Õ
HÛ\ÜÚYšXØ][Û—ˆ‚ˆˆ[ÈS
ÈT”
ÈTˆ‘Ô›Ý]\ˆY™\\Ù[Y[\ØÛÝ™\žWˆ‚ˆˆKY[\œš\ÙH[\œš\ÙKÜÝÜ˜YÙKÚY[]KÜ›Ý][™ËÓÕÛÛ›Û\[™Hš[™Ù\œš[×ˆ‚ˆˆ
]™[ÜY[ÜZ[ŽÈ[[[Û˜[H›Ý[\YYžHXKËPHY]
Wˆ‚ˆˆXHÈPH[˜X›HSYØXÞH™XÝÜœÈX›Ý™H
HHÚ][Z]ËHHÚ]Ý][Z]ÊWˆ‚ˆˆ]ˆÈUˆ[˜X›HTˆ[™[™È
ÝXš™XÝÈ\×Üš]˜]WÚ\Š
Hš[\š[™ËÙYHÛÝ\˜ÙJW—ˆ‹›ÙË›ÙÊNÂˆœ]Êˆ“ÕUU“Ô“PU—ˆ‚ˆˆØ]]Ø^H[ÙHÙY\ÈHYØXÞH™XÛÜ™È™[ÝÈ[˜Ú[™ÙY—ˆ‚ˆˆÙ[œÛÜˆ[ÙNˆÐ”ßÙ[œÛÜ—Û˜[Y_[\™˜XÙ_›[ŸYØXÞWÜ™XÛÜ™—ˆ‚ˆˆ›[L[YÙÙYˆÚ[™ÛK]YËÝ]\‹Ú[›™\ˆ›ÜˆZ[”K—ˆ‚ˆˆÖSŸXXßÜ˜×Ú\Ú[™ÝßÜØØ[_\ÜßÜ[ÛœßÝÜÜß›Ý]YWˆ‚ˆˆÖSPÒßXXßÜ˜×Ú\Ú[™ÝßÜØØ[_\ÜßÜ[ÛœßÜ˜×ÜÜß›Ý]YWˆ‚ˆˆ”ßXXßÜ˜×Ú\]Y\žWÙÛXZ[–ß›Ý]YWˆ‚ˆˆÔ“XXßÜ˜×Ú\ÝÚ\ÝÜÜÝ\ß™]˜[œ×ØÛÝ[Ý]WÙ]™[ß›Ý]YWˆ‚ˆˆßXXßÜ˜×Ú\ÝÚ\ÝÜÜÛš_˜MÙš[™Ù\œš[[–ß›Ý]YWˆ‚ˆˆÕXXßÜ˜×Ú\ÝÚ\Ûš_˜MÙš[™Ù\œš[[–ß›Ý]YWˆ‚ˆˆÔÔ•ŸXXßÙ\™\—Ú\ÛY[Ú\Ù\™\—ÜÜ]ÌWÙš[™Ù\œš[[–ß›Ý]YWˆ‚ˆˆURPßXXßÜ˜×Ú\ÝÚ\ÝÜÜÛš_™\œÚ[Û–ß›Ý]YWˆ‚ˆˆ”ÑVXXßÜ˜×Ú\ÝÚ\]Y\žWÙÛXZ[Ÿ]\_˜ÛÙ_][˜ÞWÛ\ß[›ÜVß›Ý]YWˆ‚ˆˆST•XXßÜ˜×Ú\QÒÑ”×ÑS•“Ô_]Y\žWÙÛXZ[Ÿ[›ÜVß›Ý]YWˆ‚ˆˆXXßÜ˜×Ú\\Ù\—ØYÙ[ß›Ý]YWˆ‚ˆˆXXßÞ\Û˜[Y_Þ\Ù\ØÖß›Ý]YWˆ‚ˆˆ“”ßXXßÜ˜×Ú\™]š[Ü×Û˜[YVß›Ý]YWˆ‚ˆˆÔXXßÜ˜×Ú\ÜÝ˜[Y_™[™Ü—ØÛ\Üß›ß›Ý]YWˆ‚ˆˆÔŸXXßÜ˜×Ú\\Ù×Ý\_ZYÝ\_™[™Ü—ØÛ\ÜßÜ›ßœY–ß›Ý]YWˆ‚ˆˆT”XXßÙ[™\—Ú\\™Ù]Ú\Üß›Ý]YWˆ‚ˆˆ‘XXßÜ˜×Ú\\_\™Ù]Ú\›YÜÖß›Ý]YWˆ‚ˆˆ_XXßÜ˜×Ú\ÜÛ[Z]›YÜß›Ý]\—ÛY™][Y_™Yš^™Yš^Û[Ÿ]Vß›Ý]YWˆ‚ˆˆQ”ßXXßÜ˜×Ú\Ü[˜[YVß›Ý]YWˆ‚ˆˆßXXßÜ˜×Ú\ÝÜÜ^[ØYß›Ý]YWˆ‚ˆˆS•XXßÜ˜×Ú\ÝÚ\›ÝØÛÛš[™Ù\œš[ß›Ý]YWˆ‚ˆˆQS•XXßÜ˜×Ú\›ÝØÛÛ\_Y[]Vß›Ý]YH
KZY[]HÛ›JW—ˆ‚ˆ’QS•UHÔSÓ”È
^XÚ]ÜZ[ŽÈ›ÈÙ[™\šXÈ^[ØYØØ[›š[™ÊN—ˆ‚ˆˆKZY[]VÏSSÑWHØœÙ\™YY[]Hœ›ÛH[™XYKZ[œÜXÝY[™ÚZÙKØÛÛ›ÛšY[Ë—ˆ‚ˆˆSÑH\È\Ú
Y˜][
HÜˆ˜]ÎÈ˜]È\È[ˆ^XÚ]š]˜XÞHÜZ[‹—ˆ‚ˆˆ™\]Z\™\ÈKY[\œš\ÙNÈ™]™\ˆ\ÜÝÛÜ™ËXÚÙ]ËÚÙ[œÈÜˆ]]›ØœË——ˆ‚ˆ‘‘PUT‘TÈVRS‘Q—ˆ‚ˆˆß›Ý]YHÛÝ\˜ÙH\ÈÙ™‹[[šÈ™Z[™H™^ZÜPPÈÜˆÛÛ™›XÝÈÚ]T”Ó‘ÝÛ™\œÚ\—ˆ‚ˆˆM[ZÙH”QKY\š]™YÈÚ\\‹Ù^[œÚ[Ûˆš[™Ù\œš[\ÙY›ÜˆÛY[ÛÜœ™[][Û‹—ˆ‚ˆˆ”È[›ÜHYX\Ý\™\È]Y\žH˜[™Û[™\ÜËˆŒˆšYÙÙ\œÈQÒÑ”×ÑS•“ÔH[\
ÐKÕ[›™[ÊK—ˆ‚ˆˆÌÈ
URPÊHXÜž\YÝ]Y[URPÈ[™ÚZÙ\ÈÝ]]\ÈÈ™XÛÜ™ÈÚ]	ÚÉÈS‹——ˆ‹ÝÝ]
NÂŸB‚‹ÊˆOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOBˆ
ˆÑPÕSÓŽˆXZ[Š
Bˆ
ˆ[žHÚ[ˆ\œÙ\ÈÛÛ[X[™[[™H\™Ý[Y[ËÙ]È\™]ÛÜšÈ[\™˜XÙ\ËÛÛ™šYÝ\™\Èˆ
ˆ\Û[™[œÈHš[X\žHXÚÙ]›ØÙ\ÜÚ[™ÈÛÜ‚ˆ
ˆOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOH
‹Â‚‹ÊˆOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOBˆ
ˆÑPÕSÓŽˆÙ\›™[Q—ÔPÒÑU™Yš[\‚ˆ
ˆ™XÝÜ‹X]Ø\™HÛ\ÜÚXËP”ˆÛÛœÝXÝ[Ûˆ]™\È[ˆ\™ÛÜ×Øœ‹šÛÈHÙ[™\˜]Yˆ
ˆ›ÙÜ˜[HØ[ˆ™H™YÜ™\ÜÚ[Û‹]\ÝYYØZ[œÝÞ[]XÈXÚÙ]š^\™\Ë‚ˆ
ˆOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOH
‹ÂˆÚY›™YˆT‘ÓÔ×ÔÔ•P“WÕTÕš[XZ[Š[\™ØËÚ\ˆ
˜\™Ý–×JHÂˆÛÛœÝÚ\ˆ
šY˜XÙHH˜[žHŽÂˆˆš[\—Ü›ÙÜ˜[WÝš[\—Û[ÙLHHÌNÈˆš[\—Ü›ÙÜ˜[WÝš[\—Û[ÙLˆHÌNÂˆš[\—Ü›ÙÜ˜[WÝš[\—Ù^ÛYHHÌNÂ‚ˆ[X^ÜXÚÙ]ÈHXÚÙ]ØÛÝ[HÂˆ[ÜÜÞ[ˆHÜÛ][HHÜÙÜHÜÛ™]š[ÜÈHÜÙœÈHÜÚHÜÝÈHÜÛˆHÜÝˆHÜÜ›ÛZ\ØÈHÂˆ[ÜÜÞ[—Ü›HÜÛ][WÜ›HÜÙÜÜ›HÜÛ™]š[Ü×Ü›HÜÙœ×Ü›HÜÚÜ›HÜÝ×Ü›HÜÛ—Ü›HÂˆ\™ÛÜ×Ü[[YWØÛÛ™šY×Ý[[YWØÙ™ÎÂˆ\™ÛÜ×Ü[[YWØÛÛ™šY×Ú[š]
	œ[[YWØÙ™ÊNÂˆ[ÜÂˆ[[HÈÔÔÑS”ÓÔˆHLÔÔÑS”ÓÔ—ÓSQKÔÒS”ÒQKÔÑS•T”’TÑKÔÑS•T”’TÑWÕ‘T“ÔÑKÔÕÒT‘QÕPT‘ÔÔ•ÔÒQS•UKÔÒQS•UWÔUÈNÂˆÝ]XÈÛÛœÝÝXÝÜ[ÛˆÛ™×ÛÜ[ÛœÖ×HHÂˆÈœÙ[œÛÜˆ‹›×Ø\™Ý[Y[•SÔÔÑS”ÓÔŸKˆÈœÙ[œÛÜ‹[˜[YH‹™\]Z\™YØ\™Ý[Y[•SÔÔÑS”ÓÔ—ÓSQ_KˆÈš[œÚYH‹™\]Z\™YØ\™Ý[Y[•SÔÒS”ÒQ_KˆÈ™[\œš\ÙH‹›×Ø\™Ý[Y[•SÔÑS•T”’TÑ_KˆÈ™[\œš\ÙK]™\˜›ÜÙH‹›×Ø\™Ý[Y[•SÔÑS•T”’TÑWÕ‘T“ÔÑ_KˆÈÚ\™YÝX\™\Ü‹™\]Z\™YØ\™Ý[Y[•SÔÕÒT‘QÕPT‘ÔÔ•KˆÈšY[]H‹Ü[Û˜[Ø\™Ý[Y[•SÔÒQS•U_KˆÈšY[]K\˜]È‹›×Ø\™Ý[Y[•SÔÒQS•UWÔUßKÊˆÛÛ\]Xš[]H[X\È
‹ÂˆÓ•S•SBˆNÂ‚ˆYˆ
\™ØÈOHJHÈš[Ú[
\™Ý–ÌJNÈ™]\›ˆÈB‚ˆÊˆÓH›YÈÛÛ™[[ÛŽˆ›ÜˆXXÚ[[Y]žHØ]YÛÜžH\™H\ÈHÝÙ\˜Ø\ÙBˆ
ˆ›YÈ
[˜X›H
È˜]K[[Z]YÙY\XØ]YÝ]]H]ZY]Y˜][
Bˆ
ˆ[™[ˆ\\˜Ø\ÙH›YÈ
[˜X›H
È™\˜›ÜÙKÛ›È˜]K[[Z][™Ë›Ü‚ˆ
ˆXYÙÚ[™ÊKˆXH[˜X›\È]™\ž][™È˜]K[[Z]YÈPH[˜X›\È]™\ž][™Âˆ
ˆ™\˜›ÜÙKˆT‹Ë\ˆÛÛ™šYÝ\™HPPÈY™\ÜÈ\ÝÈ
\™ÜÛÙ^ÛYJH˜]\‚ˆ
ˆ[ˆ[[Y]žHØ]YÛÜšY\Ë[™^Ë^‹ËVˆÛÛ\[HØ\\™Hš[\œËˆ
‹ÂˆÚ[H

ÜHÙ]ÜÛÛ™Ê\™ØË\™Ý‹šNœŽ”ŽžžŽ–Ž›ÎN•N˜Î™ŽœÔÛSY“œTZ•œPUÑH‹Û™×ÛÜ[ÛœË•S
JHOHLJHÂˆÝÚ]Ú
Ü
HÂˆØ\ÙHÔÔÑS”ÓÔŽˆÜÜÙ[œÛÜ—Û[ÙHHNÈÜÜ›ÛZ\ØÈHNÈœ™XZÎÂˆØ\ÙHÔÔÑS”ÓÔ—ÓSQN‚ˆYˆ
]˜[YÜÙ[œÛÜ—Û˜[YJÜ\™ÊJHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆK\Ù[œÛÜ‹[˜[YHX^HÛÛZ[ˆÛ›H]\œËYÚ]Ë	Ë‰Ë	×ÉÈ[™	ËIÈ
X^ŒÈÚ\œÊK—ˆŠNÂˆ™]\›ˆNÂˆBˆÛœš[ŠÙ[œÛÜ—Û˜[YKÚ^™[ÙŠÙ[œÛÜ—Û˜[YJK‰\È‹Ü\™ÊNÂˆœ™XZÎÂˆØ\ÙHÔÒS”ÒQNˆYˆ
XYÚ[œÚYWÜ™Yš^
Ü\™ÊJH™]\›ˆNÈœ™XZÎÂˆØ\ÙHÔÑS•T”’TÑNˆ\™ÛÜ×Ü[[YWÙ[˜X›WÙ[\œš\ÙJ	œ[[YWØÙ™Ë
NÈÜÝˆHNÈœ™XZÎÂˆØ\ÙHÔÑS•T”’TÑWÕ‘T“ÔÑNˆ\™ÛÜ×Ü[[YWÙ[˜X›WÙ[\œš\ÙJ	œ[[YWØÙ™ËJNÈÜÝˆHNÈœ™XZÎÂˆØ\ÙHÔÒQS•UN‚ˆYˆ
X\™ÛÜ×ÚY[]WÛ[ÙWÜ\œÙJÜ\™Ë	œ[[YWØÙ™ËšY[]WÛ[ÙJJHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆKZY[]H^XÝÈ\ÚÜˆ˜]È
\ÙHKZY[]OZ\ÚÜˆKZY[]O\˜]ÊK—ˆŠNÂˆ™]\›ˆNÂˆBˆœ™XZÎÂˆØ\ÙHÔÒQS•UWÔUÎ‚ˆÊˆˆÛÛ\]Xš[]H[X\È›ÜˆH›Ü›Y\ˆÙXÛÛ™›YËˆ
‹Âˆ[[YWØÙ™ËšY[]WÛ[ÙHHT‘ÓÔ×ÒQS•UWÔUÎÂˆœ™XZÎÂˆØ\ÙHÔÕÒT‘QÕPT‘ÔÔ•ˆÂˆÚ\ˆ
™[™H•SÈÛ™ÈˆHÝÛ
Ü\™Ë	™[™L
NÂˆYˆ
Y[™
™[™ˆHˆˆMLÍJHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆ[˜[YK]Ú\™YÝX\™\Üˆ	\×ˆ‹Ü\™ÊNÈ™]\›ˆNÂˆBˆ[[YWØÙ™ËÚ\™YÝX\™ÜÜH
Z[M—Ý
]ŽÈ[[YWØÙ™ËÚ\™YÝX\™ÜÜÙ^XÚ]HNÈœ™XZÎÂˆBˆØ\ÙH	ÑIÎˆÜÙ^ÛY]šXÜÈHNÈœ™XZÎÂˆØ\ÙH	ÚIÎˆY˜XÙHHÜ\™ÎÈœ™XZÎÂˆØ\ÙH	Ô‰ÎˆˆYˆ
\™Ù^ÛYWÛXX×ØÛÝ[PVÒT‘ÑVÓQWÓPPÔÊHÂˆZ[Ý\œÙYÛXXÖÍ—NÂˆYˆ
\\œÙWÛXX×ØY™\ÜÊÜ\™Ë\œÙYÛXXÊJHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆ[˜[YPPÈY™\ÜÈ›ÜˆTŽˆ	\×ˆ‹Ü\™ÊNÈ™]\›ˆNÂˆBˆY[XÜJ\™Ù^ÛYWÛXXÜÖÚ\™Ù^ÛYWÛXX×ØÛÝ[K\œÙYÛXXËŠNÂˆ\™Ù^ÛYWÛXX×ØÛÝ[
ÊÎÂˆBˆœ™XZÎÂˆØ\ÙH	Ü‰Î‚ˆYˆ
›Ý]\—ÛXX×ØÛÝ[PVÔ“ÕUT—ÓPPÔÊHÂˆZ[Ý\œÙYÛXXÖÍ—NÂˆYˆ
\\œÙWÛXX×ØY™\ÜÊÜ\™Ë\œÙYÛXXÊJHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆ[˜[YPPÈY™\ÜÈ›Üˆ\Žˆ	\×ˆ‹Ü\™ÊNÈ™]\›ˆNÂˆBˆY[XÜJ›Ý]\—ÛXXÜÖÜ›Ý]\—ÛXX×ØÛÝ[K\œÙYÛXXËŠNÂˆ›Ý]\—ÛXX×ØÛÝ[
ÊÎÂˆBˆœ™XZÎÂˆØ\ÙH	Þ	ÎˆYˆ
ÛÛ\[WÙš[\ŠÜ\™Ë	™š[\—Ù^ÛYJH
H™]\›ˆNÈœ™XZÎÂˆØ\ÙH	Þ‰ÎˆYˆ
ÛÛ\[WÙš[\ŠÜ\™Ë	™š[\—Û[ÙLJH
H™]\›ˆNÈÜÜ›ÛZ\ØÈHNÈœ™XZÎÂˆØ\ÙH	Ö‰ÎˆYˆ
ÛÛ\[WÙš[\ŠÜ\™Ë	™š[\—Û[ÙLŠH
H™]\›ˆNÈœ™XZÎÂˆØ\ÙH	ÛÉÎˆˆYˆ
\×ÜÛØÚÈH
HÛÜÙJ\×ÜÛØÚÊNÈÊˆY™[œÚ]™Nˆ]›ÚYXZÚ[™ÈH™Yˆ[È\ÈÚ]™[ˆ[Ü™H[ˆÛ˜ÙH
‹Âˆ\ÙWÚ\ÈHNÂˆYˆ

\×ÜÛØÚÈHÛØÚÙ]
Q—ÕS’VÓÐÒ×ÑÔSK
JH
HÈ\œ›ÜŠœÛØÚÙ]Q—ÕS’VŠNÈ™]\›ˆNÈBˆY[\Ù]
	š\×ØY‹Ú^™[ÙŠÝXÝÛØÚØY—Ý[ŠJNÂˆ\×ØY‹œÝ[—Ù˜[Z[HHQ—ÕS’VÂˆÝ›˜ÜJ\×ØY‹œÝ[—Ü]Ü\™ËÚ^™[ÙŠ\×ØY‹œÝ[—Ü]
HHJNÂˆœ™XZÎÂˆØ\ÙH	ÝIÎˆÊˆQ[Û›H™[[ÝH[[Y]žHÚ[šËˆ
‹ÂˆYˆ
™[[ÝWÜÛØÚÈH
HÛÜÙJ™[[ÝWÜÛØÚÊNÂˆYˆ
\œÙWÚÜÝÜÜ
Ü\™Ë	œ™[[ÝWØY‹	œ™[[ÝWØY—Û[ŠH
H™]\›ˆNÂˆYˆ

™[[ÝWÜÛØÚÈHÛØÚÙ]
™[[ÝWØY‹œÜ×Ù˜[Z[KÓÐÒ×ÑÔSK
JH
HÈ\œ›ÜŠœÛØÚÙ]]HŠNÈ™]\›ˆNÈBˆ\ÙWÜ™[[ÝHHNÂˆYÛÛ›HHNÂˆœ™XZÎÂˆØ\ÙH	ÕIÎˆÊˆ˜]]™H™[[ÝHÛØÚÙ]ˆÚ\[[Y]žH\™XÝHÈH™[[ÝHQÛÛXÝÜ‹‚ˆ
ˆØ]][ÛŽˆYˆH\Ý[˜][Ûˆ\È™XXÚX›HšXHÛ™HÙˆH[\™˜XÙ\È\Âˆ
ˆ›ØÙ\ÜÈ\È]Ù[ˆØ\\š[™ÈÛˆ
K™ËˆHÐSˆ[\™˜XÙH[ÛÈ\ÜÙYÈZJKˆ
ˆHÝ]ÛÚ[™È[[Y]žH]YÜ˜[\ÈÚ[™Hš\ÚX›HÈHØ\\™HÛÜZÙBˆ
ˆ[žHÝ\ˆ˜Y™šXÎÈ\ÙH^È^ÛYHHÛÛXÝÜ‰ÜÈTÜÜYˆ]ÛÝ[ˆ
ˆÜ™X]H›Ú\ÙHÜˆH™YY˜XÚÈÛÜˆ
‹ÂˆYˆ
™[[ÝWÜÛØÚÈH
HÛÜÙJ™[[ÝWÜÛØÚÊNÈÊˆY™[œÚ]™Nˆ]›ÚYXZÚ[™ÈH™YˆUH\ÈÚ]™[ˆ[Ü™H[ˆÛ˜ÙH
‹ÂˆYˆ
\œÙWÚÜÝÜÜ
Ü\™Ë	œ™[[ÝWØY‹	œ™[[ÝWØY—Û[ŠH
H™]\›ˆNÈÊˆ\œÙWÚÜÝÜÜ

H[™XYHš[YÚH
‹ÂˆYˆ

™[[ÝWÜÛØÚÈHÛØÚÙ]
™[[ÝWØY‹œÜ×Ù˜[Z[KÓÐÒ×ÑÔSK
JH
HÈ\œ›ÜŠœÛØÚÙ]UHŠNÈ™]\›ˆNÈBˆ\ÙWÜ™[[ÝHHNÂˆYÛÛ›HHÂˆœš[ŠÝ\œ‹Ø\›š[™ÎˆUHÝ™X[\È[[Y]žHÈ	\ÈÝ™\ˆZ[ˆQ[™ÝÝ]ÈQ\È[™[˜Üž\Y\ÙHÛ›HÝ™\ˆH\ÝY]—ˆ‹Ü\™ÊNÂˆœ™XZÎÂˆØ\ÙH	ØÉÎˆÈÚ\ˆ
™[™H•SÈÛ™ÈˆHÝÛ
Ü\™Ë	™[™L
NÈYˆ
Y[™
™[™ˆˆˆS•Ì—ÓPV
HÈœš[ŠÝ\œ‹‘\œ›ÜŽˆ[˜[YXÚÙ]ÛÝ[ˆ	\×ˆ‹Ü\™ÊNÈ™]\›ˆNÈHX^ÜXÚÙ]ÈH
[
]ŽÈœ™XZÎÈBˆØ\ÙH	Ù‰ÎˆÈÚ\ˆ
™[™H•SÈÛ™ÈˆHÝÛ
Ü\™Ë	™[™L
NÈYˆ
Y[™
™[™ˆˆˆS•Ì—ÓPV
HÈœš[ŠÝ\œ‹‘\œ›ÜŽˆ[˜[YY\XØ][ÛˆÚ[™ÝÎˆ	\×ˆ‹Ü\™ÊNÈ™]\›ˆNÈH˜]WÛ[Z]ÝH
[
]ŽÈœ™XZÎÈBˆØ\ÙH	Ü	ÎˆÜÜ›ÛZ\ØÈHNÈœ™XZÎÂˆØ\ÙH	ÜÉÎˆÜÜÞ[ˆHNÈÜÜÞ[—Ü›HNÈœ™XZÎÂˆØ\ÙH	ÔÉÎˆÜÜÞ[ˆHNÈÜÜÞ[—Ü›HÈœ™XZÎÂˆØ\ÙH	ÛIÎˆÜÛ][HHNÈÜÛ][WÜ›HNÈœ™XZÎÂˆØ\ÙH	ÓIÎˆÜÛ][HHNÈÜÛ][WÜ›HÈœ™XZÎÂˆØ\ÙH	Ù	ÎˆÜÙÜHNÈÜÙÜÜ›HNÈœ™XZÎÂˆØ\ÙH	Ñ	ÎˆÜÙÜHNÈÜÙÜÜ›HÈœ™XZÎÂˆØ\ÙH	Û‰ÎˆÜÛ™]š[ÜÈHNÈÜÛ™]š[Ü×Ü›HNÈœ™XZÎÂˆØ\ÙH	Ó‰ÎˆÜÛ™]š[ÜÈHNÈÜÛ™]š[Ü×Ü›HÈœ™XZÎÂˆØ\ÙH	ÜIÎˆÜÙœÈHNÈÜÙœ×Ü›HNÈœ™XZÎÂˆØ\ÙH	ÔIÎˆÜÙœÈHNÈÜÙœ×Ü›HÈœ™XZÎÂˆØ\ÙH	Ú	ÎˆÜÚHNÈÜÚÜ›HNÈœ™XZÎÂˆØ\ÙH	Ò	ÎˆÜÚHNÈÜÚÜ›HÈœ™XZÎÂˆØ\ÙH	Ý	ÎˆÜÝÈHNÈÜÝ×Ü›HNÈœ™XZÎÂˆØ\ÙH	Õ	ÎˆÜÝÈHNÈÜÝ×Ü›HÈœ™XZÎÂˆØ\ÙH	Û	ÎˆÜÛˆHNÈÜÛ—Ü›HNÈœ™XZÎÂˆØ\ÙH	Ó	ÎˆÜÛˆHNÈÜÛ—Ü›HÈœ™XZÎÂˆØ\ÙH	Ý‰Î‚ˆØ\ÙH	Õ‰ÎˆÜÝˆHNÈœ™XZÎÂˆØ\ÙH	ØIÎ‚ˆÜÜÞ[ˆHÜÛ][HHÜÙÜHÜÛ™]š[ÜÈHÜÙœÈHÜÚHÜÝÈHÜÛˆHNÂˆÜÜÞ[—Ü›HÜÛ][WÜ›HÜÙÜÜ›HÜÛ™]š[Ü×Ü›HÜÙœ×Ü›HÜÚÜ›HÜÝ×Ü›HÜÛ—Ü›HNÂˆÜÝˆHNÈœ™XZÎÂˆØ\ÙH	ÐIÎ‚ˆÜÜÞ[ˆHÜÛ][HHÜÙÜHÜÛ™]š[ÜÈHÜÙœÈHÜÚHÜÝÈHÜÛˆHNÂˆÜÜÞ[—Ü›HÜÛ][WÜ›HÜÙÜÜ›HÜÛ™]š[Ü×Ü›HÜÙœ×Ü›HÜÚÜ›HÜÝ×Ü›HÜÛ—Ü›HÂˆÜÝˆHNÈœ™XZÎÂˆØ\ÙH	ÕÉÎˆÜÜ]ZX×ÚX]žHHNÈœ™XZÎÈˆY˜][ˆš[Ú[
\™Ý–ÌJNÈ™]\›ˆNÂˆBˆB‚ˆYˆ
Ü[™\™ØÊHÂˆY˜XÙHH\™Ý–ÛÜ[™
Ê×NÂˆÜÜÞ[ˆHÜÛ][HHÜÙÜHÜÛ™]š[ÜÈHÜÙœÈHÜÚHÜÝÈHÜÛˆHNÂˆÜÜÞ[—Ü›HÜÛ][WÜ›HÜÙÜÜ›HÜÛ™]š[Ü×Ü›HÜÙœ×Ü›HÜÚÜ›HÜÝ×Ü›HÜÛ—Ü›HNÂˆÜÝˆHNÂˆB‚ˆYˆ
Ü[™\™ØÊHÈœš[ŠÝ\œ‹‘\œ›ÜŽˆ[œ™XÛÙÛš^™Y^˜H\™Ý[Y[—ˆŠNÈ™]\›ˆNÈB‚ˆYˆ
[ÜÜÙ[œÛÜ—Û[ÙH	‰ˆ
Ù[œÛÜ—Û˜[YVÌHÛÛ™šYÝ\™YÚ[œÚYWØÛÝ[ˆ
JHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆK\Ù[œÛÜ‹[˜[YKËKZ[œÚYH™\]Z\™HK\Ù[œÛÜ‹—ˆŠNÂˆ™]\›ˆNÂˆBˆYˆ
ÜÜÙ[œÛÜ—Û[ÙJHÂˆYˆ
\Ù[œÛÜ—Û˜[YVÌJHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆK\Ù[œÛÜˆ™\]Z\™\ÈK\Ù[œÛÜ‹[˜[YK—ˆŠNÂˆ™]\›ˆNÂˆBˆYˆ
Ý˜Ø\ÙXÛ\
Y˜XÙK˜[žHŠHOH
HÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆK\Ù[œÛÜˆ™\]Z\™\È[ˆ^XÚ]ÔS‹ÕT[\™˜XÙHšXHZH
›Ý	Ø[žIÊK—ˆŠNÂˆ™]\›ˆNÂˆBˆB‚ˆÛÛœÝÚ\ˆ
œ[[YWØÙ™×Ù\œ›ÜˆH\™ÛÜ×Ü[[YWØÛÛ™šY×Ý˜[Y]J	œ[[YWØÙ™ÊNÂˆYˆ
[[YWØÙ™×Ù\œ›ÜŠHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆ	\×ˆ‹[[YWØÙ™×Ù\œ›ÜŠNÂˆ™]\›ˆNÂˆB‚ˆYˆ
š[\—Û[ÙLKš\×ØXÝ]™H	‰ˆš[\—Û[ÙL‹š\×ØXÝ]™JHÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ^ˆ[™Vˆ›ÝÚ]™[ŽÈVˆYÛ›Ü™Y[ˆ]™HÛšY™™\ˆ[ÙK—ˆŠNÂˆB‚ˆYˆ
ÜÙ^ÛY]šXÜÊHÂˆÞ[—ÝX›HH
Þ[—Ý˜XÚ×Ý
ŠXØ[ØÊPÒ×ÔÓÕËÚ^™[ÙŠ
œÞ[—ÝX›JJNÂˆœ×ÝX›HH
\™ÛÜ×Ùœ×Ý˜XÚ×Ý
ŠXØ[ØÊPÒ×ÔÓÕËÚ^™[ÙŠ
™œ×ÝX›JJNÂˆYˆ
\Þ[—ÝX›HYœ×ÝX›JHÂˆœš[ŠÝ\œ‹‘\œ›ÜŽˆ[˜X›HÈ[ØØ]H^[™Y[Y]šXÜÈÝ]K—ˆŠNÂˆœ™YJÞ[—ÝX›JNÈœ™YJœ×ÝX›JNÈ\™ÛÜ×ÙY\Ù\Ý›ÞJ	™Y\ÜÝ]JNÈœ™YJÝÛ™\ÝX›JNÈœ™YJÝÛ™\—ÝX›JNÈ™]\›ˆNÂˆBˆB‚ˆYˆ
Yš[\—Û[ÙLKš\×ØXÝ]™H	‰ˆ[ÜÜÞ[ˆ	‰ˆ[ÜÛ][H	‰ˆ[ÜÙÜ	‰ˆ[ÜÛ™]š[ÜÈ	‰ˆ[ÜÙœÈ	‰ˆ[ÜÚ	‰ˆ[ÜÝÈ	‰ˆ[ÜÛˆ	‰ˆ\[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y
HÂˆÜÜÞ[ˆHÜÛ][HHÜÙÜHÜÛ™]š[ÜÈHNÂˆÜÜÞ[—Ü›HÜÛ][WÜ›HÜÙÜÜ›HÜÛ™]š[Ü×Ü›HNÂˆÜÝˆHNÂˆB‚ˆ\™ÛÜ×Øœ—ØÛÛ™šY×Ýœ—ØÙ™ÈHÂˆœÞ[ˆH
Z[Ý
JÜÜÞ[ˆOH
K›][HH
Z[Ý
JÜÛ][HOH
Kˆ™ÜH
Z[Ý
JÜÙÜOH
K›™]š[ÜÈH
Z[Ý
JÜÛ™]š[ÜÈOH
Kˆ™œÈH
Z[Ý
JÜÙœÈOH
KšH
Z[Ý
JÜÚOH
KˆÈH
Z[Ý
JÜÝÈOH
K›ˆH
Z[Ý
JÜÛˆOH
Kˆš\ˆH
Z[Ý
JÜÝˆOH
K™[\œš\ÙHH
Z[Ý
J[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›YOH
KˆÚ\™YÝX\™ÜÜH
Z[M—Ý
J[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›YÈ[[YWØÙ™ËÚ\™YÝX\™ÜÜˆJBˆNÂ‚ˆ[œÝ[ÜÚYÛ˜[Ú[™\œÊ
NÂ‚ˆ[\ÛÙ™H\ÛØÜ™X]LJ
NÂˆYˆ
\ÛÙ™
HÈ\œ›ÜŠ™\ÛØÜ™X]LHŠNÈ™]\›ˆNÈBˆ[[—Û™][š×Ù™HLNÂ‚ˆÊˆZHZÙ\ÈHÛÛ[XK\Ù\\˜]Y[\™˜XÙH\Ý
K™Ëˆ™]Û[ŒŠNÈXZÙHBˆ
ˆ]]X›HÛÜHÚ[˜ÙHÝÚÊ
HÜš]\È	×	ÈÙ\\˜]ÜœÈ[È][ˆXÙKˆ
‹ÂˆÚ\ˆ
šY˜XÙWÛ\ÝHÝ™\
Y˜XÙJNÂˆYˆ
ZY˜XÙWÛ\Ý
HÈœš[ŠÝ\œ‹‘\œ›ÜŽˆÝ]ÙˆY[[ÜžH\XØ][™È[\™˜XÙH\Ý—ˆŠNÈ™]\›ˆNÈBˆÚ\ˆ
ÚÙ[ˆHÝÚÊY˜XÙWÛ\Ý‹ŠNÂˆˆÊˆÜ[ˆÛ™HQ—ÔPÒÑU˜]ÈÛØÚÙ]\ˆ™\]Y\ÝY[\™˜XÙH
ÜˆHÜXÚX[ˆ
ˆ˜[žHˆÙ]YËZ[\™˜XÙKÚXÚØ\\™\ÈÛˆ[[\™˜XÙ\È]Û˜ÙH\Ú[™Âˆ
ˆ[^	ÜÈ˜ÛÛÚÙYˆÓœ˜[Z[™È[œÝXYÙˆH™X[[šË[^Y\ˆXY\ŠH[™ˆ
ˆ™YÚ\Ý\ˆXXÚÚ]\ÛÛÈHXZ[ˆÛÜØ[ˆ][\^™]ÙY[ˆ[Kˆ
‹ÂˆÚ[H
ÚÙ[ˆOH•S	‰ˆ[WÚY˜XÙ\ÈPVÒS•T‘PÑTÊHÂˆ[ÛØÚÈHÛØÚÙ]
Q—ÔPÒÑUÓÐÒ×ÔUËÛœÊUÔÐS
JNÂˆYˆ
ÛØÚÈ
HÈÚÙ[ˆHÝÚÊ•S‹ŠNÈÛÛ[YNÈB‚ˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K™™HÛØÚÎÂˆÝ›˜ÜJXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K›˜[YKÚÙ[‹Q“STÒVˆHJNÂˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K›˜[YVÒQ“STÒVˆHWHH	×	ÎÂ‚ˆÝXÝÛØÚØY—ÛÛÈY[\Ù]
	œÛÚ^™[ÙŠÛ
JNÂˆÛœÛÙ˜[Z[HHQ—ÔPÒÑUÂˆÛœÛÜ›ÝØÛÛHÛœÊUÔÐS
NÂ‚ˆYˆ
Ý˜Ø\ÙXÛ\
ÚÙ[‹˜[žHŠHOH
HÂˆÊˆÓÐÒ×ÔUÈ
ÈYš[™^[]™\œÈ˜]]™Hˆœ˜[Z[™Ëˆ™\ÛÛ™HBˆ
ˆXÝX[[šÈ\Hœ›ÛHÛØÚØY—Û›ÜˆXXÚ™XÙZ]™YXÚÙ]ˆ
‹ÂˆYˆ
[WÚY˜XÙ\Èˆ
HÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ	Ø[žIÈÚÝ[›Ý™HÛÛXš[™YÚ]^XÚ][\™˜XÙ\ÎÈÚÚ\[™È	É\É×ˆ‹ÚÙ[ŠNÂˆÛÜÙJÛØÚÊNÈÚÙ[ˆHÝÚÊ•S‹ŠNÈÛÛ[YNÂˆBˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×KšYš[™^HÂˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K\HHS’×ÔT—ÔPÒÑUÂˆÛœÛÚYš[™^HÂˆH[ÙHÂˆÝXÝYœ™\HYœŽÈY[\Ù]
	šYœ‹Ú^™[ÙŠYœŠJNÂˆÝ›˜ÜJYœ‹šYœ—Û˜[YKÚÙ[‹Q“STÒVˆHJNÂˆYˆ
[ØÝ
ÛØÚËÒSÐÑÒQ’S‘V	šYœŠH
HÈÛÜÙJÛØÚÊNÈÚÙ[ˆHÝÚÊ•S‹ŠNÈÛÛ[YNÈBˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×KšYš[™^HYœ‹šYœ—ÚYš[™^ÂˆÛœÛÚYš[™^HYœ‹šYœ—ÚYš[™^Â‚ˆYˆ
[ØÝ
ÛØÚËÒSÐÑÒQ’ÐQ‹	šYœŠHOH
HÂˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K\HH]\WÝ×Û[šÊ
[œÚYÛ™YÚÜ
ZYœ‹šYœ—ÚØY‹œØWÙ˜[Z[JNÂˆH[ÙHÂˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K\HHS’×ÕS”ÕTÔ•QÂˆBˆYˆ
XÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K\HOHS’×ÕS”ÕTÔ•Q
HÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ[œÝ\ÜY[šË[^Y\ˆ\HÛˆ	\ÎÈÚÚ\[™×ˆ‹ÚÙ[ŠNÂˆÛÜÙJÛØÚÊNÈÚÙ[ˆHÝÚÊ•S‹ŠNÈÛÛ[YNÂˆBˆBˆˆYˆ
š[™
ÛØÚË
ÝXÝÛØÚØYˆ
ŠIœÛÚ^™[ÙŠÛ
JH
HÈÛÜÙJÛØÚÊNÈÚÙ[ˆHÝÚÊ•S‹ŠNÈÛÛ[YNÈB‚ˆYˆ
XÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K\HOHS’×ÑUT“‘U	‰ˆYš[\—Û[ÙLKš\×ØXÝ]™JHÂˆYˆ
\™ÛÜ×Øœ—Ø]XÚ
ÛØÚË	˜œ—ØÙ™ÊH
HÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ[˜X›HÈ]XÚ™XÝÜ‹X]Ø\™HQ—ÔPÒÑU™Yš[\ˆÛˆ	\Îˆ	\×ˆ‹ˆÚÙ[‹Ý™\œ›ÜŠ\œ››ÊJNÂˆBˆB‚ˆYˆ
ÜÜ›ÛZ\ØÈ	‰ˆXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×K\HOHS’×ÑUT“‘U
HÂˆÝXÝXÚÙ]Û\™\H\ŽÈY[\Ù]
	›\‹Ú^™[ÙŠ\ŠJNÂˆ\‹›\—ÚYš[™^HXÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×KšYš[™^È\‹›\—Ý\HHPÒÑUÓT—Ô“ÓRTÐÎÂˆÙ]ÛØÚÛÜ
ÛØÚËÓÓÔPÒÑUPÒÑUÐQÓQSP‘T”ÒT	›\‹Ú^™[ÙŠ\ŠJNÂˆB‚ˆ[˜Ý˜YˆHˆ
ˆL
ˆLÈÙ]ÛØÚÛÜ
ÛØÚËÓÓÔÓÐÒÑUÓ×ÔÕ•Q‹	œ˜Ý˜Y‹Ú^™[ÙŠ˜Ý˜YŠJNÂˆ[Û™HHNÂˆÙ]ÛØÚÛÜ
ÛØÚËÓÓÔPÒÑUPÒÑUÐUVUK	›Û™KÚ^™[ÙŠÛ™JJNÈÊˆ™XÛÝ™\ˆË\Ýš\Y“Sˆ
‹ÂˆÚY™YˆÓ×ÕSQTÕST”ÂˆÙ]ÛØÚÛÜ
ÛØÚËÓÓÔÓÐÒÑUÓ×ÕSQTÕST”Ë	›Û™KÚ^™[ÙŠÛ™JJNÂˆÙ[™Y‚ˆÝXÝ\ÛÙ]™[]ŽÈY[\Ù]
	™]‹Ú^™[ÙŠ]ŠJNÈ]‹™]™[ÈHTÓSŽÈ]‹™]KœˆH	˜XÝ]™WÚY˜XÙ\ÖÛ[WÚY˜XÙ\×NÂˆYˆ
\ÛØÝ
\ÛÙ™TÓÐÕÐQÛØÚË	™]ŠH
HÂˆ\œ›ÜŠ™\ÛØÝŠNÈÛÜÙJÛØÚÊNÈÚÙ[ˆHÝÚÊ•S‹ŠNÈÛÛ[YNÂˆB‚ˆ[WÚY˜XÙ\ÊÊÎÈÚÙ[ˆHÝÚÊ•S‹ŠNÂˆBˆœ™YJY˜XÙWÛ\Ý
NÂˆYˆ
ÜÜ›ÛZ\ØÈ	‰ˆ[WÚY˜XÙ\ÈOHH	‰ˆXÝ]™WÚY˜XÙ\ÖÌK\HOHS’×ÔT—ÔPÒÑU
HÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ›ÛZ\ØÝ[Ý\È[ÙHÚ]ZH[žH\È›Ý[˜X›YÛØ˜[NÈ\ÙH^XÚ][\™˜XÙ\ÈÚ]\›Üˆ[ˆš\ÚXš[]WˆŠNÂˆB‚ˆYˆ
[WÚY˜XÙ\ÈOH
HÈœš[ŠÝ\œ‹“›È˜[Y[\™˜XÙ\È›Ý[™ˆ^][™Ë—ˆŠNÈ™]\›ˆNÈBˆX\›—Û[—Ü™Yš^\Ê
NÂ‚ˆ[—Û™][š×Ù™H[—Û™][š×ÛÜ[Š
NÂˆYˆ
[—Û™][š×Ù™H
HÂˆÝXÝ\ÛÙ]™[™]ŽÂˆY[\Ù]
	›™]‹Ú^™[ÙŠ™]ŠJNÂˆ™]‹™]™[ÈHTÓSŽÂˆ™]‹™]KœˆH	›[—Û™][š×Ù\ÛÝYÎÂˆYˆ
\ÛØÝ
\ÛÙ™TÓÐÕÐQ[—Û™][š×Ù™	›™]ŠH
HÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ[˜X›HÈY›Ý]K[™][šÈ\Ý[™\ˆÈ\Ûˆ	\×ˆ‹Ý™\œ›ÜŠ\œ››ÊJNÂˆÛÜÙJ[—Û™][š×Ù™
NÂˆ[—Û™][š×Ù™HLNÂˆBˆH[ÙHÂˆœš[ŠÝ\œ‹Ø\›š[™Îˆ›Ý]K[™][šÈ™Yš^™Yœ™\Ú[˜]˜Z[X›Nˆ	\×ˆ‹Ý™\œ›ÜŠ\œ››ÊJNÂˆB‚ˆÊˆÙY\ÝÝ][™KXY™™\™YÚ[™]™\ˆ]\ÈXÝ]™KˆÚ]UH]\ÈBˆ
ˆ[X™\˜]HØØ[˜[‹[Ý][Û™ÜÚYHH™[[ÝHQÚ[šËˆ
‹ÂˆYˆ
]\ÙWÚ\È\ÙWÜ™[[ÝJHÙ]˜YŠÝÝ]•SÒSÓ‘‹
NÂ‚ˆÝXÝ\ÛÙ]™[]™[ÖÓPVÑTÓÑU‘S•×NÂˆ[œÚYÛ™YÚ\ˆY™™\–ÐÐTT‘WÐ•Q—NÂ‚ˆÊˆXZ[ˆXÚÙ]Ø\\™H[™›ØÙ\ÜÚ[™ÈÛÜ
‹ÂˆÚ[H
[›š[™ÊHÂˆÝ]XÈZ[Ý\ÝÙØÈH\ÝÜÝ]ÈHX^ÛÛÜÝ\ÈHÂˆZ[Ý›Ý×Ý\ÈHÙ]ØÝ\œ™[Ý\ÙXÊ
NÂˆYˆ
ÜÜ]ZX×ÚX]žH	‰ˆ
›Ý×Ý\ÈH\ÝÙØÈˆŒS
JHÂˆ]ZX×ÚX]žWÙØÊ
NÂˆ\ÝÙØÈH›Ý×Ý\ÎÂˆBˆYˆ
›Ý×Ý\ÈH\ÝÜÝ]ÈˆLS
HÂˆ›Üˆ
[ÚHHÈÚH[WÚY˜XÙ\ÎÈÚJÊÊHÂˆÝXÝXÚÙ]ÜÝ]ÈÝÈY[\Ù]
	œÝÚ^™[ÙŠÝ
JNÂˆÛØÚÛ[—ÝÛHÚ^™[ÙŠÝ
NÂˆYˆ
Ù]ÛØÚÛÜ
XÝ]™WÚY˜XÙ\ÖÜÚWK™™ÓÓÔPÒÑUPÒÑUÔÕUTÕPÔË	œÝ	œÛ
HOH
HÂˆXÝ]™WÚY˜XÙ\ÖÜÚWKÝ[ÜXÚÙ]È
ÏHÝÜXÚÙ]ÎÂˆXÝ]™WÚY˜XÙ\ÖÜÚWKÝ[Ù›ÜÈ
ÏHÝÙ›ÜÎÂˆÊˆÙY\™\Ù][Û‹\™XYXØÛÝ[[™ÈÛÛ[[Ý\ÛK]]›ÚYBˆ
ˆ™\›ËY›ÜX\™X][ˆÞ\ÛÙÈ]™\žH[ˆÙXÛÛ™Ëˆ
‹ÂˆYˆ
ÝÙ›ÜÊHÂˆÝX›H›ÜÜÝHÝÜXÚÙ]ÈÈ
LŒ
ˆ
ÝX›J\ÝÙ›ÜÈÈ
ÝX›J\ÝÜXÚÙ]ÊHˆŒÂˆœš[ŠÝ\œ‹˜\™ÛÜÎˆ	\ÈÝÏI]H›ÜÏI]H›ÜIKŒ™‰IHÝ[ÜÝÏI[HÝ[Ù›ÜÏI[H‹ˆXÝ]™WÚY˜XÙ\ÖÜÚWK›˜[YKÝÜXÚÙ]ËÝÙ›ÜË›ÜÜÝˆ
[œÚYÛ™YÛ™ÈÛ™ÊXXÝ]™WÚY˜XÙ\ÖÜÚWKÝ[ÜXÚÙ]Ëˆ
[œÚYÛ™YÛ™ÈÛ™ÊXXÝ]™WÚY˜XÙ\ÖÜÚWKÝ[Ù›ÜÊNÂˆYˆ
ÜÝŠHœš[ŠÝ\œ‹ˆX^ÛÛÜÝ\ÏI[H‹
[œÚYÛ™YÛ™ÈÛ™Ê[X^ÛÛÜÝ\ÊNÂˆœ]Ê	×‰ËÝ\œŠNÂˆBˆBˆBˆYˆ
ÜÝŠHX^ÛÛÜÝ\ÈHÂˆ\ÝÜÝ]ÈH›Ý×Ý\ÎÂˆBˆ[™™ÈH\ÛÝØZ]
\ÛÙ™]™[ËPVÑTÓÑU‘S•ËL
NÂˆYˆ
™™È	‰ˆ\œ››ÈOHRS•ŠHœ™XZÎÂˆZ[Ý›ØÙ\ÜÚ[™×ÜÝ\Ý\ÈHÜÝˆÈÙ]ØÝ\œ™[Ý\ÙXÊ
HˆÂ‚ˆ›Üˆ
[HHÈH™™ÎÈJÊÊHÂˆYˆ
]™[ÖÚWK™]KœˆOH	›[—Û™][š×Ù\ÛÝYÊHÂˆYˆ
[—Û™][š×Ù™H	‰ˆ[—Û™][š×Ù˜Z[Š[—Û™][š×Ù™
JBˆX\›—Û[—Ü™Yš^\Ê
NÂˆÛÛ[YNÂˆB‚ˆØ\\™WÚY˜XÙWÝ
˜Ý\œ™[ÚY˜XÙHH
Ø\\™WÚY˜XÙWÝ
ŠY]™[ÖÚWK™]KœŽÂ‚ˆÝXÝÛØÚØY—Ûœ›ÛWÛÂˆY[\Ù]
	™œ›ÛWÛÚ^™[ÙŠœ›ÛWÛ
JNÂˆÝXÝ[Ý™XÈ[ÝŽÂˆ[Ý‹š[Ý—Ø˜\ÙHHY™™\ŽÂˆ[Ý‹š[Ý—Û[ˆHÚ^™[ÙŠY™™\ŠNÂˆÚ\ˆÛ\Ù×ØY–ÐÓTÑ×ÔÔPÑJÚ^™[ÙŠÝXÝXÚÙ]Ø]^]JJH
ÈÓTÑ×ÔÔPÑJÚ^™[ÙŠÝXÝ[Y\ÜXÊJWNÂˆÝXÝ\ÙÚˆ\ÙÎÂˆY[\Ù]
	›\ÙËÚ^™[ÙŠ\ÙÊJNÂˆ\ÙË›\Ù×Û˜[YHH	™œ›ÛWÛÂˆ\ÙË›\Ù×Û˜[Y[[ˆHÚ^™[ÙŠœ›ÛWÛ
NÂˆ\ÙË›\Ù×Ú[ÝˆH	š[ÝŽÂˆ\ÙË›\Ù×Ú[Ý›[ˆHNÂˆ\ÙË›\Ù×ØÛÛ›ÛHÛ\Ù×ØYŽÂˆ\ÙË›\Ù×ØÛÛ›Û[ˆHÚ^™[ÙŠÛ\Ù×ØYŠNÂ‚ˆÜÚ^™WÝ[ˆH™XÝ›\ÙÊÝ\œ™[ÚY˜XÙKO™™	›\ÙËTÑ×Õ•SÊNÂˆYˆ
[ˆH
HÛÛ[YNÂˆYˆ

Ú^™WÝ
[[ˆˆÚ^™[ÙŠY™™\ŠJH[ˆHÚ^™[ÙŠY™™\ŠNÂ‚ˆZ[ÝÝÝ\ÙXÈHÂˆZ[M—Ý]^Ý›[ˆHÂˆ[]^Ý›[—Ý˜[YHÂˆ›Üˆ
ÝXÝÛ\ÙÚˆ
˜ÈHÓTÑ×Ñ’T”ÕŠ	›\ÙÊNÈÎÈÈHÓTÑ×Ó–Š	›\ÙËÊJHÂˆÚY™YˆÓ×ÕSQTÕST”ÂˆYˆ
ËO˜Û\Ù×Û]™[OHÓÓÔÓÐÒÑU	‰ˆËO˜Û\Ù×Ý\HOHÓ×ÕSQTÕST”ÊHÂˆÝXÝ[Y\ÜXÈÎÂˆY[XÜJ	ËÓTÑ×ÑUJÊKÚ^™[ÙŠÊJNÂˆÝÝ\ÙXÈH
Z[Ý
]Ë—ÜÙXÈ
ˆLS
È
Z[Ý
]Ë—ÛœÙXÈÈLSÂˆBˆÙ[™Y‚ˆYˆ
ËO˜Û\Ù×Û]™[OHÓÓÔPÒÑU	‰ˆËO˜Û\Ù×Ý\HOHPÒÑUÐUVUH	‰‚ˆËO˜Û\Ù×Û[ˆHÓTÑ×ÓSŠÚ^™[ÙŠÝXÝXÚÙ]Ø]^]JJJHÂˆÝXÝXÚÙ]Ø]^]H]^ÂˆY[XÜJ	˜]^ÓTÑ×ÑUJÊKÚ^™[ÙŠ]^
JNÂˆYˆ
]^ÜÝ]\È	ˆÔÕUT×Õ“S—ÕSQ
HÂˆ]^Ý›[ˆH
Z[M—Ý
J]^Ý›[—ÝÚH	ˆ™™•JNÂˆ]^Ý›[—Ý˜[YHNÂˆBˆBˆBˆYˆ
ÝÝ\ÙXÈOH
HÝÝ\ÙXÈHÙ]ØÝ\œ™[Ý\ÙXÊ
NÂ‚ˆ[š×Ý\WÝÝÝ\HHÝ\œ™[ÚY˜XÙKO\NÂˆYˆ
ÝÝ\HOHS’×ÔT—ÔPÒÑU
HÝÝ\HH]\WÝ×Û[šÊœ›ÛWÛœÛÚ]\JNÂˆÊˆHÛØÚÙ]›Ý[™È[ˆ^XÚ]œšYÙH\ÈÛ\ÜÚYšYYYØZ[œÝ]ˆ
ˆœšYÙIÜÈÛÛ›™XÝY™Yš^\ËˆÛÛYHÙ\›™[È™\ÜH[™Ü™\ÜÂˆ
ˆœšYÙK\ÜYš[™^[ˆÛØÚØY—ÛÈ\Ú[™È]XYH˜[YÙ™‹[[šÂˆ
ˆTˆÛÝ\˜Ù\ÈZ\ÜÈHœ‹[[ˆ™Yš^ÛÛ^ˆ[žXÝ[\Ù\ÈBˆ
ˆXÝX[\‹\XÚÙ]Yš[™^È]›ÚYÜ›ÜÜËZ[\™˜XÙH˜[ÙHÜÚ]]™\Ëˆ
‹Âˆ[XÚÙ]ÚYš[™^H™Yš^ØÛÛ^ÚYš[™^
Ý\œ™[ÚY˜XÙKœ›ÛWÛœÛÚYš[™^
NÂ‚ˆ\™ÛÜ×ÜXÚÙ]ÝšY]×ÝXÚÙ]ÝšY]ÎÂˆYˆ
X\™ÛÜ×ÜXÚÙ]ÙXÛÙJÝÝ\KY™™\‹
[
[[‹ÜÝ‹	œXÚÙ]ÝšY]ÊJHÛÛ[YNÂ‚ˆ[œÚYÛ™YÚ\ˆ
œÜ˜×ÛXXÈHXÚÙ]ÝšY]ËœÜ˜×ÛXXÎÂˆ[œÚYÛ™YÚ\ˆ
™ÝÛXXÈHXÚÙ]ÝšY]Ë™ÝÛXXÎÂˆZ[M—Ý×Ü›ÝÈHXÚÙ]ÝšY]Ë›×Ü›ÝÎÂˆ[×ÛÙ™œÙ]HXÚÙ]ÝšY]Ë›×ÛÙ™œÙ]Â‚ˆYˆ
ÜÜÙ[œÛÜ—Û[ÙJHÂˆZ[M—ÝÝ]\ˆHXÚÙ]ÝšY]Ë›Ý]\—Ý›[ŽÂˆZ[M—Ý[›™\ˆHXÚÙ]ÝšY]Ëš[›™\—Ý›[ŽÂˆYˆ
]^Ý›[—Ý˜[Y
HÂˆYˆ
Ý]\ˆOHJHÝ]\ˆH]^Ý›[ŽÂˆ[ÙHYˆ
]^Ý›[ˆOHÝ]\ŠHÈ[›™\ˆHÝ]\ŽÈÝ]\ˆH]^Ý›[ŽÈBˆBˆÛœš[ŠÙ[œÛÜ—ÛØœÙ\˜][Û—ÚY˜XÙKÚ^™[ÙŠÙ[œÛÜ—ÛØœÙ\˜][Û—ÚY˜XÙJK‰\È‹Ý\œ™[ÚY˜XÙKO›˜[YJNÂˆÙ[œÛÜ—ÛØœÙ\˜][Û—ÛÝ]\—Ý›[ˆHÝ]\ŽÂˆÙ[œÛÜ—ÛØœÙ\˜][Û—Ú[›™\—Ý›[ˆH[›™\ŽÂˆB‚ˆÝ]XÈÛÛœÝ[œÚYÛ™YÚ\ˆ™\›×ÛXXÖÍ—HHÌNÂˆÝ]XÈÛÛœÝ[œÚYÛ™YÚ\ˆ˜Ø\ÝÛXXÖÍ—HHÌ™‹™‹™‹™‹™‹™ŸNÂˆÊˆU×ÒT
ÕS‹ÕÚ\™QÝX\™
H\È›ÈPPËÛÈ™\›ËSPPÈ˜[Y][Û‚ˆ
ˆ\Y\ÈÛ›HÈ]\›™][™ÛÛÚÙY[šË[^Y\ˆœ˜[Y\Ëˆ
‹ÂˆYˆ
ÝÝ\HOHS’×ÑUT“‘UÝÝ\HOHS’×ÐÓÓÒÑQ
HÂˆYˆ
Y[XÛ\
Ü˜×ÛXXË™\›×ÛXXËŠHOHY[XÛ\
Ü˜×ÛXXË˜Ø\ÝÛXXËŠHOH
HÛÛ[YNÂˆB‚ˆZ[Ì—ÝÜ˜×Ú\Û[HHÝÚ\Û[HHÂˆ[\×ÛÝ]›Ý[™HÂˆ[ÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]YHÂˆÝXÝ[—ØYˆÜ˜×Ú\—ØY‹ÝÚ\—ØYŽÂˆY[\Ù]
	œÜ˜×Ú\—ØY‹Ú^™[ÙŠÜ˜×Ú\—ØYŠJNÂˆY[\Ù]
	™ÝÚ\—ØY‹Ú^™[ÙŠÝÚ\—ØYŠJNÂˆ[\×Ú\—ÜXÚÙ]HXÚÙ]ÝšY]Ëš\Ý™\œÚ[ÛˆOH•NÂˆ[\×Ú\ÜXÚÙ]HXÚÙ]ÝšY]Ëš\×Ú\ÂˆZ[Ý\Ü›ÝØÛÛHXÚÙ]ÝšY]Ëš\Ü›ÝØÛÛÂˆZ[Ý\ÝHXÚÙ]ÝšY]Ëš\ÝÂˆ[ÛÙ™œÙ]HXÚÙ]ÝšY]Ë›ÛÙ™œÙ]Âˆ[\Ú\×Ùœ˜YÈHXÚÙ]ÝšY]Ë››Û™š\œÝÙœ˜YÛY[Â‚ˆYˆ
XÚÙ]ÝšY]Ëš\Ý™\œÚ[ÛˆOHJHÂˆY[XÜJ	œÜ˜×Ú\Û[KXÚÙ]ÝšY]ËœÜ˜×ØY‹JNÂˆY[XÜJ	™ÝÚ\Û[KXÚÙ]ÝšY]Ë™ÝØY‹JNÂˆ[Ü˜×Û[ˆH\×Û[—Ú\
Ü˜×Ú\Û[JNÂˆ[ÝÛ[ˆH\×Û[—Ú\
ÝÚ\Û[JNÂˆÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]YH\×Ü›Ý]YÜÛÝ\˜ÙWÚ\
Ü˜×Ú\Û[KXÚÙ]ÚYš[™^
NÂˆYˆ
\Ü˜×Û[ˆ	‰ˆYÝÛ[ˆ	‰ˆ\ÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]Y
HÛÛ[YNÂˆ\×ÛÝ]›Ý[™HÜ˜×Û[ˆÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]YÂˆH[ÙHYˆ
XÚÙ]ÝšY]Ëš\Ý™\œÚ[ÛˆOH•JHÂˆY[XÜJ	œÜ˜×Ú\—ØY‹XÚÙ]ÝšY]ËœÜ˜×ØY‹M•JNÂˆY[XÜJ	™ÝÚ\—ØY‹XÚÙ]ÝšY]Ë™ÝØY‹M•JNÂˆ[Ü˜×Û[ˆH\×Û[—Ú\Š	œÜ˜×Ú\—ØYŠNÂˆ[ÝÛ[ˆH\×Û[—Ú\Š	™ÝÚ\—ØYŠNÂˆÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]YH\×Ü›Ý]YÜÛÝ\˜ÙWÚ\Š	œÜ˜×Ú\—ØY‹XÚÙ]ÚYš[™^
NÂˆYˆ
\Ü˜×Û[ˆ	‰ˆYÝÛ[ˆ	‰ˆ\ÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]Y
HÛÛ[YNÂˆ\×ÛÝ]›Ý[™HÜ˜×Û[ˆÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]YÂˆH[ÙHYˆ
×Ü›ÝÈOHØÕH×Ü›ÝÈOH•Hˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰‚ˆ
×Ü›ÝÈHMLH×Ü›ÝÈOHUH×Ü›ÝÈOHUHˆ×Ü›ÝÈOHL•H×Ü›ÝÈOHŒH×Ü›ÝÈOH™UHˆ×Ü›ÝÈOH˜•H×Ü›ÝÈOHŒŒJJJHÂˆÊˆˆ\ØÛÝ™\žKØÛÛ›Ûœ˜[Y\È[[[Û˜[H]™H›ÈTšY]Ëˆ
‹ÂˆH[ÙHÂˆÛÛ[YNÂˆB‚ˆ[×ÜXÚÙ]Ù[™HXÚÙ]ÝšY]ËœXÚÙ]Ù[™Â‚ˆÛÛœÝÝXÝ[—ØYˆ
™š[ÜÜ˜×Ú\ˆH\×Ú\—ÜXÚÙ]È	œÜ˜×Ú\—ØYˆˆ•SÂˆÛÛœÝÝXÝ[—ØYˆ
™š[ÙÝÚ\ˆH\×Ú\—ÜXÚÙ]È	™ÝÚ\—ØYˆˆ•SÂ‚ˆYˆ
š[\—Ù^ÛYKš\×ØXÝ]™H	‰ˆ]˜[X]WÙš[\Š	™š[\—Ù^ÛYKÜ˜×ÛXXËÝÛXXËÜ˜×Ú\Û[KÝÚ\Û[Kš[ÜÜ˜×Ú\‹š[ÙÝÚ\ŠJHÂˆÛÛ[YNÂˆB‚ˆYˆ
š[\—Û[ÙLKš\×ØXÝ]™JHÂˆYˆ
Y]˜[X]WÙš[\Š	™š[\—Û[ÙLKÜ˜×ÛXXËÝÛXXËÜ˜×Ú\Û[KÝÚ\Û[Kš[ÜÜ˜×Ú\‹š[ÙÝÚ\ŠJHÛÛ[YNÂˆ[\Ý\™Ù]ÜXÚÙ]
Y™™\‹
[
[[‹×ÛÙ™œÙ]×Ü›ÝÊNÂˆXÚÙ]ØÛÝ[
ÊÎÈYˆ
X^ÜXÚÙ]Èˆ	‰ˆXÚÙ]ØÛÝ[HX^ÜXÚÙ]ÊH[›š[™ÈHÂˆÛÛ[YNÂˆB‚ˆYˆ
ÝÝ\HOHS’×ÑUT“‘U
HÂˆYˆ
\×Ú\™Ù^ÛYYÛXXÊÜ˜×ÛXXÊH	‰ˆ\×ÛÝ]›Ý[™
HÛÛ[YNÂ‚ˆYˆ
\×Ü›Ý]\—ÛXXÊÜ˜×ÛXXÊJHÂˆ[[Ý×ÜXÚÙ]HÂˆYˆ
\×Ú\ÜXÚÙ]	‰ˆ\Ü›ÝØÛÛOHT“Õ×ÕQ	‰ˆ[ˆHÛÙ™œÙ]
È
HÂˆÝXÝYˆYÚŽÈY[XÜJ	YÚ‹Y™™\ˆ
ÈÛÙ™œÙ]Ú^™[ÙŠYÚŠJNÂˆYˆ
ÚÊYÚ‹œÛÝ\˜ÙJHOHLÊH[Ý×ÜXÚÙ]HNÂˆBˆÊˆH›ÜØ\™Y[\›™]ÖSPÒÈ\X\œÈÛˆœ‹[[ˆÚ]Bˆ
ˆ›Ý]\ˆ\È]È]\›™]ÛÝ\˜ÙKˆ]]™XXÚÛ›HHÔˆ
ˆÛÜœ™[][Ûˆ]ÛÈQHØ[ˆÛÛ\]HÛY[•ÈBˆ
ˆYØXÞHÖSPÒÈ[Z]\ˆ™[ÝÈ™[XZ[œÈÝ\™\ÜÙYˆ
‹ÂˆYˆ
Z\×ÛÝ]›Ý[™	‰ˆ\×Ú\ÜXÚÙ]	‰ˆ\Ü›ÝØÛÛOHT“Õ×ÕÔ	‰‚ˆÛÙ™œÙ]
ÈŒH×ÜXÚÙ]Ù[™
HÂˆÝXÝÜˆ›ÜØ\™YÝÜÂˆY[XÜJ	™›ÜØ\™YÝÜY™™\ˆ
ÈÛÙ™œÙ]Ú^™[ÙŠ›ÜØ\™YÝÜ
JNÂˆYˆ
›ÜØ\™YÝÜœÞ[ˆ	‰ˆ›ÜØ\™YÝÜ˜XÚÊH[Ý×ÜXÚÙ]HNÂˆBˆYˆ
X[Ý×ÜXÚÙ]
HÛÛ[YNÂˆBˆB‚ˆÊˆ˜]ËRT[šÜÈ]™H›È\™Ø\™HPPÜËˆÜ™X]HÝX›HËY\š]™Yˆ
ˆÝ\œ›ÙØ]HY[]Y\È™Y›Ü™H[žHPPËZÙ^YYš[\‹ÜÝ]KÙY\]‚ˆ
ˆÙ[œÛÜ‹Ú[\™˜XÙH›Ý™[˜[˜ÙH™[XZ[œÈÙ\\˜]H[ˆHÐ”È[™[ÜKˆ
‹ÂˆYˆ
ÝÝ\HOHS’×ÔU×ÒT	‰ˆ\×Ú\ÜXÚÙ]
HÂˆYˆ
\×Ú\—ÜXÚÙ]
HÂˆ\™ÛÜ×Ü˜]×ÚY[]WÝŠÜ˜×Ú\—ØY‹œÍ—ØY‹Ü˜×ÛXXÊNÂˆ\™ÛÜ×Ü˜]×ÚY[]WÝŠÝÚ\—ØY‹œÍ—ØY‹ÝÛXXÊNÂˆH[ÙHÂˆ\™ÛÜ×Ü˜]×ÚY[]WÝ
XÚÙ]ÝšY]ËœÜ˜×ØY‹Ü˜×ÛXXÊNÂˆ\™ÛÜ×Ü˜]×ÚY[]WÝ
XÚÙ]ÝšY]Ë™ÝØY‹ÝÛXXÊNÂˆBˆB‚ˆYˆ
š[\—Û[ÙL‹š\×ØXÝ]™JHÂˆYˆ
Y]˜[X]WÙš[\Š	™š[\—Û[ÙL‹Ü˜×ÛXXËÝÛXXËÜ˜×Ú\Û[KÝÚ\Û[Kš[ÜÜ˜×Ú\‹š[ÙÝÚ\ŠJHÛÛ[YNÂˆB‚ˆ[›Ý]YÙ]šY[˜ÙHHÛÝ\˜ÙWÛÙ™›[š×Ü›Ý]YÂ‚ˆ[œÚYÛ™YÚ\ˆ]šXÙWÛXXÖÍ—NÂˆÊˆˆ\ØÛÝ™\žKØÛÛ›Ûœ˜[Y\ÈY[YžHZ\ˆÙ[™\ˆžHÛÝ\˜ÙHPPË‚ˆ
ˆ\Ú[™ÈH\Ý[˜][ÛˆPPÈÛÝ[\›ˆ][XØ\ÝY™\ÜÙ\ÈÝXÚ\Âˆ
ˆ	ÜÈNŽ˜ÌŽŒŒŒH[È˜ZÙH]šXÙHY[]Y\Ëˆ
‹ÂˆYˆ
×Ü›ÝÈOHØÈ×Ü›ÝÈOHˆˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ
×Ü›ÝÈHMLH×Ü›ÝÈOHUH×Ü›ÝÈOHUH×Ü›ÝÈOHL•Hˆ×Ü›ÝÈOHŒH×Ü›ÝÈOH™UHˆ×Ü›ÝÈOH˜•H×Ü›ÝÈOHŒŒJJJHÂˆY[XÜJ]šXÙWÛXXËÜ˜×ÛXXËŠNÂˆH[ÙHYˆ
\×ÛÝ]›Ý[™
HÂˆY[XÜJ]šXÙWÛXXËÜ˜×ÛXXËŠNÂˆH[ÙHÂˆY[XÜJ]šXÙWÛXXËÝÛXXËŠNÂˆBˆYˆ
Y[XÛ\
]šXÙWÛXXË™\›×ÛXXËŠHOHY[XÛ\
]šXÙWÛXXË˜Ø\ÝÛXXËŠHOH
HÛÛ[YNÂ‚ˆÚ\ˆXX×ÜÝ–ÌNNÂˆÛÛœÝÚ\ˆ
œ›Ý]YÜÝˆH›Ý]YÙ]šY[˜ÙHÈŸ›Ý]YˆˆˆŽÂˆ›Ü›X]ÛXXÊ]šXÙWÛXXËXX×ÜÝŠNÂ‚ˆÊˆˆ™XÝÜœÈ]\Ý[ˆ]™[ˆÚ[ˆ\™H\È›ÈTXY\‹ˆ
‹ÂˆYˆ
×Ü›ÝÈOHØÊHÂˆYˆ
ÜÛŠBˆ\œÙWÛ
Y™™\ˆ
È×ÛÙ™œÙ]
[
[[ˆH×ÛÙ™œÙ]XX×ÜÝ‹›Ý]YÜÝ‹ÜÛ—Ü›
NÂˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y
HÂˆ\™ÛÜ×ÛÛYYÜ™\Ý[ÝYYÂˆYˆ
\™ÛÜ×ÛÛYYÜ\œÙJY™™\ˆ
È×ÛÙ™œÙ]
Ú^™WÝ
J
[
[[ˆH×ÛÙ™œÙ]
K	›YY
JHÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘S•‹YY™]Z[[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß__SQQ	\×ˆ‹XX×ÜÝ‹YY™]Z[
NÂˆBˆBˆÛÛ[YNÂˆBˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ×Ü›ÝÈHMLJHÂˆ\™ÛÜ×ÜÝÜ™\Ý[ÝÝÂˆYˆ
\™ÛÜ×ÜÝÜ\œÙJY™™\ˆ
È×ÛÙ™œÙ]
Ú^™WÝ
J
[
[[ˆH×ÛÙ™œÙ]
K	œÝ
JHÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘S•‹Ý™]Z[[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß__Õ	\×ˆ‹XX×ÜÝ‹Ý™]Z[
NÂˆÛÛ[YNÂˆBˆYˆ
\™ÛÜ×ÜœÝÜ\œÙJY™™\ˆ
È×ÛÙ™œÙ]
Ú^™WÝ
J
[
[[ˆH×ÛÙ™œÙ]
K	œÝ
JHÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘S•‹Ý™]Z[[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß__”Õ	\×ˆ‹XX×ÜÝ‹Ý™]Z[
NÂˆÛÛ[YNÂˆBˆ\™ÛÜ×Û\ÝÜ™\Ý[Ý\ÝÂˆYˆ
\™ÛÜ×Û\ÝÜ\œÙJY™™\ˆ
È×ÛÙ™œÙ]
Ú^™WÝ
J
[
[[ˆH×ÛÙ™œÙ]
K	›\Ý
JHÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘S•‹\Ý™]Z[[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß__TÕ	\×ˆ‹XX×ÜÝ‹\Ý™]Z[
NÂˆÛÛ[YNÂˆBˆBˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ×Ü›ÝÈOHUJHÂˆ\™ÛÜ×ÛXÜÜ™\Ý[ÝXÜÂˆYˆ
\™ÛÜ×ÛXÜÜ\œÙJY™™\ˆ
È×ÛÙ™œÙ]
Ú^™WÝ
J
[
[[ˆH×ÛÙ™œÙ]
K	›XÜ
JHÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘S•‹XÜ™]Z[[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß__PÔ	\×ˆ‹XX×ÜÝ‹XÜ™]Z[
NÂˆBˆÛÛ[YNÂˆBˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ
×Ü›ÝÈOHUH×Ü›ÝÈOHL•Hˆ×Ü›ÝÈOHŒH×Ü›ÝÈOH™UHˆ×Ü›ÝÈOH˜•H×Ü›ÝÈOHŒŒJJHÂˆ\™ÛÜ×Ù[\œš\ÙWÜ™\Ý[Ý[ÂˆYˆ
\™ÛÜ×Ù[\œš\ÙWÜ\œÙWÛŠ×Ü›ÝËY™™\ˆ
È×ÛÙ™œÙ]
[
[[ˆH×ÛÙ™œÙ]	™[
H	‰ˆ[™[Z]
HÂˆÚ\ˆ[ÜÚYÖÍNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ß	\È‹[œ›ÝË[™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß__	\ß	\×ˆ‹XX×ÜÝ‹[œ›ÝË[™]Z[
NÂˆBˆÛÛ[YNÂˆBˆYˆ
×Ü›ÝÈOHŠHÂˆYˆ
ÜÛŠH\œÙWØ\œÝ™XÝÜŠY™™\ˆ
È×ÛÙ™œÙ]
[
[[ˆH×ÛÙ™œÙ]XÚÙ]ÚYš[™^ÜÛ—Ü›
NÂˆÛÛ[YNÂˆBˆYˆ
Z\×Ú\ÜXÚÙ]
HÛÛ[YNÂˆYˆ
\Ú\×Ùœ˜YÊHÛÛ[YNÂ‚ˆÚ\ˆÜ˜×Ú\ÜÝ–ÒS‘U—ÐQ”Õ“S—HHÌKÝÚ\ÜÝ–ÒS‘U—ÐQ”Õ“S—HHÌNÂˆZ[Ý›ÝØÛÛH\Ü›ÝØÛÛH\ÝÂ‚ˆYˆ
×Ü›ÝÈOH
HÂˆÝXÝ[—ØYˆ×ØY‹ØYŽÈ×ØY‹œ×ØYˆHÜ˜×Ú\Û[NÈØY‹œ×ØYˆHÝÚ\Û[NÂˆ[™]ÛÜ
Q—ÒS‘U	œ×ØY‹Ü˜×Ú\ÜÝ‹Ú^™[ÙŠÜ˜×Ú\ÜÝŠJNÂˆ[™]ÛÜ
Q—ÒS‘U	™ØY‹ÝÚ\ÜÝ‹Ú^™[ÙŠÝÚ\ÜÝŠJNÂˆH[ÙHYˆ
ÜÝˆ	‰ˆ×Ü›ÝÈOH™
HÂˆ[™]ÛÜ
Q—ÒS‘U‹	œÜ˜×Ú\—ØY‹Ü˜×Ú\ÜÝ‹Ú^™[ÙŠÜ˜×Ú\ÜÝŠJNÂˆ[™]ÛÜ
Q—ÒS‘U‹	™ÝÚ\—ØY‹ÝÚ\ÜÝ‹Ú^™[ÙŠÝÚ\ÜÝŠJNÂˆH[ÙHÈÛÛ[YNÈB‚ˆZ[Ý›Ý×Ú\Ý™\œÚ[ÛˆH\×Ú\—ÜXÚÙ]È•HˆNÂˆÛÛœÝZ[Ý
™›Ý×ÜÜ˜×ØYˆH\×Ú\—ÜXÚÙ]ÈÜ˜×Ú\—ØY‹œÍ—ØYˆˆ
ÛÛœÝZ[Ý
ŠIœÜ˜×Ú\Û[NÂˆÛÛœÝZ[Ý
™›Ý×ÙÝØYˆH\×Ú\—ÜXÚÙ]ÈÝÚ\—ØY‹œÍ—ØYˆˆ
ÛÛœÝZ[Ý
ŠI™ÝÚ\Û[NÂ‚ˆYˆ
›ÝØÛÛOHT“Õ×ÒPÓTˆ	‰ˆ\×Ú\—ÜXÚÙ]
HÂˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆOHUH	‰ˆÛÙ™œÙ]H	‰ˆÛÙ™œÙ]×ÜXÚÙ]Ù[™
HÂˆ\™ÛÜ×ÛY[X™\œÚ\Ü™\Ý[ÝY[X™\œÚ\ÂˆYˆ
\™ÛÜ×Û[Ü\œÙJY™™\ˆ
ÈÛÙ™œÙ]
Ú^™WÝ
J×ÜXÚÙ]Ù[™HÛÙ™œÙ]
K	›Y[X™\œÚ\
H	‰ˆY[X™\œÚ\™[Z]
HÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÌÎNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ßS	\È‹Ü˜×Ú\ÜÝ‹Y[X™\œÚ\™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ßS	\É\×ˆ‹[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹Y[X™\œÚ\™]Z[›Ý]YÜÝŠNÂˆBˆBˆYˆ
ÜÛˆ	‰ˆÛÙ™œÙ]H	‰ˆÛÙ™œÙ]×ÜXÚÙ]Ù[™
HÂˆ\œÙWÛ™Ý™XÝÜŠY™™\ˆ
ÈÛÙ™œÙ]×ÜXÚÙ]Ù[™HÛÙ™œÙ]Ü˜×ÛXXËˆ	œÜ˜×Ú\—ØY‹Ü˜×Ú\ÜÝ‹XÚÙ]ÚYš[™^ÜÛ—Ü›
NÂˆBˆÛÛ[YNÂˆB‚ˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ›ÝØÛÛOH•H	‰ˆOHUH	‰‚ˆÛÙ™œÙ]H	‰ˆÛÙ™œÙ]×ÜXÚÙ]Ù[™
HÂˆ\™ÛÜ×ÛY[X™\œÚ\Ü™\Ý[ÝY[X™\œÚ\ÂˆYˆ
\™ÛÜ×ÚYÛ\Ü\œÙJY™™\ˆ
ÈÛÙ™œÙ]
Ú^™WÝ
J×ÜXÚÙ]Ù[™HÛÙ™œÙ]
K	›Y[X™\œÚ\
H	‰ˆY[X™\œÚ\™[Z]
HÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÌÎNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ßQÓT	\È‹Ü˜×Ú\ÜÝ‹Y[X™\œÚ\™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ßQÓT	\É\×ˆ‹[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹Y[X™\œÚ\™]Z[›Ý]YÜÝŠNÂˆBˆÛÛ[YNÂˆB‚ˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ›ÝØÛÛOHLL•H	‰ˆOHMUH	‰‚ˆÛÙ™œÙ]H	‰ˆÛÙ™œÙ]×ÜXÚÙ]Ù[™
HÂˆ\™ÛÜ×ÝœœœÜ™\Ý[ÝœœœÂˆYˆ
\™ÛÜ×ÝœœœÜ\œÙJY™™\ˆ
ÈÛÙ™œÙ]
Ú^™WÝ
J×ÜXÚÙ]Ù[™HÛÙ™œÙ]
Kˆ›Ý×Ú\Ý™\œÚ[Û‹	œœœ
JHÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÌÎNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ß”””	\È‹Ü˜×Ú\ÜÝ‹œœœ™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ß”””	\É\×ˆ‹ˆ[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹œœœ™]Z[›Ý]YÜÝŠNÂˆBˆÛÛ[YNÂˆB‚ˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ›ÝØÛÛOHUH	‰ˆÛÙ™œÙ]H	‰ˆÛÙ™œÙ]×ÜXÚÙ]Ù[™
HÂˆ\™ÛÜ×Ù[\œš\ÙWÜ™\Ý[Ý[ÂˆYˆ
\™ÛÜ×Ù[\œš\ÙWÜ\œÙWÚ\›ÝÊ›ÝØÛÛY™™\ˆ
ÈÛÙ™œÙ]×ÜXÚÙ]Ù[™HÛÙ™œÙ]	™[
H	‰ˆ[™[Z]
HÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÍNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ß	\ß	\È‹Ü˜×Ú\ÜÝ‹[œ›ÝË[™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ß	\ß	\É\×ˆ‹[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹[œ›ÝË[™]Z[›Ý]YÜÝŠNÂˆBˆÛÛ[YNÂˆB‚ˆYˆ
›ÝØÛÛOHT“Õ×ÕÔ
HÂˆYˆ
ÛÙ™œÙ]
ÈŒˆ×ÜXÚÙ]Ù[™
HÛÛ[YNÂˆÝXÝÜˆÜÚŽÈY[XÜJ	ÜÚ‹Y™™\ˆ
ÈÛÙ™œÙ]Ú^™[ÙŠÜÚŠJNÂˆÝXÝÜˆ
ÜH	ÜÚŽÂˆZ[M—ÝÜHÚÊÜO™\Ý
KÜÜHÚÊÜOœÛÝ\˜ÙJNÂˆ[ÜÚHÜO™Ù™ˆ
ˆÂˆYˆ
ÜÚŒÛÙ™œÙ]
ÈÜÚˆ×ÜXÚÙ]Ù[™
HÛÛ[YNÂˆ[^[ØYÛÙ™œÙ]HÛÙ™œÙ]
ÈÜÚ^[ØYÛ[ˆH×ÜXÚÙ]Ù[™H^[ØYÛÙ™œÙ]Âˆ[ÜÜ™[]˜[H
ÜÜÞ[ˆ	‰ˆ
ÜOœÞ[ˆÜOœœÝÜO™š[ŠJHˆ
ÜÚ	‰ˆ
ÜOHHÜOHJJHˆ
ÜÝÈ	‰ˆ
\™ÛÜ×Ý×ÝÜÜÜ
Ü
H\™ÛÜ×Ý×ÝÜÜÜ
ÜÜ
JJHˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ\™ÛÜ×Ù[\œš\ÙWÝÜÜÜ
ÜÜÜ
JNÂˆYˆ
]ÜÜ™[]˜[
HÛÛ[YNÂˆYˆ
\›Ý]YÙ]šY[˜ÙH	‰ˆ\×ÛÝ]›Ý[™	‰ˆ
ÝÝ\HOHS’×ÑUT“‘UÝÝ\HOHS’×ÐÓÓÒÑQ
JHÂˆYˆ
\×Ú\—ÜXÚÙ]ÈÝÛ™\—ÛZ\ÛX]Ú
	œÜ˜×Ú\—ØY‹Ü˜×ÛXXÊHˆÝÛ™\ÛZ\ÛX]Ú
Ü˜×Ú\Û[KÜ˜×ÛXXÊJHÂˆ›Ý]YÙ]šY[˜ÙHHNÈ›Ý]YÜÝˆHŸ›Ý]YŽÂˆBˆB‚ˆYˆ
ÜÜÞ[ŠHÂˆZ[Ý›Ý×Ý\ÙXÈHÝÝ\ÙXÎÂ‚ˆYˆ
ÜOœÞ[ˆ	‰ˆ]ÜO˜XÚÊHÂˆYˆ
ÜÙ^ÛY]šXÜÊHÂˆÞ[—Ý˜XÚ×Ý
˜XÚÙYHÞ[—Ý˜XÚ×Ùš[™
Ü˜×ÛXXËÜÜÜ›Ý×Ú\Ý™\œÚ[Û‹ˆ›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹›Ý×Ý\ÙXËJNÂˆYˆ
˜XÚÙY	‰ˆ˜XÚÙYO×Ý\ÙXÈOH
HÂˆ˜XÚÙYO×Ý\ÙXÈH›Ý×Ý\ÙXÎÂˆ˜XÚÙYOœ›Ý]YH
Z[Ý
J›Ý]YÙ]šY[˜ÙHÈHˆ
NÂˆBˆBˆBˆ[ÙHYˆ
ÜOœÞ[ˆ	‰ˆÜO˜XÚÊHÂˆYˆ
ÜÙ^ÛY]šXÜÊHÂˆÞ[—Ý˜XÚ×Ý
˜XÚÙYHÞ[—Ý˜XÚ×Ùš[™
ÝÛXXËÜÜÜ›Ý×Ú\Ý™\œÚ[Û‹ˆ›Ý×ÙÝØY‹›Ý×ÜÜ˜×ØY‹›Ý×Ý\ÙXË
NÂˆYˆ
˜XÚÙY
HÂˆYˆ
˜XÚÙYO×Ý\ÙXÈˆ	‰ˆ›Ý×Ý\ÙXÈˆ˜XÚÙYO×Ý\ÙXÊHÂˆZ[ÝÝ\ÈH›Ý×Ý\ÙXÈH˜XÚÙYO×Ý\ÙXÎÂˆÚ\ˆÛY[ÛXX×ÜÝ–ÌNNÂˆÚ\ˆÞ[—Ü^[ØYÌÌ—KÞ[—ÜÚYÖÌLŽNÂˆ›Ü›X]ÛXXÊ˜XÚÙYO›XXËÛY[ÛXX×ÜÝŠNÂˆÛœš[ŠÞ[—Ü^[ØYÚ^™[ÙŠÞ[—Ü^[ØY
K”•‰]H‹ÜÜ
NÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JÞ[—ÜÚYËÚ^™[ÙŠÞ[—ÜÚYÊKÝÚ\ÜÝ‹Þ[—Ü^[ØYˆ˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊÛY[ÛXX×ÜÝ‹•Ô“‹Þ[—ÜÚYËÜÜÞ[—Ü›
JHÂˆ[Z]Ý[[Y]žJ•Ô“	\ß	\ß	\ß	]_	[_ÖSPÒÉ\×ˆ‹ˆÛY[ÛXX×ÜÝ‹ÝÚ\ÜÝ‹Ü˜×Ú\ÜÝ‹ÜÜˆ
[œÚYÛ™YÛ™ÈÛ™Ê\Ý\Ëˆ˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆBˆBˆ˜XÚÙYO˜[YHÂˆBˆBˆH[ÙHYˆ
ÜOœœÝÜO™š[ŠHÂˆYˆ
ÜÙ^ÛY]šXÜÊHÂˆÞ[—Ý˜XÚ×Ý
˜XÚÙYH•SÂˆÛÛœÝÚ\ˆ
˜ÛY[Ú\H•SÂˆÛÛœÝÚ\ˆ
œÙ\™\—Ú\H•SÂˆZ[M—ÝÙ\™\—ÜÜHÂ‚ˆ˜XÚÙYHÞ[—Ý˜XÚ×Ùš[™
Ü˜×ÛXXËÜÜÜ›Ý×Ú\Ý™\œÚ[Û‹ˆ›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹›Ý×Ý\ÙXË
NÂˆYˆ
˜XÚÙY
HÂˆÛY[Ú\HÜ˜×Ú\ÜÝŽÂˆÙ\™\—Ú\HÝÚ\ÜÝŽÂˆÙ\™\—ÜÜHÜÂˆH[ÙHÂˆ˜XÚÙYHÞ[—Ý˜XÚ×Ùš[™
ÝÛXXËÜÜÜ›Ý×Ú\Ý™\œÚ[Û‹ˆ›Ý×ÙÝØY‹›Ý×ÜÜ˜×ØY‹›Ý×Ý\ÙXË
NÂˆYˆ
˜XÚÙY
HÂˆÛY[Ú\HÝÚ\ÜÝŽÂˆÙ\™\—Ú\HÜ˜×Ú\ÜÝŽÂˆÙ\™\—ÜÜHÜÜÂˆBˆB‚ˆÊˆÔ“Ý]H™XÛÜ™È\™H[[[Û˜[H[Z]YÈ›ÝÜÈ›Ü‚ˆ
ˆÚXÚHÖSˆØ\ÈØœÙ\™Yˆ\ÈÙY\ÈY[]HÙ[X[XÜÂˆ
ˆÝX›H[™]›ÚYÈ›ÛÙ[™ÈHØ]]Ø^HÚ][œ™[]Y’S‹Ô”Õˆ
‹ÂˆYˆ
˜XÚÙY
HÂˆÚ\ˆÛY[ÛXX×ÜÝ–ÌNNÂˆÚ\ˆÞ[—Ü^[ØYÌÌ—KÞ[—ÜÚYÖÌLŽNÂˆ›Ü›X]ÛXXÊ˜XÚÙYO›XXËÛY[ÛXX×ÜÝŠNÂˆÛœš[ŠÞ[—Ü^[ØYÚ^™[ÙŠÞ[—Ü^[ØY
K”ÕUN‰]N‰\È‹Ù\™\—ÜÜÜOœœÝÈ”ˆˆˆ‘ˆŠNÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JÞ[—ÜÚYËÚ^™[ÙŠÞ[—ÜÚYÊKÛY[Ú\Þ[—Ü^[ØYˆ˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊÛY[ÛXX×ÜÝ‹•Ô“‹Þ[—ÜÚYËÜÜÞ[—Ü›
JHÂˆ[Z]Ý[[Y]žJ•Ô“	\ß	\ß	\ß	]_	\É\×ˆ‹ˆÛY[ÛXX×ÜÝ‹ÛY[Ú\Ù\™\—Ú\Ù\™\—ÜÜˆÜOœœÝÈ””Õˆˆ‘’Sˆ‹˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆBˆBˆBˆB‚ˆYˆ
ÜOœÞ[ŠHÂˆ[\ÜÈHLKÜØØ[HHLNÈÚ\ˆÜ×ÜÝ–ÍHHÌNÈ[ÜÜÜÈHÂˆYˆ
ÜÚˆŒ
HÂˆÛÛœÝ[œÚYÛ™YÚ\ˆ
›ÜÈHY™™\ˆ
ÈÛÙ™œÙ]
ÈŒÂˆ[ÜÝÝ[HÜÚHŒÜHÂˆÚ[H
ÜÜÝÝ[	‰ˆÜÜÜÈ
[
\Ú^™[ÙŠÜ×ÜÝŠHH
HÂˆZ[ÝÚ[™HÜÖÛÜNÂˆYˆ
Ú[™OH
HÈYˆ
ÜÜÜÈˆ	‰ˆÜ×ÜÝ–ÛÜÜÜËLWHOH	Ë	ÊHÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Ë	ÎÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	ÑIÎÈœ™XZÎÈBˆYˆ
Ú[™OHJHÈYˆ
ÜÜÜÈˆ	‰ˆÜ×ÜÝ–ÛÜÜÜËLWHOH	Ë	ÊHÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Ë	ÎÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Ó‰ÎÈÜ
ÊÎÈÛÛ[YNÈBˆYˆ
Ü
ÈHHÜÝÝ[
Hœ™XZÎÂˆZ[ÝÛ[ˆHÜÖÛÜ
ÈWNÂˆYˆ
Û[ˆˆÜ
ÈÛ[ˆˆÜÝÝ[
Hœ™XZÎÂˆYˆ
ÜÜÜÈˆ	‰ˆÜ×ÜÝ–ÛÜÜÜËLWHOH	Ë	ÊHÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Ë	ÎÂˆYˆ
Ú[™OHˆ	‰ˆÛ[ˆOH
HÈ\ÜÈH™XYØ™LMŠÜÈ
ÈÜ
ÈŠNÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	ÓIÎÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Ê‰ÎÈBˆ[ÙHYˆ
Ú[™OHÈ	‰ˆÛ[ˆOHÊHÈÜØØ[HHÜÖÛÜ
È—NÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	ÕÉÎÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Ê‰ÎÈBˆ[ÙHYˆ
Ú[™OH	‰ˆÛ[ˆOHŠHÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	ÔÉÎÈBˆ[ÙHYˆ
Ú[™OH	‰ˆÛ[ˆOHL
HÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	Õ	ÎÈBˆ[ÙHÈÜ×ÜÝ–ÛÜÜÜÊÊ×HH	ÏÉÎÈBˆÜ
ÏHÛ[ŽÂˆBˆBˆÜ×ÜÝ–ÛÜÜÜ×HH	×	ÎÈYˆ
Ü×ÜÝ–ÌHOH	×	ÊHÝ˜ÜJÜ×ÜÝ‹››Û™HŠNÂ‚ˆYˆ
ÜO˜XÚÈ	‰ˆÜOœÞ[ŠHÂˆÊˆ›ÜØ\™YÐSˆ™\Y\È\ÙHH›Ý]\‰ÜÈˆÛÝ\˜ÙHPPË‚ˆ
ˆ^H\™HÛÛœÝ[YYX›Ý™H›ÜˆÔ“•Û›H[™]\Ýˆ
ˆ›ÝÝ\™˜XÙH\ÈYØXÞH^\›˜[ÖSPÒÈ[[Y]žKˆ
‹ÂˆYˆ
\×ÛÝ]›Ý[™	‰ˆZ\×Ü›Ý]\—ÛXXÊÜ˜×ÛXXÊJHÂˆÚ\ˆÞ[—Ü^[ØYÌÌ—KÞ[—ÜÚYÖÌLŽNÂˆÛœš[ŠÞ[—Ü^[ØYÚ^™[ÙŠÞ[—Ü^[ØY
K‰]H‹ÜÜ
NÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JÞ[—ÜÚYËÚ^™[ÙŠÞ[—ÜÚYÊKÜ˜×Ú\ÜÝ‹Þ[—Ü^[ØY›Ý]YÜÝŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹”ÖSPÒÈ‹Þ[—ÜÚYËÜÜÞ[—Ü›
JBˆ[Z]Ý[[Y]žJ”ÖSPÒß	\ß	\ß	]_	]_	Y	Y	\ß	]I\×ˆ‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹ÚÊÜOÚ[™ÝÊKÜØØ[K\ÜËÜ×ÜÝ‹ÜÜ›Ý]YÜÝŠNÂˆBˆH[ÙHYˆ
ÜOœÞ[ŠHÂˆÚ\ˆÞ[—Ü^[ØYÌÌ—KÞ[—ÜÚYÖÌLŽNÂˆÛœš[ŠÞ[—Ü^[ØYÚ^™[ÙŠÞ[—Ü^[ØY
K‰]H‹Ü
NÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JÞ[—ÜÚYËÚ^™[ÙŠÞ[—ÜÚYÊKÜ˜×Ú\ÜÝ‹Þ[—Ü^[ØY›Ý]YÜÝŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹”ÖSˆ‹Þ[—ÜÚYËÜÜÞ[—Ü›
JBˆ[Z]Ý[[Y]žJ”ÖSŸ	\ß	\ß	]_	]_	Y	Y	\ß	]I\×ˆ‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹ÚÊÜOÚ[™ÝÊKÜØØ[K\ÜËÜ×ÜÝ‹Ü›Ý]YÜÝŠNÂˆBˆBˆB‚ˆÊˆÖSˆ\ÈHÛÛ›™XÝ[Û‹YÙ[™\˜][Ûˆ›Ý[™\žH›Üˆ[œÜXÝ[Û˜ÙHÝ]K‚ˆ
ˆ™\Ù]™Y›Ü™HÛÛœÝ[[™ÈÓ‘HÛÈ˜\YK]\H™]\ÙH\È™KZ[œÜXÝYˆ
‹ÂˆYˆ
ÜOœÞ[ˆ	‰ˆ]ÜO˜XÚÊBˆ\™ÛÜ×Ù›Ý×Ü™\Ù]ÜZ\Š	˜\Ù›Ý×ÜÝ]K›Ý×Ú\Ý™\œÚ[Û‹›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹ÜÜÜ
NÂ‚ˆ[[\œš\ÙWÝÜH[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ\™ÛÜ×Ù[\œš\ÙWÝÜÜÜ
ÜÜÜ
NÂˆ[\Ý˜XÚÈH^[ØYÛ[ˆˆ	‰‚ˆ

ÜÚ	‰ˆ
ÜOHHÜOHJJHˆ
ÜÝÈ	‰ˆ
\™ÛÜ×Ý×ÝÜÜÜ
Ü
H\™ÛÜ×Ý×ÝÜÜÜ
ÜÜ
JJH[\œš\ÙWÝÜ
NÂˆYˆ
\Ý˜XÚÈ	‰ˆ\™ÛÜ×Ù›Ý×ÜÚÝ[ÜÚÚ\
	˜\Ù›Ý×ÜÝ]K›Ý×Ú\Ý™\œÚ[Û‹›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹ˆÜÜÜ
JHÂˆÛÛ[YNÂˆB‚ˆYˆ
ÜÚ	‰ˆ
ÜOHÜOH
H	‰ˆ^[ØYÛ[ˆˆMŠHÂˆÛÛœÝ[œÚYÛ™YÚ\ˆ
œHY™™\ˆ
È^[ØYÛÙ™œÙ]ÂˆYˆ

^[ØYÛ[ˆH	‰ˆY[XÛ\
‘ÑU‹
HOH
H
^[ØYÛ[ˆHH	‰ˆY[XÛ\
”ÔÕ‹JHOH
JHÂˆÛÛœÝ[œÚYÛ™YÚ\ˆ
XWÚˆHš[™Øž]\×ØÚJ
Ú^™WÝ
\^[ØYÛ[‹——•\Ù\‹PYÙ[ˆ‹M
NÂˆYˆ
XWÚŠHÂˆÛÛœÝ[œÚYÛ™YÚ\ˆ
XHHXWÚˆ
ÈMÈÚ^™WÝXWØ]˜Z[H
Ú^™WÝ
J

È^[ØYÛ[ŠHHXJNÂˆÛÛœÝ[œÚYÛ™YÚ\ˆ
™[™Hš[™Øž]\ÊXKXWØ]˜Z[
ÛÛœÝ[œÚYÛ™YÚ\ˆ
ŠH——ˆ‹ŠNÂˆYˆ
[™
HÂˆ[X[[ˆH
[
J[™HXJNÈYˆ
X[[ˆˆMJHX[[ˆHMNÂˆÚ\ˆXWÜÝ–ÌM—NÈØ[š]^™WÙšY[
XKX[[‹XWÜÝ‹Ú^™[ÙŠXWÜÝŠK
NÂˆÚ\ˆÜÚYÖÌÎNÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JÜÚYËÚ^™[ÙŠÜÚYÊKÜ˜×Ú\ÜÝ‹XWÜÝ‹›Ý]YÜÝŠNÂˆYˆ
XWÜÝ–ÌH	‰ˆYY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹’‹ÜÚYËÜÚÜ›
JH[Z]Ý[[Y]žJ’	\ß	\ß	\É\×ˆ‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹XWÜÝ‹›Ý]YÜÝŠNÂˆBˆBˆBˆBˆ[ÙHYˆ
ÜÝÈ	‰ˆ\™ÛÜ×Ý×ÝÜÜÜ
Ü
H	‰ˆ^[ØYÛ[ˆˆ
HÂˆ\œÙWÝ×ÜÛšJY™™\ˆ
È^[ØYÛÙ™œÙ]^[ØYÛ[‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹Ü›Ý]YÜÝ‹ÜÝ×Ü›
NÂˆBˆ[ÙHYˆ
ÜÝÈ	‰ˆ\™ÛÜ×Ý×ÝÜÜÜ
ÜÜ
H	‰ˆ^[ØYÛ[ˆˆ
HÂˆ\™ÛÜ×Ý×ÜÙ\™\—Ü™\Ý[ÝÙ\™\ŽÂˆYˆ
\™ÛÜ×Ý×ÜÙ\™\—Ü\œÙJY™™\ˆ
È^[ØYÛÙ™œÙ]
Ú^™WÝ
\^[ØYÛ[‹	œÙ\™\ŠJHÂˆÚ\ˆÜ—ÜÚYÖÌM—NÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JÜ—ÜÚYËÚ^™[ÙŠÜ—ÜÚYÊKÜ˜×Ú\ÜÝ‹Ù\™\‹™š[™Ù\œš[›Ý]YÜÝŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹•ÔÔ•ˆ‹Ü—ÜÚYËÜÝ×Ü›
JBˆ[Z]Ý[[Y]žJ•ÔÔ•Ÿ	\ß	\ß	\ß	]_	\ß	\É\×ˆ‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹ÜÜÙ\™\‹™š[™Ù\œš[Ù\™\‹˜[‹›Ý]YÜÝŠNÂˆBˆB‚ˆ\™ÛÜ×Ù[\œš\ÙWÜ™\Ý[Ý[ÝÜÂˆ[[ÝÜÜÙY[ˆHÂˆYˆ
[\œš\ÙWÝÜ	‰ˆ^[ØYÛ[ˆˆ
HÂˆ[ÝÜÜÙY[ˆH\™ÛÜ×Ù[\œš\ÙWÜ\œÙWÝÜ
ÜÜÜY™™\ˆ
È^[ØYÛÙ™œÙ]^[ØYÛ[‹	™[ÝÜ
NÂˆYˆ
[ÝÜÜÙY[ˆ	‰ˆ[ÝÜ™[Z]
HÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÍÍŽNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ß	\ß	\È‹Ü˜×Ú\ÜÝ‹[ÝÜœ›ÝË[ÝÜ™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ß	\ß	\É\×ˆ‹[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹[ÝÜœ›ÝË[ÝÜ™]Z[›Ý]YÜÝŠNÂˆBˆB‚ˆÊˆY[]H\ÈHÙ\\˜]H^XÚ]™XÝÜ‹ˆ‘^˜XÝ[Ûˆ\Âˆ
ˆ][\YÛ›HÛˆÛY[OœÙ\™\ˆÌÎH[™ÚZÙH^[ØYÈ]ˆ
ˆ[\œš\ÙH[ÙH[™XYHYZ]YÈY˜][S•™[XZ[œÈ™YXÝYˆ
‹ÂˆYˆ
\™ÛÜ×ÚY[]WÙ[˜X›Y
[[YWØÙ™ËšY[]WÛ[ÙJH	‰ˆÜOHÌÎUH	‰ˆ^[ØYÛ[ˆˆ
HÂˆ\™ÛÜ×ÚY[]WÜ™\Ý[ÝY[ÂˆYˆ
\™ÛÜ×ÚY[]WÜ™Û\ÝÚ\Ú
Y™™\ˆ
È^[ØYÛÙ™œÙ]
Ú^™WÝ
\^[ØYÛ[‹ˆ\™ÛÜ×ÚY[]WÜ˜]Ê[[YWØÙ™ËšY[]WÛ[ÙJK	šY[
JHÂˆ[Z]ÚY[]WÛØœÙ\˜][ÛŠÜ˜×ÛXXËÜ˜×Ú\ÜÝ‹	šY[›Ý]YÜÝ‹ˆ[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
NÂˆBˆB‚ˆÊˆ•H\HÈ\ÈHÛY[]][XØ][Ûˆ[™ÚZÙHØ\œžZ[™Âˆ
ˆØœÙ\™YÛXZ[‹Ý\Ù\‹ÝÛÜšÜÝ][ÛˆY[]HY]Y]KˆÛ›HÜÙBˆ
ˆ™YH›Ý[™YÙXÝ\š]HY™™\œÈ\™H\œÙYÈ]]™\ÜÛœÙ\È\™H›Ýˆ
‹ÂˆYˆ
\™ÛÜ×ÚY[]WÙ[˜X›Y
[[YWØÙ™ËšY[]WÛ[ÙJH	‰ˆÜOHUH	‰ˆ^[ØYÛ[ˆˆ
HÂˆ\™ÛÜ×ÚY[]WÜ™\Ý[ÝYÖÌ×NÂˆÚ^™WÝYØÛÝ[H\™ÛÜ×ÚY[]WÛWÝ\LÊˆY™™\ˆ
È^[ØYÛÙ™œÙ]
Ú^™WÝ
\^[ØYÛ[‹ˆ\™ÛÜ×ÚY[]WÜ˜]Ê[[YWØÙ™ËšY[]WÛ[ÙJKYÊNÂˆ›Üˆ
Ú^™WÝZHHÈZHYØÛÝ[È
ÊÚZJHÂˆ[Z]ÚY[]WÛØœÙ\˜][ÛŠÜ˜×ÛXXËÜ˜×Ú\ÜÝ‹	šYÖÚZWK›Ý]YÜÝ‹ˆ[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
NÂˆBˆB‚ˆÊˆÙ\˜™\›ÜÈØœÙ\™YY[]NˆÛ›HÛY[O’ÑÈTËT‘THÛ˜[YKÜ™X[Kˆ
‹ÂˆYˆ
\™ÛÜ×ÚY[]WÙ[˜X›Y
[[YWØÙ™ËšY[]WÛ[ÙJH	‰ˆÜOHH	‰ˆ^[ØYÛ[ˆˆ
HÂˆ\™ÛÜ×ÚY[]WÜ™\Ý[ÝY[ÂˆYˆ
\™ÛÜ×ÚY[]WÚÙ\˜™\›Ü×Ø\Ü™\JY™™\ˆ
È^[ØYÛÙ™œÙ]ˆ
Ú^™WÝ
\^[ØYÛ[‹Kˆ\™ÛÜ×ÚY[]WÜ˜]Ê[[YWØÙ™ËšY[]WÛ[ÙJK	šY[
JHÂˆ[Z]ÚY[]WÛØœÙ\˜][ÛŠÜ˜×ÛXXËÜ˜×Ú\ÜÝ‹	šY[›Ý]YÜÝ‹ˆ[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
NÂˆBˆB‚ˆYˆ
\Ý˜XÚÊHÂˆ[š[™Ù\œš[ØÛÛ\]HH\Ù›Ý×Ü^[ØYØÛÛ\]JˆÜÜÜY™™\ˆ
È^[ØYÛÙ™œÙ]^[ØYÛ[ŠNÂˆYˆ
[ÝÜÜÙY[ˆ	‰ˆ[ÝÜ˜ÛÛ\]JHš[™Ù\œš[ØÛÛ\]HHNÂˆ\™ÛÜ×Ù›Ý×Û›ÝWÜ^[ØY
	˜\Ù›Ý×ÜÝ]K›Ý×Ú\Ý™\œÚ[Û‹›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹ˆÜÜÜš[™Ù\œš[ØÛÛ\]JNÂˆBˆBˆ[ÙHYˆ
›ÝØÛÛOHT“Õ×ÕQ
HÂˆYˆ
ÛÙ™œÙ]
Èˆ×ÜXÚÙ]Ù[™
HÛÛ[YNÂˆÝXÝYˆYÚŽÈY[XÜJ	YÚ‹Y™™\ˆ
ÈÛÙ™œÙ]Ú^™[ÙŠYÚŠJNÂˆÝXÝYˆ
YH	YÚŽÂˆZ[M—ÝÜHÚÊYO™\Ý
KÜÜHÚÊYOœÛÝ\˜ÙJNÂˆ[YÜ™[]˜[H
ÜÙÜ	‰ˆ

\×Ú\—ÜXÚÙ]	‰ˆÜÜOHM•H	‰ˆÜOHMÕJHˆ
Z\×Ú\—ÜXÚÙ]	‰ˆ
ÜOHÕHÜÜOHÕJJJJHˆ
ÜÛ™]š[ÜÈ	‰ˆ
ÜOHLÍÕHÜÜOHLÍÕJJHˆ
ÜÛ][H	‰ˆ
ÜOHNLHÜÜOHNLHÜOHÍÌ•HÜÜOHÍÌ•HˆÜOHLÍLÕHÜÜOHLÍLÕJJHˆ
ÜÙœÈ	‰ˆ
ÜOHLÕHÜÜOHLÕJJHˆ
ÜÝÈ	‰ˆÜOHÕJHˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ
\™ÛÜ×Ù[\œš\ÙWÝYÜÜ
ÜÜÜ
HˆÜÜOH[[YWØÙ™ËÚ\™YÝX\™ÜÜÜOH[[YWØÙ™ËÚ\™YÝX\™ÜÜ
JNÂˆYˆ
]YÜ™[]˜[
HÛÛ[YNÂˆYˆ
\›Ý]YÙ]šY[˜ÙH	‰ˆ\×ÛÝ]›Ý[™	‰ˆ
ÝÝ\HOHS’×ÑUT“‘UÝÝ\HOHS’×ÐÓÓÒÑQ
JHÂˆYˆ
\×Ú\—ÜXÚÙ]ÈÝÛ™\—ÛZ\ÛX]Ú
	œÜ˜×Ú\—ØY‹Ü˜×ÛXXÊHˆÝÛ™\ÛZ\ÛX]Ú
Ü˜×Ú\Û[KÜ˜×ÛXXÊJHÂˆ›Ý]YÙ]šY[˜ÙHHNÈ›Ý]YÜÝˆHŸ›Ý]YŽÂˆBˆBˆZ[M—ÝYÛ[ˆHÚÊYO›[ŠNÂˆYˆ
YÛ[ˆH
[
]YÛ[ˆˆ×ÜXÚÙ]Ù[™HÛÙ™œÙ]
HÛÛ[YNÂˆ[^[ØYÛÙ™œÙ]HÛÙ™œÙ]
ÈÂˆ[^[ØYÛ[ˆH
[
]YÛ[ˆHÂˆYˆ
^[ØYÛ[ˆH
HÛÛ[YNÂ‚ˆÛÛœÝ[œÚYÛ™YÚ\ˆ
œ^[ØYHY™™\ˆ
È^[ØYÛÙ™œÙ]Â‚ˆYˆ
ÜÙÜ	‰ˆ\×Ú\—ÜXÚÙ]	‰ˆÜÜOHM•H	‰ˆÜOHMÕJHÂˆ\œÙWÙÜŠ^[ØY^[ØYÛ[‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹›Ý]YÜÝ‹ÜÙÜÜ›
NÂˆBˆ[ÙHYˆ
ÜÙÜ	‰ˆZ\×Ú\—ÜXÚÙ]	‰ˆ
ÜOHÕHÜÜOHÕJJHÂˆ\œÙWÙÜ
^[ØY^[ØYÛ[‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹›Ý]YÜÝ‹ÜÙÜÜ›
NÂˆBˆ[ÙHYˆ
ÜÛ™]š[ÜÈ	‰ˆ
ÜOHLÍÈÜÜOHLÍÊJHÂˆ\œÙWÛ™]š[ÜÊ^[ØY^[ØYÛ[‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹›Ý]YÜÝ‹ÜÛ™]š[Ü×Ü›
NÂˆBˆ[ÙHYˆ
ÜÛ][H	‰ˆ
ÜOHNLÜÜOHNLÜOHÍÌˆÜÜOHÍÌŠJHÂˆÚ\ˆÛX[—Ü^[ØYÍLL×NÈ[[ˆH
^[ØYÛ[ˆˆLLŠHÈLLˆˆ^[ØYÛ[ŽÂˆØ[š]^™WÙšY[
^[ØY[‹ÛX[—Ü^[ØYÚ^™[ÙŠÛX[—Ü^[ØY
KJNÂˆÚ\ˆ×ÜÚYÖÍNÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™J×ÜÚYËÚ^™[ÙŠ×ÜÚYÊKÜ˜×Ú\ÜÝ‹ÛX[—Ü^[ØY›Ý]YÜÝŠNÂˆYˆ
ÛX[—Ü^[ØYÌH	‰ˆYY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹“È‹×ÜÚYËÜÛ][WÜ›
JHÂˆ[Z]Ý[[Y]žJ“ß	\ß	\ß	Y	\É\×ˆ‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹
ÜOHNLÜOHÍÌŠHÈÜˆÜÜÛX[—Ü^[ØY›Ý]YÜÝŠNÂˆBˆBˆ[ÙHYˆ
ÜÛ][H	‰ˆ
ÜOHLÍLÈÜÜOHLÍLÊJHÂˆ\œÙWÛYœÊ^[ØY^[ØYÛ[‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹
ÜOHLÍLÊHÈÜˆÜÜ›Ý]YÜÝ‹ÜÛ][WÜ›
NÂˆBˆ[ÙHYˆ
ÜÙœÈ	‰ˆ
ÜOHLÈÜÜOHLÊJHÂˆYˆ
^[ØYÛ[ˆˆLŠHÂˆZ[M—Ý›YÜÈH™XYØ™LMŠ^[ØY
ÈŠNÂˆ[\×Ü™\ÜÛœÙHH
›YÜÈ	ˆ
HOHÂˆZ[M—ÝYH™XYØ™LMŠ^[ØY
NÂ‚ˆYˆ
Z\×Ü™\ÜÛœÙH	‰ˆÜOHLÊHÂˆÚ\ˆ[˜[YVÌM—NÂˆZ[M—Ý]\HHÂˆYˆ
XÛÙWÙœ×Û˜[YJ^[ØY^[ØYÛ[‹L‹[˜[YKÚ^™[ÙŠ[˜[YJJHˆ	‰ˆ[˜[YVÌJHÂˆ
›ÚY
Yœ×Ü]Y\Ý[Û—Ü]\J^[ØY^[ØYÛ[‹L‹	œ]\JNÂˆYˆ
ÜÙ^ÛY]šXÜÈ	‰ˆ]\HOHJHÂˆ
›ÚY
X\™ÛÜ×Ùœ×Ý˜XÚ×Ü]
œ×ÝX›KPÒ×ÔÓÕËˆ›Ý×Ú\Ý™\œÚ[Û‹›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹ˆÜÜÜY]\K[˜[YKÝÝ\ÙXËˆÜ˜×ÛXXË
Z[Ý
J›Ý]YÙ]šY[˜ÙHÈHˆ
JNÂˆBˆÚ\ˆœ×ÜÚYÖÌÎNÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™Jœ×ÜÚYËÚ^™[ÙŠœ×ÜÚYÊKÜ˜×Ú\ÜÝ‹[˜[YK›Ý]YÜÝŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊXX×ÜÝ‹‘”È‹œ×ÜÚYËÜÙœ×Ü›
JHÂˆ[Z]Ý[[Y]žJ‘”ß	\ß	\ß	\É\×ˆ‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹[˜[YK›Ý]YÜÝŠNÂˆBˆBˆBˆ[ÙHYˆ
\×Ü™\ÜÛœÙH	‰ˆÜÜOHLÊHÂˆYˆ
ÜÙ^ÛY]šXÜÈ	‰ˆ™XYØ™LMŠ^[ØY
È
HˆJHÂˆÚ\ˆ™\ÜÛœÙWÜ[˜[YVÌM—NÂˆZ[M—Ý™\ÜÛœÙWÜ]\HHNÂˆYˆ
XÛÙWÙœ×Û˜[YJ^[ØY^[ØYÛ[‹L‹™\ÜÛœÙWÜ[˜[YKÚ^™[ÙŠ™\ÜÛœÙWÜ[˜[YJJHˆ	‰‚ˆ™\ÜÛœÙWÜ[˜[YVÌH	‰ˆœ×Ü]Y\Ý[Û—Ü]\J^[ØY^[ØYÛ[‹L‹	œ™\ÜÛœÙWÜ]\JJHÂˆ\™ÛÜ×Ùœ×Ý˜XÚ×Ý
˜XÚÙYH\™ÛÜ×Ùœ×Ý˜XÚ×Ùš[™Ü™\ÜÛœÙJˆœ×ÝX›KPÒ×ÔÓÕË›Ý×Ú\Ý™\œÚ[Û‹›Ý×ÙÝØY‹›Ý×ÜÜ˜×ØY‹ˆÜÜÜY™\ÜÛœÙWÜ]\K™\ÜÛœÙWÜ[˜[YKÝÝ\ÙXÊNÂˆYˆ
˜XÚÙY
HÂˆZ[Ý˜ÛÙHH›YÜÈ	ˆŽÂˆZ[Ý][˜ÞWÝ\ÈHÝÝ\ÙXÈH˜XÚÙYO×Ý\ÙXÎÂˆ›Ø][HØ[Ý[]WÙ[›ÜJ˜XÚÙYO™ÛXZ[ŠNÂ‚ˆÚ\ˆÛY[ÛXX×ÜÝ–ÌNNÂˆ›Ü›X]ÛXXÊ˜XÚÙYO›XXËÛY[ÛXX×ÜÝŠNÂ‚ˆÚ\ˆœÙ^ÜÚYÖÌÎNÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™JœÙ^ÜÚYËÚ^™[ÙŠœÙ^ÜÚYÊKÝÚ\ÜÝ‹ˆ˜XÚÙYO™ÛXZ[‹˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊÛY[ÛXX×ÜÝ‹‘”ÑV‹œÙ^ÜÚYËÜÙœ×Ü›
JHÂˆ[Z]Ý[[Y]žJ‘”ÑV	\ß	\ß	\ß	\ß	]_	]_	KŒ™Ÿ	KŒ™‰\×ˆ‹ˆÛY[ÛXX×ÜÝ‹ÝÚ\ÜÝ‹Ü˜×Ú\ÜÝ‹˜XÚÙYO™ÛXZ[‹ˆ
[œÚYÛ™Y
]˜XÚÙYOœ]\K
[œÚYÛ™Y
\˜ÛÙKˆ
›Ø]
[][˜ÞWÝ\ÈÈLŒ‹[˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆBˆÚ\ˆ[\ÜÚYÖÌNL—NÂˆÛÝ\˜ÙWÙY\ÜÚYÛ˜]\™J[\ÜÚYËÚ^™[ÙŠ[\ÜÚYÊKÝÚ\ÜÝ‹ˆ’QÒÑ”×ÑS•“ÔH‹˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆYˆ
[HŒ™ˆ	‰‚ˆYY\ÜÚÝ[ÜÝ\™\ÜÊÛY[ÛXX×ÜÝ‹ST•‹[\ÜÚYËÜÙœ×Ü›
JHÂˆ[Z]Ý[[Y]žJST•	\ß	\ßQÒÑ”×ÑS•“Ô_	\ß	KŒ™‰\×ˆ‹ˆÛY[ÛXX×ÜÝ‹ÝÚ\ÜÝ‹˜XÚÙYO™ÛXZ[‹[ˆ˜XÚÙYOœ›Ý]YÈŸ›Ý]YˆˆˆŠNÂˆBˆ˜XÚÙYO˜[YHÂˆBˆBˆBˆBˆBˆBˆ[ÙHYˆ
ÜÝÈ	‰ˆÜOHÊHÂˆ\œÙWÜ]ZXÊ^[ØY^[ØYÛ[‹XX×ÜÝ‹Ü˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹Ü›Ý]YÜÝ‹ÜÝ×Ü›
NÂˆBˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆOHUH	‰ˆ
ÜÜOHNNUHÜOHNNUJJHÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÍLL—NÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂ‚ˆ\™ÛÜ×ÚÜœ—Ü™\Ý[ÝÜœŽÂˆYˆ
\™ÛÜ×ÚÜœ—Ü\œÙJ^[ØY
Ú^™WÝ
\^[ØYÛ[‹	šÜœŠJHÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ßÔ”Ÿ	\È‹Ü˜×Ú\ÜÝ‹Üœ‹™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ßÔ”Ÿ	\É\×ˆ‹ˆ[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹Üœ‹™]Z[›Ý]YÜÝŠNÂˆH[ÙHÂˆ\™ÛÜ×ÚÜœWÜ™\Ý[ÝÜœNÂˆYˆ
\™ÛÜ×ÚÜœWÜ\œÙJ^[ØY
Ú^™WÝ
\^[ØYÛ[‹	šÜœJJHÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ßÔ”	\È‹Ü˜×Ú\ÜÝ‹ÜœK™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ßÔ”	\É\×ˆ‹ˆ[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹ÜœK™]Z[›Ý]YÜÝŠNÂˆBˆBˆBˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ
ÜÜOH[[YWØÙ™ËÚ\™YÝX\™ÜÜÜOH[[YWØÙ™ËÚ\™YÝX\™ÜÜ
JHÂˆÊˆ\KM˜[œÜÜXÚÙ]ÈØ[ˆ™H[ˆ[\[Q›ÝËˆ˜[Y]HBˆ
ˆ^XÝÚ\™QÝX\™œ˜[Z[™ÈÚX\K[ˆž\\ÜÈH[\œÙ\ˆ›Ü‚ˆ
ˆ™\X]Y˜[œÜÜY]H[ˆHÚÜ\ØÚˆ[™ÚZÙKØÛÛÚÚYH\\Âˆ
ˆ[™ÙY\[]™\È\™H[Ø^\È\œÙYˆ”ËÑÔÔURPËÔÕS‹ÐÛÐTÓ•\™Bˆ
ˆ[X™\˜][HÝ]ÚYH\ÈÝ\™\ÜÚ[ÛˆX›Kˆ
‹Âˆ[Ù×Ý˜[œÜÜH\™ÛÜ×ÝÚ\™YÝX\™Ý˜[œÜÜÚÚ[™
^[ØY
Ú^™WÝ
\^[ØYÛ[ŠNÂˆ[Ù×ÜÝ\™\ÜÙYHÙ×Ý˜[œÜÜOHˆ	‰‚ˆ\™ÛÜ×ÝYÜÝ\™\Ü×Ü™XÙ[
YÜÝ\™\Ü×ÝX›K›Ý×Ú\Ý™\œÚ[Û‹ˆ›Ý×ÜÜ˜×ØY‹›Ý×ÙÝØY‹ÜÜÜˆK
Z[Ý
][YJ•S
JNÂˆYˆ
]Ù×ÜÝ\™\ÜÙY
HÂˆ\™ÛÜ×ÝÚ\™YÝX\™Ü™\Ý[ÝÙÎÂˆYˆ
\™ÛÜ×ÝÚ\™YÝX\™Ü\œÙJ^[ØY
Ú^™WÝ
\^[ØYÛ[‹	ÙÊH	‰ˆÙË™[Z]
HÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÌÎNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ßÚ\™QÝX\™	\È‹Ü˜×Ú\ÜÝ‹ÙË™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ßÚ\™QÝX\™	\É\×ˆ‹ˆ[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹ÙË™]Z[›Ý]YÜÝŠNÂˆBˆBˆBˆYˆ
[[YWØÙ™Ë™[\œš\ÙWÙ[˜X›Y	‰ˆ\™ÛÜ×Ù[\œš\ÙWÝYÜÜ
ÜÜÜ
JHÂˆ\™ÛÜ×Ù[\œš\ÙWÜ™\Ý[Ý[ÝYÂˆYˆ
\™ÛÜ×Ù[\œš\ÙWÜ\œÙWÝY
ÜÜÜ^[ØY^[ØYÛ[‹	™[ÝY
H	‰ˆ[ÝY™[Z]
HÂˆÚ\ˆ[ÛXXÖÌNK[ÜÚYÖÍÍŽNÂˆ›Ü›X]ÛXXÊÜ˜×ÛXXË[ÛXXÊNÂˆÛœš[Š[ÜÚYËÚ^™[ÙŠ[ÜÚYÊK‰\ß	\ß	\È‹Ü˜×Ú\ÜÝ‹[ÝYœ›ÝË[ÝY™]Z[
NÂˆYˆ
YY\ÜÚÝ[ÜÝ\™\ÜÊ[ÛXXË‘S•‹[ÜÚYË[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
JBˆ[Z]Ý[[Y]žJ‘S•	\ß	\ß	\ß	\ß	\É\×ˆ‹[ÛXXËÜ˜×Ú\ÜÝ‹ÝÚ\ÜÝ‹[ÝYœ›ÝË[ÝY™]Z[›Ý]YÜÝŠNÂˆBˆBˆÊˆQUTÈØœÙ\™YY[]NˆÛY[XØÙ\ÜËT™\]Y\Ý\Ù\‹S˜[YHÛ›Kˆ
‹ÂˆYˆ
\™ÛÜ×ÚY[]WÙ[˜X›Y
[[YWØÙ™ËšY[]WÛ[ÙJH	‰ˆÜOHNL•JHÂˆ\™ÛÜ×ÚY[]WÜ™\Ý[ÝY[ÂˆYˆ
\™ÛÜ×ÚY[]WÜ˜Y]\×ØXØÙ\Ü×Ü™\]Y\Ý
^[ØY
Ú^™WÝ
\^[ØYÛ[‹ˆ\™ÛÜ×ÚY[]WÜ˜]Ê[[YWØÙ™ËšY[]WÛ[ÙJK	šY[
JHÂˆ[Z]ÚY[]WÛØœÙ\˜][ÛŠÜ˜×ÛXXËÜ˜×Ú\ÜÝ‹	šY[›Ý]YÜÝ‹ˆ[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
NÂˆBˆB‚ˆÊˆQÎ\Ù\ÈHØ[YHÝšXÝH›Ý[™YTËT‘TH\œÙ\ˆÚ]Ý]ˆ
ˆH‘ÈLŒÔ™XÛÜ™[[™Ý™Yš^ˆ
‹ÂˆYˆ
\™ÛÜ×ÚY[]WÙ[˜X›Y
[[YWØÙ™ËšY[]WÛ[ÙJH	‰ˆÜOHJHÂˆ\™ÛÜ×ÚY[]WÜ™\Ý[ÝY[ÂˆYˆ
\™ÛÜ×ÚY[]WÚÙ\˜™\›Ü×Ø\Ü™\J^[ØY
Ú^™WÝ
\^[ØYÛ[‹ˆ\™ÛÜ×ÚY[]WÜ˜]Ê[[YWØÙ™ËšY[]WÛ[ÙJK	šY[
JHÂˆ[Z]ÚY[]WÛØœÙ\˜][ÛŠÜ˜×ÛXXËÜ˜×Ú\ÜÝ‹	šY[›Ý]YÜÝ‹ˆ[[YWØÙ™Ë™[\œš\ÙWÜ˜]WÛ[Z]Y
NÂˆBˆBˆBˆBˆYˆ
ÜÝŠHÂˆZ[Ý›ØÙ\ÜÚ[™×Ù[™Ý\ÈHÙ]ØÝ\œ™[Ý\ÙXÊ
NÂˆYˆ
›ØÙ\ÜÚ[™×Ù[™Ý\ÈH›ØÙ\ÜÚ[™×ÜÝ\Ý\È	‰ˆ›ØÙ\ÜÚ[™×Ù[™Ý\ÈH›ØÙ\ÜÚ[™×ÜÝ\Ý\ÈˆX^ÛÛÜÝ\ÊBˆX^ÛÛÜÝ\ÈH›ØÙ\ÜÚ[™×Ù[™Ý\ÈH›ØÙ\ÜÚ[™×ÜÝ\Ý\ÎÂˆBˆB‚ˆÊˆÛX[\ÛØÚÙ]È[™™\ÛÝ\˜Ù\È
‹Âˆ›Üˆ
[HHÈH[WÚY˜XÙ\ÎÈJÊÊHÛÜÙJXÝ]™WÚY˜XÙ\ÖÚWK™™
NÂˆYˆ
[—Û™][š×Ù™H
HÛÜÙJ[—Û™][š×Ù™
NÂˆYˆ
\×ÜÛØÚÈH
HÛÜÙJ\×ÜÛØÚÊNÂˆYˆ
™[[ÝWÜÛØÚÈH
HÛÜÙJ™[[ÝWÜÛØÚÊNÂˆœ™YJÞ[—ÝX›JNÈœ™YJœ×ÝX›JNÈ\™ÛÜ×ÙY\Ù\Ý›ÞJ	™Y\ÜÝ]JNÈœ™YJÝÛ™\ÝX›JNÈœ™YJÝÛ™\—ÝX›JNÂˆÛÜÙJ\ÛÙ™
NÂˆ™]\›ˆÂŸBˆÙ[™Y‚