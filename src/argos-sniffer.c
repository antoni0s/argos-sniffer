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
#include "argos_dispatch.h"
#include "argos_help.h"
#include "argos_telemetry.h"
#include "argos_packet.h"
#include "argos_discovery.h"
#include "argos_filter.h"
#include "argos_network.h"
#include "argos_flow_state.h"
#include "argos_identity.h"
#include "argos_enterprise.h"
#include "argos_raw_identity.h"
#ifndef ARGOS_PORTABLE_TEST
#include "argos_capture.h"
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
typedef struct { uint8_t *fake_tls; } argos_quic_state_t;
#define ARGOS_QUIC_FAKE_TLS_CAP 8192U
static int argos_quic_prepare(argos_quic_state_t *state, int heavy) {
    (void)state; (void)heavy; return 1;
}
static void argos_quic_destroy(argos_quic_state_t *state) { (void)state; }
static int decrypt_quic_sni(argos_quic_state_t *state,
                            const unsigned char *payload, int len, int pos, uint8_t dcid_len,
                            uint8_t *out, int out_max, int *out_len) {
    (void)state; (void)payload; (void)len; (void)pos; (void)dcid_len; (void)out; (void)out_max;
    if (out_len) *out_len = 0;
    return 0;
}
static int decrypt_quic_sni_stateful(argos_quic_state_t *state,
                                     const unsigned char *payload, int len, int pos, uint8_t dcid_len,
                                     uint8_t *out, int out_max, int *out_len) {
    (void)state; (void)payload; (void)len; (void)pos; (void)dcid_len; (void)out; (void)out_max;
    if (out_len) *out_len = 0;
    return -1;
}
static void quic_heavy_gc(argos_quic_state_t *state) { (void)state; }
static int argos_quic_success_recent(argos_quic_state_t *state, uint64_t key) {
    (void)state; (void)key; return 0;
}
static void argos_quic_mark_success(argos_quic_state_t *state, uint64_t key) {
    (void)state; (void)key;
}
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

static argos_network_state_t network_state;
static argos_runtime_state_t runtime_state;
static argos_quic_state_t quic_state;


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

#ifndef ARGOS_PORTABLE_TEST
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
static int rate_limit_ttl = ARGOS_DEFAULT_RATE_LIMIT_SECONDS;
static int dedup_should_suppress_for(const char *mac, const char *evtype, const char *payload,
                                     int rl_enabled, int ttl, int sliding) {
    return argos_dedup_should_suppress(&runtime_state.dedup, mac, evtype, payload,
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
/* UDP suppression is intentionally separate from TCP DONE state. It is used
 * only for protocol/message classes proven safe to skip briefly. */

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
 * SECTION: Protocol Parsers
 * Parsers for TLS/JA4, QUIC, LLDP, NetBIOS, DHCP, DNS, and mDNS traffic.
 * ============================================================================ */
static void parse_tls_sni(const unsigned char *payload, int len, const char *mac,
                          const char *src_ip, const char *dst_ip, uint16_t dport,
                          const char *routed_str, int emit_tls, int tls_rl,
                          int emit_dot, int dot_rl) {
    argos_tls_client_result_t tls;
    if (!argos_tls_client_parse(payload, len, &tls)) return;
    char fp_payload[512], fp_sig[640];
    snprintf(fp_payload, sizeof(fp_payload), "%s|%s", tls.sni, tls.ja4);
    source_dedup_signature(fp_sig, sizeof(fp_sig), src_ip, fp_payload, routed_str);
    if (emit_tls && !dedup_should_suppress(mac, "TLS", fp_sig, tls_rl)) {
        emit_telemetry("TLS|%s|%s|%s|%u|%s|%s|%s%s\n", mac, src_ip, dst_ip, dport, tls.sni, tls.ja4, tls.alpn, routed_str);
    }
    if (emit_dot && dport == 853U &&
        !dedup_should_suppress(mac, "DOT", fp_sig, dot_rl)) {
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


static uint64_t quic_flow_key(const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport) {
    char keybuf[160];
    int n = snprintf(keybuf, sizeof(keybuf), "%s|%s|%s|%u", mac, src_ip, dst_ip, (unsigned)dport);
    if (n < 0) return 0;
    if (n >= (int)sizeof(keybuf)) n = (int)sizeof(keybuf) - 1;
    return hash_bytes(keybuf, (size_t)n);
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

        uint8_t *fake_tls_buf = quic_state.fake_tls;
        int fake_tls_len = 0;
        int result;
        if (opt_quic_heavy) {
            /* Stateful result: 1=ready, 0=pending, -1=real failure. */
            result = decrypt_quic_sni_stateful(&quic_state, payload + offset, packet_span,
                                                dcid_pos, dcid_len, fake_tls_buf,
                                                (int)ARGOS_QUIC_FAKE_TLS_CAP, &fake_tls_len);
        } else {
            result = decrypt_quic_sni(&quic_state, payload + offset, packet_span,
                                      dcid_pos, dcid_len, fake_tls_buf,
                                      (int)ARGOS_QUIC_FAKE_TLS_CAP, &fake_tls_len) ? 1 : -1;
        }

        if (result > 0) {
            parse_tls_sni(fake_tls_buf, fake_tls_len, mac, src_ip, dst_ip, dport,
                          routed_str, 1, rl_enabled, 0, 0);
                argos_quic_mark_success(&quic_state, success_key);
            return;
        }
        if (result < 0) { saw_failure = 1; failure_version = packet_version; }
        /* result == 0 is normal stateful reassembly pending: stay silent. */
        offset += packet_span;
    }

    if (saw_initial && saw_failure && !argos_quic_success_recent(&quic_state, success_key)) {
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
    const char *routed = argos_network_routed4(&network_state, spa, ifindex) ? "|routed" : "";
    char sig[128];
    snprintf(sig, sizeof(sig), "%s|%s|%s|%s", sender_ip, target_ip, op, routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "ARP", sig, rl_enabled))
        emit_telemetry("ARP|%s|%s|%s|%s%s\n", mac, sender_ip, target_ip, op, routed);

    /* Learn only after evaluating the event so a stale owner cannot be hidden
     * before this packet is classified. */
    argos_network_owner4_note(&network_state, spa, parsed.sender_mac);
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

    int mismatch = argos_network_owner6_mismatch(&network_state, src_addr, frame_src_mac);
    const char *routed = (argos_network_routed6(&network_state, src_addr, ifindex) || mismatch) ? "|routed" : "";
    char sig[256];
    snprintf(sig, sizeof(sig), "%s|%u|%s|%u|%s|%u|%u|%s", src_ip,
             (unsigned)parsed.hop_limit, parsed.flags, (unsigned)parsed.lifetime,
             prefix, (unsigned)parsed.prefix_length, (unsigned)parsed.mtu,
             routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "RA", sig, rl_enabled))
        emit_telemetry("RA|%s|%s|%u|%s|%u|%s|%u|%u%s\n", mac, src_ip,
                       (unsigned)parsed.hop_limit, parsed.flags, (unsigned)parsed.lifetime,
                       prefix, (unsigned)parsed.prefix_length, (unsigned)parsed.mtu, routed);
    argos_network_owner6_note(&network_state, src_addr, frame_src_mac);
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
    int mismatch = argos_network_owner6_mismatch(&network_state, src_addr, parsed.identity_mac);
    const char *routed = (argos_network_routed6(&network_state, src_addr, ifindex) || mismatch) ? "|routed" : "";
    char sig[320]; snprintf(sig, sizeof(sig), "%s|%s|%s|%s|%s", src_ip, parsed.kind,
                            target, parsed.flags,
                            routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "NDP", sig, rl_enabled))
        emit_telemetry("NDP|%s|%s|%s|%s|%s%s\n", mac, src_ip, parsed.kind,
                       target, parsed.flags, routed);

    /* Source LLA owns the packet's source address. An NA TLLA additionally
     * claims the advertised target address. */
    argos_network_owner6_note(&network_state, src_addr, parsed.identity_mac);
    if (parsed.is_advertisement) argos_network_owner6_note(&network_state, &target_addr, parsed.identity_mac);
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

static void emit_ptp_vector(const unsigned char *payload, size_t payload_len,
                            const char *mac, const char *src_ip, const char *dst_ip,
                            const char *routed, int rate_limited) {
    argos_network_ptp_result_t ptp;
    if (!argos_network_ptp_parse(payload, payload_len, &ptp)) return;
    char signature[768];
    source_dedup_signature(signature, sizeof(signature), src_ip, ptp.detail, routed);
    if (!dedup_should_suppress(mac, "PTP", signature, rate_limited))
        emit_telemetry("PTP|%s|%s|%s|%s%s\n",
                       mac, src_ip, dst_ip, ptp.detail, routed);
}

/* ============================================================================
 * SECTION: Mode 1 - Target Packet Inspector
 * Dumps live captured packets in a tcpdump-like format when Mode 1 is active
 * (-z filter given). This is a read-only, best-effort human-readable printer;
 * it consumes the normalized view, but intentionally is not a strict transport
 * admission path (nonfirst IPv4 fragments and invalid UDP lengths still print).
 * ============================================================================ */
#ifndef ARGOS_PORTABLE_TEST
/* Called only after successful normalization and the main IP/L2 allowlist. */
static void dump_target_packet(const argos_packet_view_t *v) {
    const unsigned char *buffer = v->frame;
    int len = v->captured_len, l3_offset = v->l3_offset;
    uint16_t l3_proto = v->l3_proto;
    struct timeval tv; gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    char tmbuf[32]; strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", tm_info);

    if (v->ip_version == 4U) {
        int ip_packet_len = v->packet_end - l3_offset;
        int l4_offset = v->l4_offset, available = v->packet_end - l4_offset;
        char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, v->src_addr, s_ip, sizeof(s_ip)); inet_ntop(AF_INET, v->dst_addr, d_ip, sizeof(d_ip));

        if (v->ip_protocol == IPPROTO_TCP && available >= 20) {
            int header = argos_packet_tcp_header_length(buffer + l4_offset, available);
            if (!header) return;
            struct tcphdr tcp_hdr; memcpy(&tcp_hdr, buffer + l4_offset, sizeof(tcp_hdr));
            struct tcphdr *tcp = &tcp_hdr;
            char flags[16] = {0}; int fi = 0;
            if (tcp->syn) flags[fi++] = 'S';
            if (tcp->ack) flags[fi++] = '.';
            if (tcp->psh) flags[fi++] = 'P';
            if (tcp->fin) flags[fi++] = 'F';
            if (tcp->rst) flags[fi++] = 'R';
            flags[fi] = '\0';
            printf("%s.%06d IP %s.%u > %s.%u: Flags [%s], seq %u, win %u, length %d\n",
                   tmbuf, (int)tv.tv_usec, s_ip, ntohs(tcp->source), d_ip, ntohs(tcp->dest),
                   flags[0] ? flags : "none", (uint32_t)ntohl(tcp->seq), ntohs(tcp->window), available - header);
        } else if (v->ip_protocol == IPPROTO_UDP && available >= 8) {
            struct udphdr udp_hdr; memcpy(&udp_hdr, buffer + l4_offset, sizeof(udp_hdr));
            struct udphdr *udp = &udp_hdr;
            printf("%s.%06d IP %s.%u > %s.%u: UDP, length %u\n", tmbuf, (int)tv.tv_usec, s_ip, ntohs(udp->source), d_ip, ntohs(udp->dest), ntohs(udp->len));
        } else if (v->ip_protocol == IPPROTO_ICMP) {
            printf("%s.%06d IP %s > %s: ICMP, length %d\n", tmbuf, (int)tv.tv_usec, s_ip, d_ip, available);
        } else {
            printf("%s.%06d IP %s > %s: proto %u, length %d\n", tmbuf, (int)tv.tv_usec, s_ip, d_ip, v->ip_protocol, ip_packet_len);
        }
    } else if (v->ip_version == 6U) {
        char s_ip6[INET6_ADDRSTRLEN], d_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, v->src_addr, s_ip6, sizeof(s_ip6)); inet_ntop(AF_INET6, v->dst_addr, d_ip6, sizeof(d_ip6));
        /* Print the base header's next value, not the traversed L4 protocol. */
        printf("%s.%06d IP6 %s > %s: next-hdr %u, length %d\n", tmbuf, (int)tv.tv_usec, s_ip6, d_ip6, buffer[l3_offset + 6], v->packet_end - l3_offset - 40);
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
    if (argos_network_add_inside(&network_state, spec)) return 1;
    fprintf(stderr, "Error: invalid or too many --inside prefixes: %s\n",
            spec ? spec : "(null)");
    return 0;
}

/* ============================================================================
 * SECTION: main()
 * Entry point: parses command-line arguments, sets up network interfaces, configures 
 * epoll, and runs the primary packet processing loop.
 * ============================================================================ */

/* ============================================================================
 * SECTION: Kernel AF_PACKET Prefilter
 * Vector-aware classic-BPF construction lives in argos_bpf.h so the generated
 * program can be regression-tested against synthetic packet fixtures.
 * ============================================================================ */
#ifndef ARGOS_PORTABLE_TEST
int main(int argc, char *argv[]) {
    int help_status = argos_help_preflight(argc, argv, VERSION, stdout, stderr);
    if (help_status != 0) return help_status > 0 ? 0 : 1;

    const char *iface = "any";
    int exit_status = 1;
    
    argos_filter_program_t filter_mode1 = {0};
    argos_filter_program_t filter_mode2 = {0};
    argos_filter_program_t filter_exclude = {0};

    int max_packets = 0, packet_count = 0;
    int opt_syn = 0, opt_v6 = 0, opt_promisc = 0;
    int opt_syn_rl = 0;
    argos_cli_selection_t cli_selection;
    argos_cli_selection_init(&cli_selection);
    argos_runtime_config_t runtime_cfg;
    argos_runtime_config_init(&runtime_cfg);
    int opt;
    enum { OPT_SENSOR = 1000, OPT_SENSOR_NAME, OPT_INSIDE, OPT_ENTERPRISE,
           OPT_ENTERPRISE_VERBOSE, OPT_WIREGUARD_PORT, OPT_IDENTITY,
           OPT_IDENTITY_RAW, OPT_PROFILE, OPT_SUPER_GROUP, OPT_GROUP,
           OPT_PROTOCOL, OPT_NO_RATE_LIMIT };
    static const struct option long_options[] = {
        {"sensor", no_argument, NULL, OPT_SENSOR},
        {"sensor-name", required_argument, NULL, OPT_SENSOR_NAME},
        {"inside", required_argument, NULL, OPT_INSIDE},
        {"enterprise", no_argument, NULL, OPT_ENTERPRISE},
        {"enterprise-verbose", no_argument, NULL, OPT_ENTERPRISE_VERBOSE},
        {"wireguard-port", required_argument, NULL, OPT_WIREGUARD_PORT},
        {"identity", optional_argument, NULL, OPT_IDENTITY},
        {"identity-raw", no_argument, NULL, OPT_IDENTITY_RAW}, /* compatibility alias */
        {"profile", required_argument, NULL, OPT_PROFILE},
        {"super-group", required_argument, NULL, OPT_SUPER_GROUP},
        {"group", required_argument, NULL, OPT_GROUP},
        {"protocol", required_argument, NULL, OPT_PROTOCOL},
        {"no-rate-limit", required_argument, NULL, OPT_NO_RATE_LIMIT},
        {NULL, 0, NULL, 0}
    };

    /* CLI flag convention: for each telemetry category there is a lowercase
     * flag (enable + rate-limited/deduplicated output, the quiet default)
     * and an uppercase flag (enable + verbose/no rate-limiting, for
     * debugging). -a enables everything rate-limited; -A enables everything
     * verbose. -R/-r configure MAC address lists (hard/soft exclude) rather
     * than telemetry categories, and -x/-z/-Z compile capture filters. */
    while ((opt = getopt_long(argc, argv, "i:r:R:x:z:Z:o:u:U:c:f:sSmMdDnNqQhHtTlLvVpaAWE", long_options, NULL)) != -1) {
        switch (opt) {
            case OPT_SENSOR:
                opt_sensor_mode = 1; opt_promisc = 1;
                argos_cli_selection_apply_feature(&cli_selection,
                                                  ARGOS_FEATURE_SENSOR_DEPLOYMENT, 0);
                break;
            case OPT_SENSOR_NAME:
                if (!valid_sensor_name(optarg)) {
                    fprintf(stderr, "Error: --sensor-name may contain only letters, digits, '.', '_' and '-' (max 63 chars).\n");
                    goto cleanup_state;
                }
                snprintf(sensor_name, sizeof(sensor_name), "%s", optarg);
                break;
            case OPT_INSIDE: if (!add_inside_prefix(optarg)) goto cleanup_state; break;
            case OPT_ENTERPRISE:
                argos_runtime_enable_enterprise(&runtime_cfg, 0);
                argos_cli_selection_apply_legacy(&cli_selection,
                                                 ARGOS_LEGACY_CATEGORY_ENTERPRISE, 0);
                argos_cli_selection_apply_feature(&cli_selection, ARGOS_FEATURE_IPV6, 0);
                break;
            case OPT_ENTERPRISE_VERBOSE:
                argos_runtime_enable_enterprise(&runtime_cfg, 1);
                argos_cli_selection_apply_legacy(&cli_selection,
                                                 ARGOS_LEGACY_CATEGORY_ENTERPRISE, 1);
                argos_cli_selection_apply_feature(&cli_selection, ARGOS_FEATURE_IPV6, 0);
                break;
            case OPT_IDENTITY:
                if (!argos_identity_mode_parse(optarg, &runtime_cfg.identity_mode)) {
                    fprintf(stderr, "Error: --identity expects hash or raw (use --identity=hash or --identity=raw).\n");
                    goto cleanup_state;
                }
                break;
            case OPT_IDENTITY_RAW:
                /* v6 compatibility alias for the former second flag. */
                runtime_cfg.identity_mode = ARGOS_IDENTITY_RAW;
                break;
            case OPT_PROFILE:
                if (!argos_cli_selection_apply_named(
                        &cli_selection, ARGOS_CLI_SELECTOR_PROFILE, optarg)) {
                    fprintf(stderr, "Error: unknown --profile: %.80s\n", optarg);
                    goto cleanup_state;
                }
                break;
            case OPT_SUPER_GROUP:
                if (!argos_cli_selection_apply_named(
                        &cli_selection, ARGOS_CLI_SELECTOR_SUPER_GROUP, optarg)) {
                    fprintf(stderr, "Error: unknown --super-group: %.80s\n", optarg);
                    goto cleanup_state;
                }
                break;
            case OPT_GROUP:
                if (!argos_cli_selection_apply_named(
                        &cli_selection, ARGOS_CLI_SELECTOR_GROUP, optarg)) {
                    fprintf(stderr, "Error: unknown --group: %.80s\n", optarg);
                    goto cleanup_state;
                }
                break;
            case OPT_PROTOCOL:
                if (!argos_cli_selection_apply_named(
                        &cli_selection, ARGOS_CLI_SELECTOR_PROTOCOL, optarg)) {
                    fprintf(stderr,
                            "Error: unknown or unavailable --protocol: %.80s\n",
                            optarg);
                    goto cleanup_state;
                }
                break;
            case OPT_NO_RATE_LIMIT:
                if (!argos_cli_selection_apply_named(
                        &cli_selection, ARGOS_CLI_SELECTOR_NO_RATE_LIMIT, optarg)) {
                    fprintf(stderr, "Error: unknown --no-rate-limit target: %.80s\n",
                            optarg);
                    goto cleanup_state;
                }
                break;
            case OPT_WIREGUARD_PORT: {
                char *end = NULL; long v = strtol(optarg, &end, 10);
                if (!end || *end || v < 1 || v > 65535) {
                    fprintf(stderr, "Error: invalid --wireguard-port: %s\n", optarg); goto cleanup_state;
                }
                runtime_cfg.wireguard_port = (uint16_t)v; runtime_cfg.wireguard_port_explicit = 1; break;
            }
            case 'E':
                argos_cli_selection_apply_feature(&cli_selection,
                                                  ARGOS_FEATURE_EXTENDED_METRICS, 0);
                break;
            case 'i': iface = optarg; break;
            case 'R': 
                if (hard_exclude_mac_count < MAX_HARD_EXCLUDE_MACS) {
                    uint8_t parsed_mac[6];
                    if (!argos_filter_parse_mac(optarg, parsed_mac)) {
                        fprintf(stderr, "Error: invalid MAC address for -R: %s\n", optarg); goto cleanup_state;
                    }
                    memcpy(hard_exclude_macs[hard_exclude_mac_count], parsed_mac, 6);
                    hard_exclude_mac_count++;
                }
                break;
            case 'r':
                if (router_mac_count < MAX_ROUTER_MACS) {
                    uint8_t parsed_mac[6];
                    if (!argos_filter_parse_mac(optarg, parsed_mac)) {
                        fprintf(stderr, "Error: invalid MAC address for -r: %s\n", optarg); goto cleanup_state;
                    }
                    memcpy(router_macs[router_mac_count], parsed_mac, 6);
                    router_mac_count++;
                }
                break;
            case 'x': if (argos_filter_compile(optarg, &filter_exclude) < 0) goto cleanup_state; break;
            case 'z': if (argos_filter_compile(optarg, &filter_mode1) < 0) goto cleanup_state; opt_promisc = 1; break;
            case 'Z': if (argos_filter_compile(optarg, &filter_mode2) < 0) goto cleanup_state; break;
            case 'o': 
                if (ipc_sock >= 0) close(ipc_sock); /* defensive: avoid leaking a fd if -o is given more than once */
                use_ipc = 1;
                if ((ipc_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) { perror("socket AF_UNIX"); goto cleanup_state; }
                memset(&ipc_addr, 0, sizeof(struct sockaddr_un));
                ipc_addr.sun_family = AF_UNIX;
                strncpy(ipc_addr.sun_path, optarg, sizeof(ipc_addr.sun_path) - 1);
                break;
            case 'u': /* UDP-only remote telemetry sink. */
                if (remote_sock >= 0) close(remote_sock);
                remote_sock = -1; /* No stale owner if resolution fails. */
                if (parse_host_port(optarg, &remote_addr, &remote_addr_len) < 0) goto cleanup_state;
                if ((remote_sock = socket(remote_addr.ss_family, SOCK_DGRAM, 0)) < 0) { perror("socket -u"); goto cleanup_state; }
                use_remote = 1;
                udp_only = 1;
                break;
            case 'U': /* Native Remote Socket: ship telemetry directly to a remote UDP collector.
                       * Caution: if the destination is reachable via one of the interfaces this
                       * process is itself capturing on (e.g. a WAN interface also passed to -i),
                       * the outgoing telemetry datagrams will be visible to the capture loop like
                       * any other traffic; use -x to exclude the collector's IP/port if that would
                       * create noise or a feedback loop. */
                if (remote_sock >= 0) close(remote_sock);
                remote_sock = -1; /* No stale owner if resolution fails. */
                if (parse_host_port(optarg, &remote_addr, &remote_addr_len) < 0) goto cleanup_state; /* parse_host_port() already printed why */
                if ((remote_sock = socket(remote_addr.ss_family, SOCK_DGRAM, 0)) < 0) { perror("socket -U"); goto cleanup_state; }
                use_remote = 1;
                udp_only = 0;
                fprintf(stderr, "warning: -U streams telemetry to %s over plain UDP and stdout; UDP is unencrypted, use only over a trusted path.\n", optarg);
                break;
            case 'c': { char *end = NULL; long v = strtol(optarg, &end, 10); if (!end || *end || v < 0 || v > INT32_MAX) { fprintf(stderr, "Error: invalid packet count: %s\n", optarg); goto cleanup_state; } max_packets = (int)v; break; }
            case 'f': { char *end = NULL; long v = strtol(optarg, &end, 10); if (!end || *end || v < 0 || v > INT32_MAX) { fprintf(stderr, "Error: invalid deduplication window: %s\n", optarg); goto cleanup_state; } rate_limit_ttl = (int)v; break; }
            case 'p': opt_promisc = 1; break;
            case 's': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_SYN, 0); break;
            case 'S': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_SYN, 1); break;
            case 'm': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_MULTI, 0); break;
            case 'M': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_MULTI, 1); break;
            case 'd': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_DHCP, 0); break;
            case 'D': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_DHCP, 1); break;
            case 'n': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_NETBIOS, 0); break;
            case 'N': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_NETBIOS, 1); break;
            case 'q': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_DNS, 0); break;
            case 'Q': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_DNS, 1); break;
            case 'h': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_HTTP, 0); break;
            case 'H': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_HTTP, 1); break;
            case 't': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_TLS, 0); break;
            case 'T': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_TLS, 1); break;
            case 'l': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_L2, 0); break;
            case 'L': argos_cli_selection_apply_legacy(&cli_selection, ARGOS_LEGACY_CATEGORY_L2, 1); break;
            case 'v':
            case 'V': argos_cli_selection_apply_feature(&cli_selection, ARGOS_FEATURE_IPV6, 0); break;
            case 'a': argos_cli_selection_apply_legacy_all(&cli_selection, 0); break;
            case 'A': argos_cli_selection_apply_legacy_all(&cli_selection, 1); break;
            case 'W':
                argos_cli_selection_apply_feature(&cli_selection,
                                                  ARGOS_FEATURE_QUIC_STATEFUL, 0);
                break;
            default: argos_help_print_topic(stdout, ARGOS_HELP_BASE, argv[0], VERSION); goto cleanup_state;
        }
    }

    if (optind < argc) {
        iface = argv[optind++];
        argos_cli_selection_apply_legacy_all(&cli_selection, 0);
    }

    if (optind < argc) { fprintf(stderr, "Error: Unrecognized extra argument.\n"); goto cleanup_state; }

    if (!opt_sensor_mode && (sensor_name[0] || network_state.configured_count > 0)) {
        fprintf(stderr, "Error: --sensor-name/--inside require --sensor.\n");
        goto cleanup_state;
    }
    if (opt_sensor_mode) {
        if (!sensor_name[0]) {
            fprintf(stderr, "Error: --sensor requires --sensor-name.\n");
            goto cleanup_state;
        }
        if (strcasecmp(iface, "any") == 0) {
            fprintf(stderr, "Error: --sensor requires an explicit SPAN/TAP interface via -i (not 'any').\n");
            goto cleanup_state;
        }
    }

    const char *runtime_cfg_error = argos_runtime_config_validate(&runtime_cfg);
    if (runtime_cfg_error) {
        fprintf(stderr, "Error: %s\n", runtime_cfg_error);
        goto cleanup_state;
    }

    if (filter_mode1.is_active && filter_mode2.is_active) {
        fprintf(stderr, "warning: -z and -Z both given; -Z ignored in live sniffer mode.\n");
    }

    if (!filter_mode1.is_active) argos_cli_selection_finalize(&cli_selection);

    argos_dispatch_plan_t dispatch_plan;
    argos_dispatch_plan_compile(&dispatch_plan, &cli_selection);

    opt_syn = argos_feature_selection_has(
        &dispatch_plan.features, ARGOS_FEATURE_TCP_SYN);
    opt_syn_rl = opt_syn && (dispatch_plan.features.unrated &
        argos_feature_bit(ARGOS_FEATURE_TCP_SYN)) == 0U;
    opt_v6 = argos_feature_selection_has(&dispatch_plan.features, ARGOS_FEATURE_IPV6);
    opt_ext_metrics = argos_feature_selection_has(&dispatch_plan.features,
                                                  ARGOS_FEATURE_EXTENDED_METRICS);
    opt_quic_heavy = argos_feature_selection_has(&dispatch_plan.features,
                                                 ARGOS_FEATURE_QUIC_STATEFUL);
    if (opt_ext_metrics) {
        if (!argos_runtime_state_enable_extended_metrics(&runtime_state)) {
            fprintf(stderr, "Error: unable to allocate extended-metrics state.\n");
            goto cleanup_state;
        }
    }

    /* Compile canonical dedup demand once, after defaults/option precedence.
     * Live inspector bypasses emission; -f 0 and wholly unrated modes need none. */
    if (!filter_mode1.is_active && rate_limit_ttl > 0 &&
        argos_dispatch_any_rate_limited(&dispatch_plan)) {
        if (!argos_dedup_prepare(&runtime_state.dedup))
            fprintf(stderr, "warning: dedup cache unavailable; telemetry remains unsuppressed.\n");
    }

    /* ARP/NDP ownership is learned only by the L2 engine. Prepare its bounded
     * family tables once; live inspector and disabled families reserve nothing. */
    int owner4_enabled = argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_ARP);
    int owner6_enabled = opt_v6 &&
                         (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_NDP) ||
                          argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_RA));
    if (!filter_mode1.is_active && (owner4_enabled || owner6_enabled) &&
        !argos_network_prepare_owners(&network_state, owner4_enabled, owner6_enabled))
        fprintf(stderr, "warning: network ownership cache unavailable; routed inference remains fail-open.\n");

    /* Stateless scratch follows TLS/QUIC demand; heavy reassembly state exists
     * only when -W is also active. Neither allocation is attempted by packets. */
    if (!filter_mode1.is_active &&
        argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_QUIC) &&
        !argos_quic_prepare(&quic_state, opt_quic_heavy))
        fprintf(stderr, "warning: QUIC workspace unavailable; encrypted fallback remains active.\n");

    argos_bpf_config_t bpf_cfg;
    argos_bpf_config_compile(&bpf_cfg, &dispatch_plan,
                             (uint16_t)runtime_cfg.wireguard_port);

    install_signal_handlers();

    argos_capture_state_t capture;
    int capture_count = argos_capture_open(&capture, iface, opt_promisc,
                                           filter_mode1.is_active, &bpf_cfg);
    if (capture_count < 0) { perror("capture initialization"); goto cleanup_capture; }
    if (opt_promisc && capture_count == 1 && capture.ifaces[0].type == LINK_PER_PACKET)
        fprintf(stderr, "warning: promiscuous mode with -i any is not enabled globally; use explicit interfaces with -p for full L2 visibility\n");
    if (capture_count == 0) { fprintf(stderr, "No valid interfaces bound. Exiting.\n"); goto cleanup_capture; }
    for (int i = 0; i < capture_count; ++i)
        argos_network_add_iface(&network_state, capture.ifaces[i].name,
                                capture.ifaces[i].ifindex);
    argos_network_learn_prefixes(&network_state);

    int lan_netlink_fd = argos_network_netlink_open();
    static unsigned char lan_netlink_epoll_tag;
    if (lan_netlink_fd >= 0) {
        if (argos_capture_add_external(&capture, lan_netlink_fd, &lan_netlink_epoll_tag) < 0) {
            fprintf(stderr, "warning: unable to add route-netlink listener to epoll: %s\n", strerror(errno));
            close(lan_netlink_fd); lan_netlink_fd = -1;
        }
    } else fprintf(stderr, "warning: route-netlink prefix refresh unavailable: %s\n", strerror(errno));

    /* Keep stdout line-buffered whenever it is active. With -U it is a
     * deliberate local fan-out alongside the remote UDP sink. */
    if (!use_ipc || use_remote) setvbuf(stdout, NULL, _IOLBF, 0);

    struct epoll_event events[ARGOS_CAPTURE_MAX_EVENTS];
    unsigned char buffer[ARGOS_CAPTURE_BUFFER_SIZE];

    /* Main packet capture and processing loop */
    while (running) {
        static uint64_t last_gc = 0, last_stats = 0, max_loop_us = 0;
        uint64_t now_us = get_current_usec();
        if (opt_quic_heavy && (now_us - last_gc > 2000000ULL)) {
            quic_heavy_gc(&quic_state);
            last_gc = now_us;
        }
        if (now_us - last_stats > 10000000ULL) {
            argos_capture_report_stats(&capture, opt_v6, max_loop_us);
            if (opt_v6) max_loop_us = 0;
            last_stats = now_us;
        }
        int nfds = epoll_wait(capture.epoll_fd, events, ARGOS_CAPTURE_MAX_EVENTS, 1000);
        if (nfds < 0 && errno != EINTR) break;
        uint64_t processing_start_us = opt_v6 ? get_current_usec() : 0;

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.ptr == &lan_netlink_epoll_tag) {
                if (lan_netlink_fd >= 0 && argos_network_netlink_drain(lan_netlink_fd))
                    argos_network_learn_prefixes(&network_state);
                continue;
            }

            argos_capture_iface_t *current_iface = (argos_capture_iface_t *)events[i].data.ptr;
            argos_capture_packet_t captured;
            if (!argos_capture_receive(current_iface, buffer, sizeof(buffer), &captured)) continue;
            ssize_t len = captured.len;
            uint64_t pkt_usec = captured.timestamp_usec ? captured.timestamp_usec : get_current_usec();
            uint16_t aux_vlan = captured.aux_vlan;
            int aux_vlan_valid = captured.aux_vlan_valid;
            link_type_t pkt_type = captured.type;
            int packet_ifindex = captured.packet_ifindex;

            argos_packet_view_t packet_view;
            if (!argos_packet_decode(pkt_type, buffer, (int)len, opt_v6, &packet_view)) continue;

            unsigned char *src_mac = packet_view.src_mac;
            unsigned char *dst_mac = packet_view.dst_mac;
            uint16_t l3_proto = packet_view.l3_proto;
            int l3_offset = packet_view.l3_offset;

            if (opt_sensor_mode) {
                argos_telemetry_capture_context(current_iface->name,
                                                packet_view.outer_vlan, packet_view.inner_vlan,
                                                aux_vlan_valid, aux_vlan);
            }

            static const unsigned char zero_mac[6] = {0,0,0,0,0,0};
            static const unsigned char bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
            /* RAW_IP (PPP/TUN/WireGuard) has no MAC, so zero-MAC validation
             * applies only to Ethernet and cooked link-layer frames. */
            if (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED) {
                if (memcmp(src_mac, zero_mac, 6) == 0 || memcmp(src_mac, bcast_mac, 6) == 0) continue;
            }

            uint32_t src_ip_num = 0, dst_ip_num = 0;
            argos_network_packet_context_t network_context = {0};
            struct in6_addr src_ip6_addr, dst_ip6_addr;
            memset(&src_ip6_addr, 0, sizeof(src_ip6_addr));
            memset(&dst_ip6_addr, 0, sizeof(dst_ip6_addr));
            int is_ipv6_packet = packet_view.ip_version == 6U;
            int is_ip_packet = packet_view.is_ip;
            uint8_t ip_protocol = packet_view.ip_protocol;
            uint8_t ip_ttl = packet_view.ip_ttl;
            int l4_offset = packet_view.l4_offset;
            int ipv4_is_frag = packet_view.nonfirst_fragment;

            if (packet_view.ip_version == 4U) {
                memcpy(&src_ip_num, packet_view.src_addr, 4U);
                memcpy(&dst_ip_num, packet_view.dst_addr, 4U);
                if (!argos_network_context4(&network_state, src_ip_num, dst_ip_num,
                                             packet_ifindex, &network_context)) continue;
            } else if (packet_view.ip_version == 6U) {
                memcpy(&src_ip6_addr, packet_view.src_addr, 16U);
                memcpy(&dst_ip6_addr, packet_view.dst_addr, 16U);
                if (!argos_network_context6(&network_state, &src_ip6_addr, &dst_ip6_addr,
                                             packet_ifindex, &network_context)) continue;
            } else if (argos_dispatch_l2_frame_enabled(&dispatch_plan, l3_proto)) {
                /* L2 discovery/control frames intentionally have no IP view. */
            } else {
                continue;
            }

            int is_outbound = network_context.source_side;
            int l3_packet_end = packet_view.packet_end;

            const struct in6_addr *filt_src_ip6 = is_ipv6_packet ? &src_ip6_addr : NULL;
            const struct in6_addr *filt_dst_ip6 = is_ipv6_packet ? &dst_ip6_addr : NULL;

            if (filter_exclude.is_active && argos_filter_match(&filter_exclude, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) {
                continue;
            }

            if (filter_mode1.is_active) {
                if (!argos_filter_match(&filter_mode1, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) continue;
                dump_target_packet(&packet_view);
                packet_count++; if (max_packets > 0 && packet_count >= max_packets) running = 0;
                continue;
            }

            if (pkt_type == LINK_ETHERNET) {
                if (is_hard_excluded_mac(src_mac) && is_outbound) continue;

                if (is_router_mac(src_mac)) {
                    if (!is_ip_packet || !argos_network_router_exception(ip_protocol,
                            buffer + l4_offset, l3_packet_end - l4_offset, is_outbound)) continue;
                }
            }

            /* Raw-IP links have no hardware MACs. Create stable L3-derived
             * surrogate identities before any MAC-keyed filter/state/dedup path.
             * Sensor/interface provenance remains separate in the OBS envelope. */
            if (pkt_type == LINK_RAW_IP && is_ip_packet) {
                if (is_ipv6_packet) {
                    argos_raw_identity_v6(src_ip6_addr.s6_addr, src_mac);
                    argos_raw_identity_v6(dst_ip6_addr.s6_addr, dst_mac);
                } else {
                    argos_raw_identity_v4(packet_view.src_addr, src_mac);
                    argos_raw_identity_v4(packet_view.dst_addr, dst_mac);
                }
            }

            if (filter_mode2.is_active) {
                if (!argos_filter_match(&filter_mode2, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) continue;
            }

            int routed_evidence = network_context.routed;

            unsigned char device_mac[6];
            /* L2 discovery/control frames identify their sender by source MAC.
             * Using the destination MAC would turn multicast addresses such as
             * LLDP's 01:80:c2:00:00:0e into fake device identities. */
            if (argos_dispatch_l2_frame_enabled(&dispatch_plan, l3_proto)) {
                memcpy(device_mac, src_mac, 6);
            } else if (is_outbound) {
                memcpy(device_mac, src_mac, 6);
            } else {
                memcpy(device_mac, dst_mac, 6);
            }
            if (memcmp(device_mac, zero_mac, 6) == 0 || memcmp(device_mac, bcast_mac, 6) == 0) continue;

            char mac_str[18];
            const char *routed_str = routed_evidence ? "|routed" : "";
            format_mac(device_mac, mac_str);

            /* L2 vectors must run even when there is no IP header. */
            if (l3_proto == 0x88cc) {
                if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_LLDP))
                    parse_lldp(buffer + l3_offset, (int)len - l3_offset, mac_str, routed_str,
                               argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_LLDP));
                if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_LLDP_MED)) {
                    argos_lldp_med_result_t med;
                    if (argos_lldp_med_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &med)) {
                        if (!dedup_should_suppress(mac_str, "LLDP-MED", med.detail,
                                argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_LLDP_MED)))
                            emit_telemetry("LLDP-MED|%s|-|-|%s%s\n", mac_str, med.detail, routed_str);
                    }
                }
                continue;
            }
            if (argos_dispatch_l2_protocol(l3_proto) == ARGOS_PROTOCOL_STP &&
                argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_STP)) {
                argos_stp_result_t stp;
                if (argos_stp_parse(buffer + l3_offset, (size_t)(l3_packet_end - l3_offset), &stp)) {
                    if (!dedup_should_suppress(mac_str, "STP", stp.detail,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_STP)))
                        emit_telemetry("STP|%s|-|-|%s%s\n", mac_str, stp.detail, routed_str);
                    continue;
                }
                if (argos_rstp_parse(buffer + l3_offset, (size_t)(l3_packet_end - l3_offset), &stp)) {
                    if (!dedup_should_suppress(mac_str, "STP", stp.detail,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_STP)))
                        emit_telemetry("STP|%s|-|-|%s%s\n", mac_str, stp.detail, routed_str);
                    continue;
                }
                argos_mstp_result_t mstp;
                if (argos_mstp_parse(buffer + l3_offset, (size_t)(l3_packet_end - l3_offset), &mstp)) {
                    if (!dedup_should_suppress(mac_str, "STP", mstp.detail,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_STP)))
                        emit_telemetry("STP|%s|-|-|%s%s\n", mac_str, mstp.detail, routed_str);
                    continue;
                }
            }
            if (l3_proto == 0x8809U &&
                argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_LACP)) {
                argos_lacp_result_t lacp;
                if (argos_lacp_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &lacp)) {
                    if (!dedup_should_suppress(mac_str, "LACP", lacp.detail,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_LACP)))
                        emit_telemetry("LACP|%s|-|-|%s%s\n", mac_str, lacp.detail, routed_str);
                }
                continue;
            }
            if (l3_proto == 0x88f7U &&
                argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_PTP)) {
                emit_ptp_vector(buffer + l3_offset, (size_t)(l3_packet_end - l3_offset),
                                mac_str, "-", "-", routed_str,
                                argos_dispatch_protocol_rate_limited(
                                    &dispatch_plan, ARGOS_PROTOCOL_PTP));
                continue;
            }
            argos_protocol_id_t l2_engine = argos_dispatch_l2_protocol(l3_proto);
            if (l2_engine < ARGOS_PROTOCOL_COUNT && l2_engine != ARGOS_PROTOCOL_STP &&
                l2_engine != ARGOS_PROTOCOL_ARP && l2_engine != ARGOS_PROTOCOL_LACP &&
                argos_dispatch_protocol_enabled(&dispatch_plan, l2_engine)) {
                argos_enterprise_result_t ent;
                if (argos_enterprise_parse_l2(l3_proto, buffer + l3_offset, l3_packet_end - l3_offset, &ent) && ent.emit) {
                    char ent_sig[640];
                    snprintf(ent_sig, sizeof(ent_sig), "%s|%s", ent.proto, ent.detail);
                    if (!dedup_should_suppress(mac_str, "ENT", ent_sig,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, l2_engine)))
                        emit_telemetry("ENT|%s|-|-|%s|%s\n", mac_str, ent.proto, ent.detail);
                }
                continue;
            }
            if (l3_proto == 0x0806) {
                if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_ARP))
                    parse_arp_vector(buffer + l3_offset, (int)len - l3_offset, packet_ifindex,
                                     argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_ARP));
                continue;
            }
            if (!is_ip_packet) continue;
            if (ipv4_is_frag) continue;

            char src_ip_str[INET6_ADDRSTRLEN] = {0}, dst_ip_str[INET6_ADDRSTRLEN] = {0};
            uint8_t protocol = ip_protocol, ttl = ip_ttl;

            if (l3_proto == 0x0800) {
                struct in_addr s_addr, d_addr; s_addr.s_addr = src_ip_num; d_addr.s_addr = dst_ip_num;
                inet_ntop(AF_INET, &s_addr, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &d_addr, dst_ip_str, sizeof(dst_ip_str));
            } else if (opt_v6 && l3_proto == 0x86dd) {
                inet_ntop(AF_INET6, &src_ip6_addr, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET6, &dst_ip6_addr, dst_ip_str, sizeof(dst_ip_str));
            } else { continue; }

            uint8_t flow_ip_version = is_ipv6_packet ? 6U : 4U;
            const uint8_t *flow_src_addr = is_ipv6_packet ? src_ip6_addr.s6_addr : (const uint8_t *)&src_ip_num;
            const uint8_t *flow_dst_addr = is_ipv6_packet ? dst_ip6_addr.s6_addr : (const uint8_t *)&dst_ip_num;

            if (protocol == IPPROTO_ICMPV6 && is_ipv6_packet) {
                if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_MLD) &&
                    ttl == 1U && l4_offset >= 0 && l4_offset < l3_packet_end) {
                    argos_membership_result_t membership;
                    if (argos_mld_parse(buffer + l4_offset, (size_t)(l3_packet_end - l4_offset), &membership) && membership.emit) {
                        char ent_mac[18], ent_sig[384];
                        format_mac(src_mac, ent_mac);
                        snprintf(ent_sig, sizeof(ent_sig), "%s|MLD|%s", src_ip_str, membership.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                                argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_MLD)))
                            emit_telemetry("ENT|%s|%s|%s|MLD|%s%s\n", ent_mac, src_ip_str, dst_ip_str, membership.detail, routed_str);
                    }
                }
                if (l4_offset >= 0 && l4_offset < l3_packet_end &&
                    (((buffer[l4_offset] == ND_ROUTER_ADVERT) &&
                      argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_RA)) ||
                     ((buffer[l4_offset] != ND_ROUTER_ADVERT) &&
                      argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_NDP)))) {
                    argos_protocol_id_t nd_engine = buffer[l4_offset] == ND_ROUTER_ADVERT ?
                        ARGOS_PROTOCOL_RA : ARGOS_PROTOCOL_NDP;
                    parse_ndp_vector(buffer + l4_offset, l3_packet_end - l4_offset, src_mac,
                                     &src_ip6_addr, src_ip_str, packet_ifindex,
                                     argos_dispatch_protocol_rate_limited(&dispatch_plan, nd_engine));
                }
                continue;
            }

            if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_IGMP) &&
                protocol == 2U && ttl == 1U &&
                l4_offset >= 0 && l4_offset < l3_packet_end) {
                argos_membership_result_t membership;
                if (argos_igmp_parse(buffer + l4_offset, (size_t)(l3_packet_end - l4_offset), &membership) && membership.emit) {
                    char ent_mac[18], ent_sig[384];
                    format_mac(src_mac, ent_mac);
                    snprintf(ent_sig, sizeof(ent_sig), "%s|IGMP|%s", src_ip_str, membership.detail);
                    if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_IGMP)))
                        emit_telemetry("ENT|%s|%s|%s|IGMP|%s%s\n", ent_mac, src_ip_str, dst_ip_str, membership.detail, routed_str);
                }
                continue;
            }

            if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_VRRP) &&
                protocol == 112U && ttl == 255U &&
                l4_offset >= 0 && l4_offset < l3_packet_end) {
                argos_vrrp_result_t vrrp;
                if (argos_vrrp_parse(buffer + l4_offset, (size_t)(l3_packet_end - l4_offset),
                                     flow_ip_version, &vrrp)) {
                    char ent_mac[18], ent_sig[384];
                    format_mac(src_mac, ent_mac);
                    snprintf(ent_sig, sizeof(ent_sig), "%s|VRRP|%s", src_ip_str, vrrp.detail);
                    if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_VRRP)))
                        emit_telemetry("ENT|%s|%s|%s|VRRP|%s%s\n",
                                       ent_mac, src_ip_str, dst_ip_str, vrrp.detail, routed_str);
                }
                continue;
            }

            if (argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_OSPF) &&
                protocol == 89U && l4_offset >= 0 && l4_offset < l3_packet_end) {
                argos_enterprise_result_t ent;
                if (argos_enterprise_parse_ipproto(protocol, buffer + l4_offset, l3_packet_end - l4_offset, &ent) && ent.emit) {
                    char ent_mac[18], ent_sig[640];
                    format_mac(src_mac, ent_mac);
                    snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent.proto, ent.detail);
                    if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                            argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_OSPF)))
                        emit_telemetry("ENT|%s|%s|%s|%s|%s%s\n", ent_mac, src_ip_str, dst_ip_str, ent.proto, ent.detail, routed_str);
                }
                continue;
            }

            if (protocol == IPPROTO_TCP) {
                argos_transport_view_t transport;
                if (!argos_packet_transport_normalized(&packet_view, IPPROTO_TCP, &transport)) continue;
                struct tcphdr tcp_hdr; memcpy(&tcp_hdr, buffer + l4_offset, sizeof(tcp_hdr));
                struct tcphdr *tcp = &tcp_hdr;
                uint16_t dport = transport.dport, sport = transport.sport;
                int tcp_hl = transport.header_len;
                int payload_offset = transport.payload_offset, payload_len = transport.payload_len;
                int http_tcp = argos_dispatch_protocol_enabled(
                    &dispatch_plan, ARGOS_PROTOCOL_HTTP) &&
                    (dport == 80U || dport == 8080U);
                int tls_port = argos_tls_tcp_port(dport) || argos_tls_tcp_port(sport);
                int tls_tcp = tls_port && argos_dispatch_protocol_enabled(
                    &dispatch_plan, ARGOS_PROTOCOL_TLS);
                int dot_tcp = (dport == 853U || sport == 853U) &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_DOT);
                argos_protocol_id_t tcp_engine = argos_dispatch_tcp_port_engine(
                    &dispatch_plan, sport, dport);
                int identity_tcp = argos_identity_enabled(runtime_cfg.identity_mode) &&
                    ((dport == 3389U && argos_dispatch_protocol_enabled(
                        &dispatch_plan, ARGOS_PROTOCOL_RDP)) ||
                     (dport == 445U && argos_dispatch_protocol_enabled(
                        &dispatch_plan, ARGOS_PROTOCOL_NTLM)) ||
                     (dport == 88U && argos_dispatch_protocol_enabled(
                        &dispatch_plan, ARGOS_PROTOCOL_KERBEROS)));
                int tcp_relevant = (opt_syn && (tcp->syn || tcp->rst || tcp->fin)) ||
                                   http_tcp || tls_tcp || dot_tcp ||
                                   tcp_engine < ARGOS_PROTOCOL_COUNT || identity_tcp;
                if (!tcp_relevant) continue;
                if (!routed_evidence && is_outbound && (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED)) {
                    if (is_ipv6_packet ? argos_network_owner6_mismatch(&network_state, &src_ip6_addr, src_mac) : argos_network_owner4_mismatch(&network_state, src_ip_num, src_mac)) {
                        routed_evidence = 1; routed_str = "|routed";
                    }
                }

                if (opt_syn) {
                    uint64_t now_usec = pkt_usec;

                    if (tcp->syn && !tcp->ack) {
                        if (opt_ext_metrics) {
                            argos_syn_track_t *tracked = argos_syn_track_find(&runtime_state, src_mac, sport, dport, flow_ip_version,
                                                                  flow_src_addr, flow_dst_addr, now_usec, 1);
                            if (tracked && tracked->ts_usec == 0) {
                                tracked->ts_usec = now_usec;
                                tracked->routed = (uint8_t)(routed_evidence ? 1 : 0);
                            }
                        }
                    }
                    else if (tcp->syn && tcp->ack) {
                        if (opt_ext_metrics) {
                            argos_syn_track_t *tracked = argos_syn_track_find(&runtime_state, dst_mac, dport, sport, flow_ip_version,
                                                                  flow_dst_addr, flow_src_addr, now_usec, 0);
                            if (tracked) {
                                if (tracked->ts_usec > 0 && now_usec > tracked->ts_usec) {
                                    uint64_t rtt_us = now_usec - tracked->ts_usec;
                                    char client_mac_str[18];
                                    char syn_payload[32], syn_sig[128];
                                    format_mac(tracked->mac, client_mac_str);
                                    snprintf(syn_payload, sizeof(syn_payload), "RTT:%u", sport);
                                    source_dedup_signature(syn_sig, sizeof(syn_sig), dst_ip_str, syn_payload,
                                                           tracked->routed ? "|routed" : "");
                                    if (!dedup_should_suppress(client_mac_str, "TCPLVL", syn_sig, opt_syn_rl)) {
                                        emit_telemetry("TCPLVL|%s|%s|%s|%u|%llu|0|SYNACK%s\n",
                                                       client_mac_str, dst_ip_str, src_ip_str, sport,
                                                       (unsigned long long)rtt_us,
                                                       tracked->routed ? "|routed" : "");
                                    }
                                }
                                tracked->valid = 0;
                            }
                        }
                    } else if (tcp->rst || tcp->fin) {
                        if (opt_ext_metrics) {
                            argos_syn_track_t *tracked = NULL;
                            const char *client_ip = NULL;
                            const char *server_ip = NULL;
                            uint16_t server_port = 0;

                            tracked = argos_syn_track_find(&runtime_state, src_mac, sport, dport, flow_ip_version,
                                                     flow_src_addr, flow_dst_addr, now_usec, 0);
                            if (tracked) {
                                client_ip = src_ip_str;
                                server_ip = dst_ip_str;
                                server_port = dport;
                            } else {
                                tracked = argos_syn_track_find(&runtime_state, dst_mac, dport, sport, flow_ip_version,
                                                         flow_dst_addr, flow_src_addr, now_usec, 0);
                                if (tracked) {
                                    client_ip = dst_ip_str;
                                    server_ip = src_ip_str;
                                    server_port = sport;
                                }
                            }

                            /* TCPLVL state records are intentionally limited to flows for
                             * which a SYN was observed. This keeps identity semantics
                             * stable and avoids flooding the gateway with unrelated FIN/RST. */
                            if (tracked) {
                                char client_mac_str[18];
                                char syn_payload[32], syn_sig[128];
                                format_mac(tracked->mac, client_mac_str);
                                snprintf(syn_payload, sizeof(syn_payload), "STATE:%u:%s", server_port, tcp->rst ? "R" : "F");
                                source_dedup_signature(syn_sig, sizeof(syn_sig), client_ip, syn_payload,
                                                       tracked->routed ? "|routed" : "");
                                if (!dedup_should_suppress(client_mac_str, "TCPLVL", syn_sig, opt_syn_rl)) {
                                    emit_telemetry("TCPLVL|%s|%s|%s|%u|0|0|%s%s\n",
                                                   client_mac_str, client_ip, server_ip, server_port,
                                                   tcp->rst ? "RST" : "FIN", tracked->routed ? "|routed" : "");
                                }
                            }
                        }
                    }

                    if (tcp->syn) {
                    int mss = -1, wscale = -1; char opts_str[64] = {0}; int opt_pos = 0;
                    if (tcp_hl > 20) {
                        const unsigned char *opts = buffer + l4_offset + 20;
                        int opt_total = tcp_hl - 20, op = 0;
                        while (op < opt_total && opt_pos < (int)sizeof(opts_str) - 4) {
                            uint8_t kind = opts[op];
                            if (kind == 0) { if (opt_pos > 0 && opts_str[opt_pos-1] != ',') opts_str[opt_pos++] = ','; opts_str[opt_pos++] = 'E'; break; }
                            if (kind == 1) { if (opt_pos > 0 && opts_str[opt_pos-1] != ',') opts_str[opt_pos++] = ','; opts_str[opt_pos++] = 'N'; op++; continue; }
                            if (op + 1 >= opt_total) break;
                            uint8_t olen = opts[op + 1];
                            if (olen < 2 || op + olen > opt_total) break;
                            if (opt_pos > 0 && opts_str[opt_pos-1] != ',') opts_str[opt_pos++] = ',';
                            if (kind == 2 && olen == 4) { mss = read_be16(opts + op + 2); opts_str[opt_pos++] = 'M'; opts_str[opt_pos++] = '*'; }
                            else if (kind == 3 && olen == 3) { wscale = opts[op + 2]; opts_str[opt_pos++] = 'W'; opts_str[opt_pos++] = '*'; }
                            else if (kind == 4 && olen == 2) { opts_str[opt_pos++] = 'S'; }
                            else if (kind == 8 && olen == 10) { opts_str[opt_pos++] = 'T'; }
                            else { opts_str[opt_pos++] = '?'; }
                            op += olen;
                        }
                    }
                    opts_str[opt_pos] = '\0'; if (opts_str[0] == '\0') strcpy(opts_str, "none");

                    if (tcp->ack && tcp->syn) {
                        /* Forwarded WAN replies use the router's L2 source MAC.
                         * They are consumed above for TCPLVL RTT only and must
                         * not surface as legacy external SYNACK telemetry. */
                        if (is_outbound && !is_router_mac(src_mac)) {
                            char syn_payload[32], syn_sig[128];
                            snprintf(syn_payload, sizeof(syn_payload), "%u", sport);
                            source_dedup_signature(syn_sig, sizeof(syn_sig), src_ip_str, syn_payload, routed_str);
                            if (!dedup_should_suppress(mac_str, "SYNACK", syn_sig, opt_syn_rl))
                                emit_telemetry("SYNACK|%s|%s|%u|%u|%d|%d|%s|%u%s\n", mac_str, src_ip_str, ttl, ntohs(tcp->window), wscale, mss, opts_str, sport, routed_str);
                        }
                    } else if (tcp->syn) {
                        char syn_payload[32], syn_sig[128];
                        snprintf(syn_payload, sizeof(syn_payload), "%u", dport);
                        source_dedup_signature(syn_sig, sizeof(syn_sig), src_ip_str, syn_payload, routed_str);
                        if (!dedup_should_suppress(mac_str, "SYN", syn_sig, opt_syn_rl))
                            emit_telemetry("SYN|%s|%s|%u|%u|%d|%d|%s|%u%s\n", mac_str, src_ip_str, ttl, ntohs(tcp->window), wscale, mss, opts_str, dport, routed_str);
                    }
                    }
                }

                int app_demand = http_tcp || tls_tcp || dot_tcp ||
                                 tcp_engine < ARGOS_PROTOCOL_COUNT || identity_tcp;
                int app_track = payload_len > 0 && app_demand;
                /* SYN is the connection-generation boundary for inspect-once state.
                 * Touch application state only when a selected payload engine owns
                 * this tuple; SYN-only telemetry has no application generation. */
                if (app_demand && tcp->syn && !tcp->ack)
                    argos_flow_reset_pair(&runtime_state.application, flow_ip_version,
                                          flow_src_addr, flow_dst_addr, sport, dport);
                if (app_track && argos_flow_should_skip(&runtime_state.application, flow_ip_version, flow_src_addr, flow_dst_addr,
                                      sport, dport)) {
                    continue;
                }

                if (http_tcp && payload_len > 16) {
                    const unsigned char *p = buffer + payload_offset;
                    if ((payload_len >= 4 && memcmp(p, "GET ", 4) == 0) || (payload_len >= 5 && memcmp(p, "POST ", 5) == 0)) {
                        const unsigned char *ua_hdr = find_bytes_ci(p, (size_t)payload_len, "\r\nUser-Agent: ", 14);
                        if (ua_hdr) {
                            const unsigned char *ua = ua_hdr + 14; size_t ua_avail = (size_t)((p + payload_len) - ua);
                            const unsigned char *end = find_bytes(ua, ua_avail, (const unsigned char *)"\r\n", 2);
                            if (end) {
                                int ualen = (int)(end - ua); if (ualen > 255) ualen = 255;
                                char ua_str[256]; sanitize_field(ua, ualen, ua_str, sizeof(ua_str), 0);
                                char http_sig[384];
                                source_dedup_signature(http_sig, sizeof(http_sig), src_ip_str, ua_str, routed_str);
                                if (ua_str[0] && !dedup_should_suppress(mac_str, "HTTP", http_sig,
                                        argos_dispatch_protocol_rate_limited(&dispatch_plan, ARGOS_PROTOCOL_HTTP)))
                                    emit_telemetry("HTTP|%s|%s|%s%s\n", mac_str, src_ip_str, ua_str, routed_str);
                            }
                        }
                    }
                }
                else if ((tls_tcp || dot_tcp) && argos_tls_tcp_port(dport) &&
                         payload_len > 44) {
                    parse_tls_sni(buffer + payload_offset, payload_len, mac_str, src_ip_str,
                                  dst_ip_str, dport, routed_str, tls_tcp,
                                  argos_dispatch_protocol_rate_limited(
                                      &dispatch_plan, ARGOS_PROTOCOL_TLS),
                                  dot_tcp,
                                  argos_dispatch_protocol_rate_limited(
                                      &dispatch_plan, ARGOS_PROTOCOL_DOT));
                }
                else if ((tls_tcp || dot_tcp) && argos_tls_tcp_port(sport) &&
                         payload_len > 44) {
                    argos_tls_server_result_t server;
                    if (argos_tls_server_parse(buffer + payload_offset, (size_t)payload_len, &server)) {
                        char srv_sig[256];
                        source_dedup_signature(srv_sig, sizeof(srv_sig), src_ip_str, server.fingerprint, routed_str);
                        int server_rl = (!tls_tcp || argos_dispatch_protocol_rate_limited(
                                             &dispatch_plan, ARGOS_PROTOCOL_TLS)) &&
                                        (!dot_tcp || argos_dispatch_protocol_rate_limited(
                                             &dispatch_plan, ARGOS_PROTOCOL_DOT));
                        if (!dedup_should_suppress(mac_str, "TLSSRV", srv_sig, server_rl))
                            emit_telemetry("TLSSRV|%s|%s|%s|%u|%s|%s%s\n", mac_str, src_ip_str, dst_ip_str, sport, server.fingerprint, server.alpn, routed_str);
                    }
                }

                argos_enterprise_result_t ent_tcp;
                int ent_tcp_seen = 0;
                if (tcp_engine < ARGOS_PROTOCOL_COUNT && payload_len > 0) {
                    ent_tcp_seen = argos_enterprise_parse_tcp(sport, dport, buffer + payload_offset, payload_len, &ent_tcp);
                    if (ent_tcp_seen && ent_tcp.emit) {
                        char ent_mac[18], ent_sig[768];
                        format_mac(src_mac, ent_mac);
                        snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent_tcp.proto, ent_tcp.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                                argos_dispatch_protocol_rate_limited(
                                    &dispatch_plan, tcp_engine)))
                            emit_telemetry("ENT|%s|%s|%s|%s|%s%s\n", ent_mac, src_ip_str, dst_ip_str, ent_tcp.proto, ent_tcp.detail, routed_str);
                    }
                }

                /* Identity is a separate explicit vector. RDP extraction is
                 * attempted only on client->server 3389 handshake payloads that
                 * enterprise mode already admitted; default ENT remains redacted. */
                if (argos_identity_enabled(runtime_cfg.identity_mode) && dport == 3389U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_RDP) &&
                    payload_len > 0) {
                    argos_identity_result_t ident;
                    if (argos_identity_rdp_mstshash(buffer + payload_offset, (size_t)payload_len,
                                                    argos_identity_raw(runtime_cfg.identity_mode), &ident)) {
                        emit_identity_observation(src_mac, src_ip_str, &ident, routed_str,
                                                  argos_dispatch_protocol_rate_limited(
                                                      &dispatch_plan, ARGOS_PROTOCOL_RDP));
                    }
                }

                /* NTLM Type 3 is the client authentication handshake carrying
                 * observed domain/user/workstation identity metadata. Only those
                 * three bounded security buffers are parsed; auth responses are not. */
                if (argos_identity_enabled(runtime_cfg.identity_mode) && dport == 445U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_NTLM) &&
                    payload_len > 0) {
                    argos_identity_result_t ids[3];
                    size_t id_count = argos_identity_ntlm_type3(
                        buffer + payload_offset, (size_t)payload_len,
                        argos_identity_raw(runtime_cfg.identity_mode), ids);
                    for (size_t ii = 0; ii < id_count; ++ii) {
                        emit_identity_observation(src_mac, src_ip_str, &ids[ii], routed_str,
                                                  argos_dispatch_protocol_rate_limited(
                                                      &dispatch_plan, ARGOS_PROTOCOL_NTLM));
                    }
                }

                /* Kerberos observed identity: only client->KDC AS-REQ cname/realm. */
                if (argos_identity_enabled(runtime_cfg.identity_mode) && dport == 88U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_KERBEROS) &&
                    payload_len > 0) {
                    argos_identity_result_t ident;
                    if (argos_identity_kerberos_asreq(buffer + payload_offset,
                                                      (size_t)payload_len, 1,
                                                      argos_identity_raw(runtime_cfg.identity_mode), &ident)) {
                        emit_identity_observation(src_mac, src_ip_str, &ident, routed_str,
                                                  argos_dispatch_protocol_rate_limited(
                                                      &dispatch_plan, ARGOS_PROTOCOL_KERBEROS));
                    }
                }

                if (app_track) {
                    int fingerprint_complete = app_flow_payload_complete(
                        sport, dport, buffer + payload_offset, payload_len);
                    if (ent_tcp_seen && ent_tcp.complete) fingerprint_complete = 1;
                    argos_flow_note_payload(&runtime_state.application, flow_ip_version, flow_src_addr, flow_dst_addr,
                                        sport, dport, fingerprint_complete);
                }
            }
            else if (protocol == IPPROTO_UDP) {
                if (l4_offset + 8 > l3_packet_end) continue;
                struct udphdr udp_hdr; memcpy(&udp_hdr, buffer + l4_offset, sizeof(udp_hdr));
                struct udphdr *udp = &udp_hdr;
                uint16_t dport = ntohs(udp->dest), sport = ntohs(udp->source);
                argos_protocol_id_t dhcp_engine = ARGOS_PROTOCOL_COUNT;
                if (is_ipv6_packet && sport == 546U && dport == 547U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_DHCPV6))
                    dhcp_engine = ARGOS_PROTOCOL_DHCPV6;
                else if (!is_ipv6_packet && (dport == 67U || sport == 67U) &&
                         argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_DHCP))
                    dhcp_engine = ARGOS_PROTOCOL_DHCP;
                argos_protocol_id_t discovery_engine = ARGOS_PROTOCOL_COUNT;
                if (dport == 1900U || sport == 1900U)
                    discovery_engine = argos_dispatch_first_enabled(
                        &dispatch_plan, ARGOS_PROTOCOL_SSDP, ARGOS_PROTOCOL_UPNP,
                        ARGOS_PROTOCOL_COUNT);
                else if ((dport == 3702U || sport == 3702U) &&
                         argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_WSD))
                    discovery_engine = ARGOS_PROTOCOL_WSD;
                else if ((dport == 5353U || sport == 5353U) &&
                         argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_MDNS))
                    discovery_engine = ARGOS_PROTOCOL_MDNS;
                int nbns_udp = (dport == 137U || sport == 137U) &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_NBNS);
                int dns_udp = (dport == 53U || sport == 53U) &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_DNS);
                int quic_udp = dport == 443U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_QUIC);
                int wireguard_udp =
                    (sport == runtime_cfg.wireguard_port || dport == runtime_cfg.wireguard_port) &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_WIREGUARD);
                int ptp_udp = argos_dispatch_ptp_udp_enabled(&dispatch_plan, sport, dport);
                argos_protocol_id_t udp_engine = argos_dispatch_udp_port_engine(
                    &dispatch_plan, sport, dport);
                int udp_relevant = dhcp_engine < ARGOS_PROTOCOL_COUNT ||
                                   discovery_engine < ARGOS_PROTOCOL_COUNT || nbns_udp ||
                                   dns_udp || quic_udp || wireguard_udp || ptp_udp ||
                                   udp_engine < ARGOS_PROTOCOL_COUNT;
                if (!udp_relevant) continue;
                if (!routed_evidence && is_outbound && (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED)) {
                    if (is_ipv6_packet ? argos_network_owner6_mismatch(&network_state, &src_ip6_addr, src_mac) : argos_network_owner4_mismatch(&network_state, src_ip_num, src_mac)) {
                        routed_evidence = 1; routed_str = "|routed";
                    }
                }
                argos_transport_view_t transport;
                if (!argos_packet_transport_normalized(&packet_view, IPPROTO_UDP, &transport)) continue;
                int payload_offset = transport.payload_offset;
                int payload_len = transport.payload_len;
                if (payload_len <= 0) continue;

                const unsigned char *payload = buffer + payload_offset;

                /* UDP/623 is a shared RMCP envelope. Resolve its one-byte
                 * class before the parser so IPMI and ASF cannot inherit each
                 * other's payload work; explicit RMCP intentionally owns both. */
                if (dport == 623U || sport == 623U) {
                    if (payload_len < 4)
                        udp_engine = ARGOS_PROTOCOL_COUNT;
                    else if (payload[3] == 0x06U)
                        udp_engine = argos_dispatch_first_enabled(
                            &dispatch_plan, ARGOS_PROTOCOL_ASF,
                            ARGOS_PROTOCOL_RMCP, ARGOS_PROTOCOL_COUNT);
                    else if (payload[3] == 0x07U)
                        udp_engine = argos_dispatch_first_enabled(
                            &dispatch_plan, ARGOS_PROTOCOL_IPMI,
                            ARGOS_PROTOCOL_RMCP, ARGOS_PROTOCOL_COUNT);
                    else
                        udp_engine = ARGOS_PROTOCOL_COUNT;
                }

                if (dhcp_engine == ARGOS_PROTOCOL_DHCPV6) {
                    parse_dhcp6(payload, payload_len, mac_str, src_ip_str, routed_str,
                                argos_dispatch_protocol_rate_limited(
                                    &dispatch_plan, ARGOS_PROTOCOL_DHCPV6));
                }
                else if (dhcp_engine == ARGOS_PROTOCOL_DHCP) {
                    parse_dhcp(payload, payload_len, mac_str, src_ip_str, routed_str,
                               argos_dispatch_protocol_rate_limited(
                                   &dispatch_plan, ARGOS_PROTOCOL_DHCP));
                }
                else if (nbns_udp) {
                    parse_netbios(payload, payload_len, mac_str, src_ip_str, routed_str,
                                  argos_dispatch_protocol_rate_limited(
                                      &dispatch_plan, ARGOS_PROTOCOL_NBNS));
                }
                else if ((discovery_engine == ARGOS_PROTOCOL_SSDP ||
                          discovery_engine == ARGOS_PROTOCOL_UPNP ||
                          discovery_engine == ARGOS_PROTOCOL_WSD)) {
                    char clean_payload[513]; int plen = (payload_len > 512) ? 512 : payload_len;
                    sanitize_field(payload, plen, clean_payload, sizeof(clean_payload), 1);
                    char l7_sig[640];
                    source_dedup_signature(l7_sig, sizeof(l7_sig), src_ip_str, clean_payload, routed_str);
                    if (clean_payload[0] && !dedup_should_suppress(mac_str, "L7", l7_sig,
                            argos_dispatch_protocol_rate_limited(
                                &dispatch_plan, discovery_engine))) {
                        emit_telemetry("L7|%s|%s|%d|%s%s\n", mac_str, src_ip_str, (dport == 1900 || dport == 3702) ? dport : sport, clean_payload, routed_str);
                    }
                }
                else if (discovery_engine == ARGOS_PROTOCOL_MDNS) {
                    parse_mdns(payload, payload_len, mac_str, src_ip_str,
                               (dport == 5353) ? dport : sport, routed_str,
                               argos_dispatch_protocol_rate_limited(
                                   &dispatch_plan, ARGOS_PROTOCOL_MDNS));
                }
                else if (dns_udp) {
                    if (payload_len > 12) {
                        uint16_t flags = read_be16(payload + 2);
                        int is_response = (flags & 0x8000) != 0;
                        uint16_t txid = read_be16(payload);

                        if (!is_response && dport == 53) {
                            char qname[256];
                            uint16_t qtype = 0;
                            if (decode_dns_name(payload, payload_len, 12, qname, sizeof(qname)) > 0 && qname[0]) {
                                (void)dns_question_qtype(payload, payload_len, 12, &qtype);
                                if (opt_ext_metrics && qtype != 0U) {
                                    (void)argos_dns_track_put(runtime_state.dns_track, ARGOS_RUNTIME_DNS_SLOTS,
                                                              flow_ip_version, flow_src_addr, flow_dst_addr,
                                                              sport, dport, txid, qtype, qname, pkt_usec,
                                                              src_mac, (uint8_t)(routed_evidence ? 1 : 0));
                                }
                                char dns_sig[384];
                                source_dedup_signature(dns_sig, sizeof(dns_sig), src_ip_str, qname, routed_str);
                                if (!dedup_should_suppress(mac_str, "DNS", dns_sig,
                                        argos_dispatch_protocol_rate_limited(
                                            &dispatch_plan, ARGOS_PROTOCOL_DNS))) {
                                    emit_telemetry("DNS|%s|%s|%s%s\n", mac_str, src_ip_str, qname, routed_str);
                                }
                            }
                        }
                        else if (is_response && sport == 53) {
                            if (opt_ext_metrics && read_be16(payload + 4) > 0U) {
                                char response_qname[256];
                                uint16_t response_qtype = 0U;
                                if (decode_dns_name(payload, payload_len, 12, response_qname, sizeof(response_qname)) > 0 &&
                                    response_qname[0] && dns_question_qtype(payload, payload_len, 12, &response_qtype)) {
                                    argos_dns_track_t *tracked = argos_dns_track_find_response(
                                        runtime_state.dns_track, ARGOS_RUNTIME_DNS_SLOTS, flow_ip_version, flow_dst_addr, flow_src_addr,
                                        dport, sport, txid, response_qtype, response_qname, pkt_usec);
                                    if (tracked) {
                                        uint8_t rcode = flags & 0x000F;
                                        uint64_t latency_us = pkt_usec - tracked->ts_usec;
                                        float ent = calculate_entropy(tracked->domain);

                                        char client_mac_str[18];
                                        format_mac(tracked->mac, client_mac_str);

                                        char dnsext_sig[384];
                                        source_dedup_signature(dnsext_sig, sizeof(dnsext_sig), dst_ip_str,
                                                               tracked->domain, tracked->routed ? "|routed" : "");
                                        if (!dedup_should_suppress(client_mac_str, "DNSEXT", dnsext_sig,
                                                argos_dispatch_protocol_rate_limited(
                                                    &dispatch_plan, ARGOS_PROTOCOL_DNS))) {
                                            emit_telemetry("DNSEXT|%s|%s|%s|%s|%u|%u|%.2f|%.2f%s\n",
                                                client_mac_str, dst_ip_str, src_ip_str, tracked->domain,
                                                (unsigned)tracked->qtype, (unsigned)rcode,
                                                (float)latency_us / 1000.0f, ent, tracked->routed ? "|routed" : "");
                                        }
                                        char alert_sig[192];
                                        source_dedup_signature(alert_sig, sizeof(alert_sig), dst_ip_str,
                                                               "HIGH_DNS_ENTROPY", tracked->routed ? "|routed" : "");
                                        if (ent >= 4.2f &&
                                            !dedup_should_suppress(client_mac_str, "ALERT", alert_sig,
                                                argos_dispatch_protocol_rate_limited(
                                                    &dispatch_plan, ARGOS_PROTOCOL_DNS))) {
                                            emit_telemetry("ALERT|%s|%s|HIGH_DNS_ENTROPY|%s|%.2f%s\n",
                                                           client_mac_str, dst_ip_str, tracked->domain, ent,
                                                           tracked->routed ? "|routed" : "");
                                        }
                                        tracked->valid = 0;
                                    }
                                }
                            }
                        }
                    }
                }
                else if (quic_udp) {
                    parse_quic(payload, payload_len, mac_str, src_ip_str, dst_ip_str,
                               dport, routed_str,
                               argos_dispatch_protocol_rate_limited(
                                   &dispatch_plan, ARGOS_PROTOCOL_QUIC));
                }
                else if (ptp_udp) {
                    emit_ptp_vector(payload, (size_t)payload_len, mac_str,
                                    src_ip_str, dst_ip_str, routed_str,
                                    argos_dispatch_protocol_rate_limited(
                                        &dispatch_plan, ARGOS_PROTOCOL_PTP));
                }
                if (udp_engine == ARGOS_PROTOCOL_HSRP && ttl == 1U) {
                    char ent_mac[18], ent_sig[512];
                    format_mac(src_mac, ent_mac);

                    argos_hsrp2_result_t hsrp2;
                    if (argos_hsrp2_parse(payload, (size_t)payload_len, &hsrp2)) {
                        snprintf(ent_sig, sizeof(ent_sig), "%s|HSRP2|%s", src_ip_str, hsrp2.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                                argos_dispatch_protocol_rate_limited(
                                    &dispatch_plan, ARGOS_PROTOCOL_HSRP)))
                            emit_telemetry("ENT|%s|%s|%s|HSRP2|%s%s\n",
                                           ent_mac, src_ip_str, dst_ip_str, hsrp2.detail, routed_str);
                    } else {
                        argos_hsrp1_result_t hsrp1;
                        if (argos_hsrp1_parse(payload, (size_t)payload_len, &hsrp1)) {
                            snprintf(ent_sig, sizeof(ent_sig), "%s|HSRP|%s", src_ip_str, hsrp1.detail);
                            if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                                    argos_dispatch_protocol_rate_limited(
                                        &dispatch_plan, ARGOS_PROTOCOL_HSRP)))
                                emit_telemetry("ENT|%s|%s|%s|HSRP|%s%s\n",
                                               ent_mac, src_ip_str, dst_ip_str, hsrp1.detail, routed_str);
                        }
                    }
                }
                if (udp_engine == ARGOS_PROTOCOL_RIP) {
                    argos_network_rip_result_t rip;
                    int parsed = 0;
                    if (!is_ipv6_packet && (sport == 520U || dport == 520U))
                        parsed = argos_network_rip_parse(payload, (size_t)payload_len, &rip);
                    else if (is_ipv6_packet && (sport == 521U || dport == 521U))
                        parsed = argos_network_ripng_parse(payload, (size_t)payload_len, &rip);
                    if (parsed && !dedup_should_suppress(mac_str, "RIP", rip.detail,
                            argos_dispatch_protocol_rate_limited(
                                &dispatch_plan, ARGOS_PROTOCOL_RIP)))
                        emit_telemetry("RIP|%s|%s|%s|%s%s\n", mac_str,
                                       src_ip_str, dst_ip_str, rip.detail, routed_str);
                }
                if (wireguard_udp) {
                    /* Type-4 transport packets can be an elephant UDP flow. Validate the
                     * exact WireGuard framing cheaply, then bypass the full parser for
                     * repeated transport-data in a short epoch. Handshake/cookie types
                     * and keepalives are always parsed. DNS/DHCP/QUIC/STUN/CoAP/NTP are
                     * deliberately outside this suppression table. */
                    int wg_transport = argos_wireguard_transport_kind(payload, (size_t)payload_len);
                    int wg_suppressed = wg_transport == 2 &&
                        argos_udp_suppress_recent(runtime_state.udp_suppress, flow_ip_version,
                                                  flow_src_addr, flow_dst_addr, sport, dport,
                                                  4U, (uint64_t)time(NULL));
                    if (!wg_suppressed) {
                        argos_wireguard_result_t wg;
                        if (argos_wireguard_parse(payload, (size_t)payload_len, &wg) && wg.emit) {
                            char ent_mac[18], ent_sig[384];
                            format_mac(src_mac, ent_mac);
                            snprintf(ent_sig, sizeof(ent_sig), "%s|WireGuard|%s", src_ip_str, wg.detail);
                            if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                                    argos_dispatch_protocol_rate_limited(
                                        &dispatch_plan, ARGOS_PROTOCOL_WIREGUARD)))
                                emit_telemetry("ENT|%s|%s|%s|WireGuard|%s%s\n",
                                               ent_mac, src_ip_str, dst_ip_str, wg.detail, routed_str);
                        }
                    }
                }
                if (udp_engine < ARGOS_PROTOCOL_COUNT &&
                    udp_engine != ARGOS_PROTOCOL_HSRP &&
                    udp_engine != ARGOS_PROTOCOL_RIP) {
                    argos_enterprise_result_t ent_udp;
                    if (argos_enterprise_parse_udp(sport, dport, payload, payload_len, &ent_udp) && ent_udp.emit) {
                        char ent_mac[18], ent_sig[768];
                        format_mac(src_mac, ent_mac);
                        snprintf(ent_sig, sizeof(ent_sig), "%s|%s|%s", src_ip_str, ent_udp.proto, ent_udp.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig,
                                argos_dispatch_protocol_rate_limited(
                                    &dispatch_plan, udp_engine)))
                            emit_telemetry("ENT|%s|%s|%s|%s|%s%s\n", ent_mac, src_ip_str, dst_ip_str, ent_udp.proto, ent_udp.detail, routed_str);
                    }
                }
                /* RADIUS observed identity: client Access-Request User-Name only. */
                if (argos_identity_enabled(runtime_cfg.identity_mode) && dport == 1812U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_RADIUS)) {
                    argos_identity_result_t ident;
                    if (argos_identity_radius_access_request(payload, (size_t)payload_len,
                                                             argos_identity_raw(runtime_cfg.identity_mode), &ident)) {
                        emit_identity_observation(src_mac, src_ip_str, &ident, routed_str,
                                                  argos_dispatch_protocol_rate_limited(
                                                      &dispatch_plan, ARGOS_PROTOCOL_RADIUS));
                    }
                }

                /* UDP/88 uses the same strictly bounded AS-REQ parser without
                 * the RFC 4120 TCP record-length prefix. */
                if (argos_identity_enabled(runtime_cfg.identity_mode) && dport == 88U &&
                    argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_KERBEROS)) {
                    argos_identity_result_t ident;
                    if (argos_identity_kerberos_asreq(payload, (size_t)payload_len, 0,
                                                      argos_identity_raw(runtime_cfg.identity_mode), &ident)) {
                        emit_identity_observation(src_mac, src_ip_str, &ident, routed_str,
                                                  argos_dispatch_protocol_rate_limited(
                                                      &dispatch_plan, ARGOS_PROTOCOL_KERBEROS));
                    }
                }
            }
        }
        if (opt_v6) {
            uint64_t processing_end_us = get_current_usec();
            if (processing_end_us >= processing_start_us && processing_end_us - processing_start_us > max_loop_us)
                max_loop_us = processing_end_us - processing_start_us;
        }
    }

    if (lan_netlink_fd >= 0) close(lan_netlink_fd);
    exit_status = 0;
cleanup_capture:
    /* Every open attempt leaves a closeable owner; CLI failures never reach it. */
    argos_capture_close(&capture);
cleanup_state:
    argos_telemetry_close();
    argos_runtime_state_destroy(&runtime_state);
    argos_network_destroy(&network_state);
    argos_quic_destroy(&quic_state);
    return exit_status;
}
#endif
