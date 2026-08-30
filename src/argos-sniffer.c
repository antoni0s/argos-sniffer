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
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
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
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

#ifndef ARGOS_QUIC_STUB
#include "argos_quic.h"
#include "argos_quic_heavy.h"
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

#define VERSION "5.2.2"

/* ============================================================================
 * SECTION: Telemetry Output Engine
 * Handles transmission of formatted telemetry strings to any combination of:
 *   - a local Unix domain socket (-o <path>), e.g. a local collector daemon
 *     running on the same router;
 *   - a remote UDP socket (-U <ip>:<port> / -U [ipv6]:<port>), i.e. the
 *     "Native Remote Socket" feature -- a direct, dependency-free way to
 *     ship telemetry straight to a central server over the network without
 *     needing a local relay process;
 *   - syslog (-u), a local syslog-only sink for daemon.info telemetry;
 *   - stdout, used for local daemon pipelines (and always retained with -U).
 * All configured sinks receive every record. The -U path intentionally fans out
 * to both UDP and stdout so a supervising daemon can continue parsing events.
 * ============================================================================ */
static int use_syslog = 0;

#ifdef ARGOS_PORTABLE_TEST
static void emit_telemetry(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void emit_telemetry(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#else
static int ipc_sock = -1;
static struct sockaddr_un ipc_addr;
static int use_ipc = 0;

static int remote_sock = -1;
static struct sockaddr_storage remote_addr;
static socklen_t remote_addr_len = 0;
static int use_remote = 0;

/**
 * Parses a "host:port" (or "[host]:port" for an IPv6 literal, per the usual
 * URI bracket convention needed to disambiguate the address's own colons
 * from the port separator) spec for the -U remote telemetry socket.
 * `host` may be a numeric IPv4/IPv6 address or a resolvable hostname --
 * resolution is done once at startup via getaddrinfo(), which also gives us
 * a ready-to-use sockaddr for whichever address family the host resolved
 * to. On success fills *out_addr and *out_len and returns 0; returns -1 (with a
 * message already printed to stderr) on any parse or resolution failure.
 */
static int parse_host_port(const char *spec, struct sockaddr_storage *out_addr, socklen_t *out_len) {
    char host[256]; const char *port_str;

    if (spec[0] == '[') {
        /* "[host]:port" -- bracketed form, required for IPv6 literals like
         * [2001:db8::1]:5140 since a bare IPv6 address already contains
         * colons. */
        const char *close = strchr(spec, ']');
        if (!close || close[1] != ':' || close[2] == '\0') {
            fprintf(stderr, "Error: -U expects [host]:port for a bracketed address, got '%s'\n", spec);
            return -1;
        }
        size_t hlen = (size_t)(close - (spec + 1));
        if (hlen == 0 || hlen >= sizeof(host)) {
            fprintf(stderr, "Error: -U host part too long in '%s'\n", spec);
            return -1;
        }
        memcpy(host, spec + 1, hlen); host[hlen] = '\0';
        port_str = close + 2;
    } else {
        /* Plain "host:port" -- split on the last colon so IPv4 dotted-quads
         * and hostnames (which never contain a colon) work as expected. */
        const char *colon = strrchr(spec, ':');
        if (!colon || colon == spec || colon[1] == '\0') {
            fprintf(stderr, "Error: -U expects host:port, got '%s'\n", spec);
            return -1;
        }
        size_t hlen = (size_t)(colon - spec);
        if (hlen == 0 || hlen >= sizeof(host)) {
            fprintf(stderr, "Error: -U host part missing or too long in '%s'\n", spec);
            return -1;
        }
        memcpy(host, spec, hlen); host[hlen] = '\0';
        if (strchr(host, ':')) {
            fprintf(stderr, "Error: -U IPv6 literals must use [host]:port, got '%s'\n", spec);
            return -1;
        }
        port_str = colon + 1;
    }

    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* accept whichever of IPv4/IPv6 the host resolves to */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "Error: -U could not resolve '%s': %s\n", spec, gai_strerror(rc));
        return -1;
    }
    memcpy(out_addr, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/**
 * Emits a telemetry record using a formatted string. Sends to every
 * configured sink (local IPC socket and/or remote UDP socket); if neither
 * is configured, prints to stdout instead. Both sendto() calls use
 * MSG_DONTWAIT on unconnected datagram sockets, so a slow/unreachable
 * collector (local or remote) can never stall the packet capture loop --
 * telemetry delivery here is deliberately best-effort/fire-and-forget, the
 * same trade-off the pre-existing -o local IPC path already made.
 */
static void emit_telemetry(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void emit_telemetry(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (len < 0) return;
    if (len >= (int)sizeof(buffer)) {
        /* Still emit a truncated record rather than silently dropping a
         * long HTTP UA / DNS name -- collectors would otherwise miss the event. */
        len = (int)sizeof(buffer) - 1;
    }
    if (len > 0) {
        int sent_anywhere = 0;
        if (use_ipc) {
            sendto(ipc_sock, buffer, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr));
            sent_anywhere = 1;
        }
        if (use_remote) {
            sendto(remote_sock, buffer, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&remote_addr, remote_addr_len);
            sent_anywhere = 1;
        }
#ifndef ARGOS_PORTABLE_TEST
        if (use_syslog) {
            int syslog_len = len;
            while (syslog_len > 0 &&
                   (buffer[syslog_len - 1] == '\n' || buffer[syslog_len - 1] == '\r')) {
                syslog_len--;
            }
            if (syslog_len > 0) {
                syslog(LOG_INFO, "%.*s", syslog_len, buffer);
            }
            sent_anywhere = 1;
        }
#endif
        /* -U is a fan-out sink: keep stdout active for the local daemon while
         * also delivering the same record to the remote UDP collector. */
        if (use_remote || !use_ipc) {
            fputs(buffer, stdout);
        } else if (!sent_anywhere) {
            fputs(buffer, stdout);
        }
    }
}
#endif

/* ============================================================================
 * SECTION: Micro MD5 Implementation (For JA4 Fingerprinting)
 * Provides a lightweight, optimized MD5 calculation routine tailored for JA4
 * cipher and extension string hashing.
 * ============================================================================ */
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define MD5_STACK_BUF 8192 /* JA4 inputs here are bounded (cipher_hex<4096, ext_hex<2048) */

/**
 * Computes the MD5 hash of an input message and outputs it as a lowercase hex string.
 *
 * NOTE: MD5 is defined over 32-bit words in LITTLE-ENDIAN byte order, and the
 * trailing 64-bit bit-length field must also be written little-endian. This
 * implementation reads/writes those multi-byte values explicitly byte-by-byte
 * (see below) instead of casting the buffer to uint32_t* and dereferencing
 * it, which would silently produce wrong hashes on a big-endian host (some
 * MIPS-based OpenWrt boards are big-endian) and would also be an unaligned /
 * strict-aliasing violation.
 */
static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const uint32_t MD5_S[16] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};

static void md5_hash(const uint8_t *initial_msg, size_t initial_len, char *out_hex) {
    uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
    /* Pad message: 1 marker bit (0x80 byte) + zero padding so length % 64 == 56,
     * then 8 more bytes for the 64-bit original-length-in-bits field. */
    size_t new_len = ((((initial_len + 8) / 64) + 1) * 64) - 8;
    size_t total_len = new_len + 64;

    uint8_t stackbuf[MD5_STACK_BUF];
    uint8_t *heapbuf = NULL;
    uint8_t *msg = stackbuf;
    if (total_len > sizeof(stackbuf)) {
        heapbuf = calloc(total_len, 1);
        if (!heapbuf) {
            strcpy(out_hex, "00000000000000000000000000000000");
            return;
        }
        msg = heapbuf;
    } else {
        memset(stackbuf, 0, total_len);
    }
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 128; /* append the single '1' padding bit (0x80 = 1000 0000) */

    /* Write the 64-bit "message length in bits" field explicitly as
     * little-endian bytes. JA4 inputs here are always well under 2^32 bits,
     * so the upper 4 bytes stay zero (already zeroed by memset/calloc above). */
    uint32_t bits_len = 8 * (uint32_t)initial_len;
    msg[new_len + 0] = (uint8_t)(bits_len);
    msg[new_len + 1] = (uint8_t)(bits_len >> 8);
    msg[new_len + 2] = (uint8_t)(bits_len >> 16);
    msg[new_len + 3] = (uint8_t)(bits_len >> 24);

    /* Process the padded message in 64-byte (16 x 32-bit word) blocks. */
    for (size_t offset = 0; offset < new_len + 8; offset += 64) {
        /* Load this block's 16 words explicitly as little-endian, byte by
         * byte -- portable across host endianness and avoids casting a raw
         * byte pointer to uint32_t* (alignment/strict-aliasing safe). */
        uint32_t w[16];
        for (int wi = 0; wi < 16; wi++) {
            const uint8_t *b = msg + offset + (size_t)wi * 4;
            w[wi] = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3;
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16)      { f = (b & c) | ((~b) & d); g = i; }
            else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
            else             { f = c ^ (b | (~d)); g = (7 * i) % 16; }
            
            uint32_t temp = d;
            d = c; c = b;
            
            b = b + LEFTROTATE((a + f + MD5_K[i] + w[g]), MD5_S[(i/16)*4 + (i%4)]);
            a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
    }
    if (heapbuf) free(heapbuf);
    snprintf(out_hex, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        h0&0xff, (h0>>8)&0xff, (h0>>16)&0xff, (h0>>24)&0xff,
        h1&0xff, (h1>>8)&0xff, (h1>>16)&0xff, (h1>>24)&0xff,
        h2&0xff, (h2>>8)&0xff, (h2>>16)&0xff, (h2>>24)&0xff,
        h3&0xff, (h3>>8)&0xff, (h3>>16)&0xff, (h3>>24)&0xff);
}

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

typedef struct {
    uint16_t txid;
    uint16_t qtype;
    uint32_t src_ip;
    uint64_t ts_usec;
    char domain[128];
    uint8_t mac[6];
    uint8_t routed;
} dns_track_t;
static dns_track_t *dns_table = NULL;

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

static uint32_t addr6_key(const struct in6_addr *a) {
    uint32_t k = (uint32_t)hash_bytes(a->s6_addr, 16);
    return k ? k : 1u; /* never collide with "no address" */
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
typedef enum { LINK_UNSUPPORTED = 0, LINK_ETHERNET = 1, LINK_RAW_IP = 2, LINK_COOKED = 3, LINK_PER_PACKET = 4 } link_type_t;
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
#endif

static int is_lan_ipv4(uint32_t ip_be) {
    if (is_private_ipv4(ip_be)) return 1;
    for (int i = 0; i < lan_pfx_count; i++) {
        if (lan_pfx[i].family == AF_INET && (ip_be & lan_pfx[i].v4mask) == lan_pfx[i].v4) return 1;
    }
    return 0;
}

static int is_lan_ipv6(const struct in6_addr *addr) {
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

/**
 * Walk IPv6 extension headers to the real L4 protocol. Returns 0 and fills
 * *proto_out / *l4_off_out on success, -1 if the chain is truncated, loops,
 * or is a non-first fragment (no L4 header in this packet).
 */
static int skip_ipv6_exthdrs(const unsigned char *buf, int len, int l3_off,
                             uint8_t *proto_out, int *l4_off_out) {
    if (len < l3_off + 40) return -1;
    uint8_t nxt = buf[l3_off + 6];
    int off = l3_off + 40;
    for (int guard = 0; guard < 8; guard++) {
        if (nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING || nxt == IPPROTO_DSTOPTS) {
            if (off + 2 > len) return -1;
            int hdrlen = ((int)buf[off + 1] + 1) * 8;
            nxt = buf[off];
            off += hdrlen;
            if (off > len) return -1;
        } else if (nxt == IPPROTO_FRAGMENT) {
            if (off + 8 > len) return -1;
            uint16_t frag_off = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);
            if ((frag_off & 0xFFF8) != 0) return -1; /* non-first fragment: no L4 header */
            nxt = buf[off];
            off += 8;
        } else if (nxt == 51 /* IPPROTO_AH */) {
            if (off + 2 > len) return -1;
            int hdrlen = ((int)buf[off + 1] + 2) * 4;
            nxt = buf[off];
            off += hdrlen;
            if (off > len) return -1;
        } else if (nxt == IPPROTO_NONE) {
            return -1;
        } else {
            break;
        }
    }
    *proto_out = nxt;
    *l4_off_out = off;
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
#define DEDUP_SLOTS 2048
#define DEDUP_PROBES 8
#define ARP_DEDUP_TTL_SECS 900
#define NDP_DEDUP_TTL_SECS 900
#define RA_DEDUP_TTL_SECS 1800
static int rate_limit_ttl = 35;
typedef struct { uint64_t key; time_t last_seen; uint8_t valid; } dedup_entry_t;
static dedup_entry_t *dedup_table = NULL;

/**
 * Determines whether a telemetry event should be suppressed based on rate limiting.
 */
static int dedup_should_suppress_for(const char *mac, const char *evtype, const char *payload,
                                     int rl_enabled, int ttl, int sliding) {
    if (!rl_enabled || ttl <= 0) return 0;
    if (!dedup_table) {
        dedup_table = (dedup_entry_t *)calloc(DEDUP_SLOTS, sizeof(*dedup_table));
        if (!dedup_table) return 0; /* telemetry must fail open, never drop silently */
    }
    static const char sep = '|';
    const char *pl = payload ? payload : "";
    uint64_t h = 1469598103934665603ULL;
    h = hash_update(h, mac, strlen(mac));
    h = hash_update(h, &sep, 1U);
    h = hash_update(h, evtype, strlen(evtype));
    h = hash_update(h, &sep, 1U);
    h = hash_update(h, pl, strlen(pl));
    size_t base = (size_t)(h & (DEDUP_SLOTS - 1U));
    time_t now = time(NULL);
    size_t replace_slot = base;
    time_t oldest_ts = now;

    for (size_t probe = 0; probe < DEDUP_PROBES; ++probe) {
        size_t slot = (base + probe) & (DEDUP_SLOTS - 1U);
        dedup_entry_t *e = &dedup_table[slot];
        if (e->valid && e->key == h) {
            if ((now - e->last_seen) < ttl) {
                if (sliding) e->last_seen = now;
                return 1;
            }
            replace_slot = slot;
            break;
        }
        if (!e->valid || (now - e->last_seen) >= ttl) {
            replace_slot = slot;
            break;
        }
        if (e->last_seen < oldest_ts) {
            oldest_ts = e->last_seen;
            replace_slot = slot;
        }
    }

    dedup_table[replace_slot].key = h;
    dedup_table[replace_slot].last_seen = now;
    dedup_table[replace_slot].valid = 1;
    return 0;
}

static int dedup_should_suppress(const char *mac, const char *evtype, const char *payload, int rl_enabled) {
    return dedup_should_suppress_for(mac, evtype, payload, rl_enabled, rate_limit_ttl, 1);
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
static inline uint16_t read_be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
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
 * SECTION: Universal L2 Stripper
 * Strips link-layer headers across Ethernet, cooked packets, and raw IP sockets.
 * ============================================================================ */
/**
 * Removes the link-layer (L2) header from a raw captured frame so the rest
 * of the pipeline can work purely in terms of "L3 protocol + offset to L3
 * header", regardless of which kind of socket/interface the packet came
 * from. Fills in src_mac/dst_mac (all-zero when the link type has no MAC
 * concept) and *l3_proto (the EtherType-style value for the L3 protocol,
 * e.g. 0x0800 for IPv4, 0x86dd for IPv6). Returns the byte offset where the
 * L3 header starts, or -1 if the frame is too short / not understood.
 */
static int strip_l2(link_type_t type, const unsigned char *buffer, int len,
                    unsigned char *src_mac, unsigned char *dst_mac, uint16_t *l3_proto) {
    if (type == LINK_ETHERNET) {
        /* Standard Ethernet II frame: dst MAC(6) + src MAC(6) + EtherType(2). */
        if (len < 14) return -1;
        memcpy(dst_mac, buffer, 6); memcpy(src_mac, buffer + 6, 6);
        uint16_t eth_type = read_be16(buffer + 12);
        int offset = 14;
        /* 802.1Q / 802.1ad VLAN tag (4 extra bytes): TPID(2) + TCI(2), then
         * the real EtherType follows where the TCI would otherwise be read. */
        if (eth_type == 0x8100 || eth_type == 0x88A8) {
            if (len < 18) return -1;
            eth_type = read_be16(buffer + 16); offset = 18;
            /* QinQ / 802.1ad+802.1Q double tag: a second TPID may follow. */
            if (eth_type == 0x8100 || eth_type == 0x88A8) {
                if (len < 22) return -1;
                eth_type = read_be16(buffer + 20); offset = 22;
            }
        }
        /* PPPoE Session stage (common on DSL/fiber ONTs): 6-byte PPPoE
         * header + 2-byte PPP protocol ID, which maps to the real L3
         * EtherType (0x0021 = IPv4-over-PPP, 0x0057 = IPv6-over-PPP). */
        if (eth_type == 0x8864) {
            if (len < offset + 8) return -1;
            uint16_t ppp_proto = read_be16(buffer + offset + 6); offset += 8;
            if (ppp_proto == 0x0021) eth_type = 0x0800; else if (ppp_proto == 0x0057) eth_type = 0x86dd; else return -1;
        }
        *l3_proto = eth_type; return offset;
    } else if (type == LINK_COOKED) {
        /* Linux SLL "cooked" capture header, used for the special "any"
         * pseudo-interface: packet_type(2) + arphrd_type(2) + addr_len(2) +
         * addr[8] (only first `addr_len` bytes meaningful) + protocol(2).
         * There's no destination MAC in this format (it's not per-link). */
        if (len < 16) return -1;
        memset(dst_mac, 0, 6); memset(src_mac, 0, 6);
        if (buffer[4] >= 6) {
            memcpy(src_mac, buffer + 6, 6);
        }
        *l3_proto = read_be16(buffer + 14);
        return 16;
    } else if (type == LINK_RAW_IP) {
        /* Raw IP (e.g. a PPP/tunnel interface with no link-layer header at
         * all): the buffer starts directly with the IP header, so there's
         * no MAC to extract -- infer the L3 protocol from the IP version
         * nibble in the very first byte instead. */
        if (len < 1) return -1;
        memset(src_mac, 0, 6); memset(dst_mac, 0, 6);
        uint8_t ip_version = buffer[0] >> 4;
        if (ip_version == 4) *l3_proto = 0x0800; else if (ip_version == 6) *l3_proto = 0x86dd; else return -1;
        return 0; 
    }
    return -1;
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
static int cmp_uint16(const void *a, const void *b) { return (int)(*(const uint16_t *)a) - (int)(*(const uint16_t *)b); }

/**
 * Checks if a 16-bit value matches TLS GREASE extension/cipher definitions.
 */
static inline int is_grease16(uint16_t v) {
    return ((v >> 8) == (v & 0xFF)) && ((v & 0x0F) == 0x0A);
}

/**
 * Parses a TLS ClientHello (record type 0x16, handshake type 0x01) to
 * extract the SNI, ALPN, cipher suites and extensions, and builds a JA4
 * client fingerprint from them.
 *
 * ClientHello wire layout (offsets below are from the start of `payload`,
 * i.e. from the TLS record header):
 *   byte 0        record type            (0x16 = handshake)
 *   bytes 1-2     record version
 *   bytes 3-4     record length
 *   byte 5        handshake type         (0x01 = ClientHello)
 *   bytes 6-8     handshake length       (24-bit)
 *   bytes 9-10    legacy client_version  (may be overridden below by the
 *                                          supported_versions extension)
 *   bytes 11-42   client random          (32 bytes)
 *   byte 43       session_id length      (followed by that many bytes)
 *   ...           cipher_suites: 2-byte length + 2-byte cipher IDs
 *   ...           compression_methods: 1-byte length + methods
 *   ...           extensions: 2-byte total length + TLV extension list
 */
static void parse_tls_sni(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport, const char *routed_str, int rl_enabled) {
    if (len < 44 || payload[0] != 0x16 || payload[5] != 0x01) return; /* not a TLS handshake / not a ClientHello */

    /* Skip the fixed 43-byte header, then the variable-length session_id. */
    int pos = 43; if (pos >= len) return; pos += payload[pos] + 1;

    if (pos + 2 > len) return;
    int cipher_len = read_be16(payload + pos);
    int cipher_count = cipher_len / 2;
    if (pos + 2 + cipher_len > len) return;
    
    /* Build the comma-separated cipher hex list that gets MD5-hashed into
     * ja4_b, excluding GREASE reserved values (RFC 8701) -- browsers insert
     * these as random noise to prevent protocol ossification, so they carry
     * no fingerprinting signal and would make otherwise-identical clients
     * hash differently run to run. `real_cipher_count` counts exactly the
     * entries that end up in the hash. */
    char cipher_hex[4096] = {0}; int chex_pos = 0; int real_cipher_count = 0;
    for (int i = 0; i < cipher_count && chex_pos < (int)sizeof(cipher_hex) - 5; i++) {
        uint16_t c = read_be16(payload + pos + 2 + (i * 2));
        if (!is_grease16(c)) {
            int written = snprintf(cipher_hex + chex_pos, sizeof(cipher_hex) - (size_t)chex_pos, "%04x,", c);
            if (written < 0) return;
            if (written >= (int)(sizeof(cipher_hex) - (size_t)chex_pos)) break;
            chex_pos += written;
            real_cipher_count++;
        }
    }
    if (chex_pos > 0) cipher_hex[chex_pos-1] = '\0'; /* drop trailing comma */
    pos += cipher_len + 2; 

    /* compression_methods (unused, just skip over it). */
    if (pos + 1 > len) return;
    pos += payload[pos] + 1;
    /* extensions block: 2-byte total length, then the TLV extension list. */
    if (pos + 2 > len) return;
    int ext_list_len = read_be16(payload + pos);
    pos += 2; 
    int end = pos + ext_list_len; if (end > len) end = len;

    char sni[256] = {0}, alpn[32] = {0}; int ext_count = 0;
    uint16_t ext_arr[128] = {0};
    /* Track whether the SNI / ALPN extensions were actually present in this
     * ClientHello, independent of the parsed string contents, so valid values
     * that happen to start with placeholder-like text remain distinguishable. */
    int has_sni = 0, has_alpn = 0;

    /* Legacy client_version at bytes 9-10 (see layout above); len>=44 was
     * already checked, so this read is always in-bounds. May be superseded
     * below by the supported_versions extension, which TLS 1.3+ clients
     * actually use for negotiation. */
    uint16_t tls_version = (len >= 11) ? read_be16(payload + 9) : 0x0301;
    
    /* Walk the extensions TLV list: type(2) + length(2) + payload. */
    while (pos + 4 <= end) {
        uint16_t e_type = read_be16(payload + pos); int e_len = read_be16(payload + pos + 2);
        pos += 4; 
        /* Collect extension IDs for the ja4_c hash. SNI (0x00) and ALPN
         * (0x10) are excluded here since JA4 encodes them elsewhere (the
         * 'd'/'i' flag and the ALPN first/last char below); GREASE values
         * are excluded as noise, same reasoning as for ciphers above. */
        if (e_type != 0x0000 && e_type != 0x0010 && !is_grease16(e_type) && ext_count < 128) ext_arr[ext_count++] = e_type;

        if (e_type == 0 && pos + e_len <= end && e_len >= 5 && sni[0] == '\0') {
            /* server_name extension: list length(2) + name_type(1) + name length(2) + name bytes. */
            has_sni = 1;
            int sn_len = read_be16(payload + pos + 3);
            if (payload[pos + 2] == 0 && pos + 5 + sn_len <= end && sn_len < 256) {
                sanitize_field(payload + pos + 5, sn_len, sni, sizeof(sni), 0);
            }
        }
        else if (e_type == 16 && pos + e_len <= end && e_len >= 3 && alpn[0] == '\0') {
            /* ALPN extension: list length(2), then one or more
             * (proto length(1) + proto bytes) entries. Only the first
             * offered protocol is kept, which is all JA4 needs. */
            has_alpn = 1;
            int alpn_list_len = read_be16(payload + pos);
            if (alpn_list_len > 0 && pos + 3 <= end) {
                int first_alpn_len = payload[pos + 2];
                if (first_alpn_len < 32 && pos + 3 + first_alpn_len <= end) sanitize_field(payload + pos + 3, first_alpn_len, alpn, sizeof(alpn), 0);
            }
        }
        else if (e_type == 0x002b && pos + e_len <= end && e_len >= 3) {
            /* supported_versions extension: list length(1) + 2-byte version
             * entries. Pick the highest non-GREASE version offered, since
             * that's what a TLS 1.3 client actually negotiates with. */
            int list_len = payload[pos];
            uint16_t best = 0;
            for (int vi = 0, voff = pos + 1; vi + 1 < list_len && voff + 1 < end; vi += 2, voff += 2) {
                uint16_t v = read_be16(payload + voff);
                if (!is_grease16(v) && v > best) best = v;
            }
            if (best) tls_version = best;
        }
        pos += e_len;
    }

    /* Display values fall back to the literal string "none" when absent --
     * this is only for the human-readable TLS| telemetry line below, and no
     * longer feeds the JA4 computation (see has_sni/has_alpn above). */
    if (sni[0] == '\0') strcpy(sni, "none");
    if (alpn[0] == '\0') strcpy(alpn, "none");
    
    /* ja4_c hash input: sorted, comma-joined list of extension IDs. */
    qsort(ext_arr, (size_t)ext_count, sizeof(uint16_t), cmp_uint16);
    char ext_hex[2048] = {0}; int ex_pos = 0;
    for(int i=0; i<ext_count && ex_pos < 2000; i++) {
        int written = snprintf(ext_hex + ex_pos, sizeof(ext_hex) - (size_t)ex_pos, "%04x,", ext_arr[i]);
        if (written < 0) return;
        if (written >= (int)(sizeof(ext_hex) - (size_t)ex_pos)) {
            ex_pos = (int)sizeof(ext_hex) - 1;
            break;
        }
        ex_pos += written;
    }
    if (ex_pos > 0) ext_hex[ex_pos-1] = '\0';

    const char *ja4_ver;
    switch (tls_version) {
        case 0x0304: ja4_ver = "13"; break;
        case 0x0303: ja4_ver = "12"; break;
        case 0x0302: ja4_ver = "11"; break;
        case 0x0301: ja4_ver = "10"; break;
        case 0x0300: ja4_ver = "s3"; break;
        default:     ja4_ver = "00"; break;
    }
    /* Keep the JA4 cipher count consistent with ja4_b by excluding GREASE. */
    int a_cipher_count = real_cipher_count > 99 ? 99 : real_cipher_count;
    int a_ext_count = ext_count > 99 ? 99 : ext_count;

    /* First/last character of the negotiated ALPN value for JA4's "a"
     * section. Guarded against an empty alpn string (possible if the peer
     * offered a zero-length protocol identifier) to avoid reading alpn[-1]. */
    char alpn_first = '0', alpn_last = '0';
    if (has_alpn && alpn[0] != '\0') { alpn_first = alpn[0]; alpn_last = alpn[strlen(alpn) - 1]; }

    char ja4_a[64], ja4_b[33], ja4_c[33];
    snprintf(ja4_a, sizeof(ja4_a), "t%s%c%02d%02d%c%c", ja4_ver,
        has_sni ? 'd' : 'i', 
        a_cipher_count, a_ext_count, alpn_first, alpn_last);
    
    md5_hash((uint8_t*)cipher_hex, strlen(cipher_hex), ja4_b);
    md5_hash((uint8_t*)ext_hex, strlen(ext_hex), ja4_c);
    
    /* Final fingerprint. NOTE: this is JA4-*like*, not FoxIO JA4:
     *   - hash is MD5 (OpenWrt-cheap), not SHA-256
     *   - ciphers are hashed in WIRE order, not sorted
     *   - ja4_c does not append the signature_algorithms list
     *   - extension *count* excludes SNI/ALPN (spec includes them)
     * Kept byte-compatible with 5.0.9 collectors. Spec-compliant JA4 is in v6. */
    char ja4_full[128];
    snprintf(ja4_full, sizeof(ja4_full), "%s_%.12s_%.12s", ja4_a, ja4_b, ja4_c);

    char fp_payload[512], fp_sig[640];
    snprintf(fp_payload, sizeof(fp_payload), "%s|%s", sni, ja4_full);
    source_dedup_signature(fp_sig, sizeof(fp_sig), src_ip, fp_payload, routed_str);
    if (!dedup_should_suppress(mac, "TLS", fp_sig, rl_enabled)) {
        emit_telemetry("TLS|%s|%s|%s|%u|%s|%s|%s%s\n", mac, src_ip, dst_ip, dport, sni, ja4_full, alpn, routed_str);
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

/* Returns the complete byte span of a QUIC v1 Initial packet inside a UDP
 * datagram. This lets the caller walk coalesced Initial packets without
 * treating the entire datagram as one cryptographic packet. */
static int quic_v1_initial_span(const unsigned char *payload, int len, int offset,
                                int *dcid_pos, uint8_t *dcid_len, int *packet_span) {
    if (!payload || !dcid_pos || !dcid_len || !packet_span || offset < 0 || len - offset < 7) return 0;
    const unsigned char *p = payload + offset;
    int rem = len - offset;
    if ((p[0] & 0xC0U) != 0xC0U || ((p[0] & 0x30U) >> 4) != 0U) return 0;
    uint32_t version = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) |
                       ((uint32_t)p[3] << 8) | (uint32_t)p[4];
    if (version != 0x00000001U) return 0;

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
    while (offset < len) {
        int dcid_pos = 0, packet_span = 0;
        uint8_t dcid_len = 0;
        if (!quic_v1_initial_span(payload, len, offset, &dcid_pos, &dcid_len, &packet_span)) break;
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
        if (result < 0) saw_failure = 1;
        /* result == 0 is normal stateful reassembly pending: stay silent. */
        offset += packet_span;
    }

    if (saw_initial && saw_failure && !quic_success_recent(success_key)) {
        /* Failure fallback is intentionally coarse and rate-limited per device
         * and QUIC version, so repeated Initial packets cannot spam telemetry. */
        char failure_sig[192];
        source_dedup_signature(failure_sig, sizeof(failure_sig), src_ip, "v1-failure", routed_str);
        if (!dedup_should_suppress(mac, "QUIC", failure_sig, rl_enabled)) {
            emit_telemetry("QUIC|%s|%s|%s|%u|encrypted|v1%s\n", mac, src_ip, dst_ip, dport, routed_str);
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
static void decode_netbios_name(const unsigned char *enc, char *out, int outsize) {
    int o = 0;
    for (int i = 0; i + 1 < 32 && o < outsize - 1; i += 2) {
        if (enc[i] < 'A' || enc[i] > 'P' || enc[i+1] < 'A' || enc[i+1] > 'P') break; /* not valid half-ASCII encoding -> stop */
        unsigned char c = (unsigned char)(((enc[i] - 'A') << 4) | (enc[i+1] - 'A'));
        if (c == 0 || c == 0x20) break; /* NUL or space padding marks the end of the real name */
        out[o++] = (c >= 32 && c <= 126 && c != '|') ? (char)c : ' '; /* keep printable ASCII, blank out anything else (incl. our own '|' delimiter) */
    }
    out[o] = '\0'; while (o > 0 && out[o-1] == ' ') out[--o] = '\0'; /* trim trailing padding spaces */
}

/**
 * Parses NetBIOS Name Service requests.
 */
static void parse_netbios(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *routed_str, int rl_enabled) {
    if (len < 50 || payload[12] != 0x20) return; 
    char name[17]; decode_netbios_name(payload + 13, name, sizeof(name));
    char sig[96]; source_dedup_signature(sig, sizeof(sig), src_ip, name, routed_str);
    if (name[0] && !dedup_should_suppress(mac, "NBNS", sig, rl_enabled)) emit_telemetry("NBNS|%s|%s|%s%s\n", mac, src_ip, name, routed_str);
}


/* Parse an Ethernet/IPv4 ARP payload and update the passive ownership cache. */
static void parse_arp_vector(const unsigned char *payload, int len, int ifindex, int rl_enabled) {
    if (!payload || len < 28) return;
    uint16_t htype = read_be16(payload);
    uint16_t ptype = read_be16(payload + 2);
    uint8_t hlen = payload[4], plen = payload[5];
    uint16_t oper = read_be16(payload + 6);
    if (htype != 1U || ptype != 0x0800U || hlen != 6U || plen != 4U) return;

    const uint8_t *sha = payload + 8;
    uint32_t spa, tpa;
    memcpy(&spa, payload + 14, sizeof(spa));
    memcpy(&tpa, payload + 24, sizeof(tpa));
    if (!mac_is_unicast_nonzero(sha)) return;

    char mac[18], sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    struct in_addr a;
    format_mac(sha, mac);
    a.s_addr = spa; if (!inet_ntop(AF_INET, &a, sender_ip, sizeof(sender_ip))) return;
    a.s_addr = tpa; if (!inet_ntop(AF_INET, &a, target_ip, sizeof(target_ip))) return;

    const char *op = oper == 1U ? "request" : (oper == 2U ? "reply" : "other");
    const char *routed = is_routed_source_ipv4(spa, ifindex) ? "|routed" : "";
    char sig[128];
    snprintf(sig, sizeof(sig), "%s|%s|%s|%s", sender_ip, target_ip, op, routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "ARP", sig, rl_enabled))
        emit_telemetry("ARP|%s|%s|%s|%s%s\n", mac, sender_ip, target_ip, op, routed);

    /* Learn only after evaluating the event so a stale owner cannot be hidden
     * before this packet is classified. */
    owner4_note(spa, sha);
}

static int decode_dhcp6_name(const uint8_t *buf, size_t len, char *out, size_t out_cap) {
    size_t p = 0, o = 0;
    if (!buf || !out || out_cap == 0U) return 0;
    out[0] = '\0';
    while (p < len) {
        uint8_t n = buf[p++];
        if (n == 0U) break;
        if ((n & 0xC0U) != 0U || n > 63U || (size_t)n > len - p) return 0;
        if (o != 0U) {
            if (o + 1U >= out_cap) return 0;
            out[o++] = '.';
        }
        for (uint8_t i = 0; i < n; ++i) {
            if (o + 1U >= out_cap) return 0;
            unsigned char c = buf[p++];
            out[o++] = (char)((c >= 32U && c <= 126U && c != '|') ? c : '_');
        }
    }
    out[o] = '\0';
    return o > 0U;
}

static const char *dhcp6_msg_name(uint8_t type) {
    switch (type) {
        case 1: return "SOLICIT";
        case 3: return "REQUEST";
        case 5: return "RENEW";
        case 6: return "REBIND";
        case 11: return "INFORMATION";
        case 4: return "CONFIRM";
        case 8: return "RELEASE";
        case 9: return "DECLINE";
        default: return "OTHER";
    }
}

static const char *dhcp6_duid_name(uint16_t type) {
    switch (type) {
        case 1: return "LLT";
        case 2: return "EN";
        case 3: return "LL";
        case 4: return "UUID";
        default: return "UNKNOWN";
    }
}

/* DHCPv6 is emitted as a separate fixed-format vector. Only client-originated
 * messages are passed here, avoiding noisy ADVERTISE/REPLY records that add no
 * client fingerprint value. */
static void parse_dhcp6(const unsigned char *payload, int len, const char *mac,
                        const char *src_ip, const char *routed_str, int rl_enabled) {
    if (!payload || len < 4) return;
    uint8_t msg_type = payload[0];
    if (msg_type == 12U || msg_type == 13U) return; /* relay messages have a different header */

    const char *duid_type = "UNKNOWN";
    char vendor[128] = "none", oro[256] = "none", fqdn[256] = "none";
    int pos = 4;
    while (pos + 4 <= len) {
        uint16_t code = read_be16(payload + pos);
        uint16_t olen = read_be16(payload + pos + 2);
        pos += 4;
        if ((int)olen > len - pos) break;
        const uint8_t *v = payload + pos;

        if (code == 1U && olen >= 2U) { /* Client Identifier / DUID */
            duid_type = dhcp6_duid_name(read_be16(v));
        } else if (code == 6U && olen >= 2U) { /* Option Request Option */
            size_t used = 0;
            oro[0] = '\0';
            for (size_t i = 0; i + 1U < (size_t)olen; i += 2U) {
                uint16_t val = read_be16(v + i);
                int n = snprintf(oro + used, sizeof(oro) - used, "%s%u", used ? "," : "", (unsigned)val);
                if (n < 0 || (size_t)n >= sizeof(oro) - used) break;
                used += (size_t)n;
            }
            if (oro[0] == '\0') strcpy(oro, "none");
        } else if (code == 16U && olen >= 6U) { /* Vendor Class */
            size_t vp = 4U; /* enterprise-number */
            uint16_t vlen = read_be16(v + vp); vp += 2U;
            if ((size_t)vlen <= (size_t)olen - vp) {
                int take = (int)vlen;
                if (take > (int)sizeof(vendor) - 1) take = (int)sizeof(vendor) - 1;
                sanitize_field(v + vp, take, vendor, (int)sizeof(vendor), 0);
                if (vendor[0] == '\0') strcpy(vendor, "none");
            }
        } else if (code == 39U && olen >= 2U) { /* Client FQDN: flags + DNS name */
            if (!decode_dhcp6_name(v + 1, (size_t)olen - 1U, fqdn, sizeof(fqdn))) strcpy(fqdn, "none");
        }
        pos += (int)olen;
    }

    char payload_sig[768], sig[896];
    snprintf(payload_sig, sizeof(payload_sig), "%s|%s|%s|%s|%s", dhcp6_msg_name(msg_type), duid_type, vendor, oro, fqdn);
    source_dedup_signature(sig, sizeof(sig), src_ip, payload_sig, routed_str);
    if (!dedup_should_suppress(mac, "DHCP6", sig, rl_enabled)) {
        emit_telemetry("DHCP6|%s|%s|%s|%s|%s|%s|%s%s\n",
                       mac, src_ip, dhcp6_msg_name(msg_type), duid_type, vendor, oro, fqdn, routed_str);
    }
}

static const uint8_t *ndp_find_lladdr(const uint8_t *icmp, int len, int opt_off, uint8_t wanted_type) {
    int pos = opt_off;
    while (pos + 2 <= len) {
        uint8_t type = icmp[pos], units = icmp[pos + 1];
        if (units == 0U) break;
        int olen = (int)units * 8;
        if (olen > len - pos) break;
        if (type == wanted_type && olen >= 8) return icmp + pos + 2;
        pos += olen;
    }
    return NULL;
}

static void parse_ra_vector(const uint8_t *icmp, int len, const uint8_t frame_src_mac[6],
                            const struct in6_addr *src_addr, const char *src_ip, int ifindex,
                            int rl_enabled) {
    if (!icmp || len < 16 || icmp[0] != ND_ROUTER_ADVERT || !frame_src_mac || !src_addr) return;
    char mac[18]; format_mac(frame_src_mac, mac);
    uint8_t hop_limit = icmp[4], raf = icmp[5];
    uint16_t lifetime = read_be16(icmp + 6);
    char flags[8]; size_t fo = 0;
    if (raf & 0x80U) flags[fo++] = 'M';
    if (raf & 0x40U) flags[fo++] = 'O';
    if (raf & 0x20U) flags[fo++] = 'H';
    if (fo == 0U) flags[fo++] = '-';
    flags[fo] = '\0';

    char prefix[INET6_ADDRSTRLEN] = "none";
    unsigned prefix_len = 0U, mtu = 0U;
    int pos = 16;
    while (pos + 2 <= len) {
        uint8_t type = icmp[pos], units = icmp[pos + 1];
        if (units == 0U) break;
        int olen = (int)units * 8;
        if (olen > len - pos) break;
        if (type == 3U && olen >= 32 && strcmp(prefix, "none") == 0) {
            prefix_len = icmp[pos + 2];
            struct in6_addr pfx; memcpy(&pfx, icmp + pos + 16, 16);
            if (!inet_ntop(AF_INET6, &pfx, prefix, sizeof(prefix))) strcpy(prefix, "none");
        } else if (type == 5U && olen >= 8) {
            uint32_t mtu_be; memcpy(&mtu_be, icmp + pos + 4, sizeof(mtu_be));
            mtu = ntohl(mtu_be);
        }
        pos += olen;
    }

    int mismatch = owner6_mismatch(src_addr, frame_src_mac);
    const char *routed = (is_routed_source_ipv6(src_addr, ifindex) || mismatch) ? "|routed" : "";
    char sig[256];
    snprintf(sig, sizeof(sig), "%s|%u|%s|%u|%s|%u|%u|%s", src_ip, (unsigned)hop_limit, flags,
             (unsigned)lifetime, prefix, prefix_len, mtu, routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "RA", sig, rl_enabled))
        emit_telemetry("RA|%s|%s|%u|%s|%u|%s|%u|%u%s\n", mac, src_ip,
                       (unsigned)hop_limit, flags, (unsigned)lifetime, prefix, prefix_len, mtu, routed);
    owner6_note(src_addr, frame_src_mac);
}

static void parse_ndp_vector(const uint8_t *icmp, int len, const uint8_t frame_src_mac[6],
                             const struct in6_addr *src_addr, const char *src_ip, int ifindex,
                             int rl_enabled) {
    if (!icmp || len < 8 || !frame_src_mac || !src_addr) return;
    uint8_t type = icmp[0];
    if (type == ND_ROUTER_ADVERT) {
        parse_ra_vector(icmp, len, frame_src_mac, src_addr, src_ip, ifindex, rl_enabled);
        return;
    }
    if (type != ND_ROUTER_SOLICIT && type != ND_NEIGHBOR_SOLICIT && type != ND_NEIGHBOR_ADVERT) return;

    const char *name = type == ND_ROUTER_SOLICIT ? "RS" : (type == ND_NEIGHBOR_SOLICIT ? "NS" : "NA");
    int opt_off = type == ND_ROUTER_SOLICIT ? 8 : 24;
    if (len < opt_off) return;
    uint8_t wanted = type == ND_NEIGHBOR_ADVERT ? 2U : 1U;
    const uint8_t *opt_mac = ndp_find_lladdr(icmp, len, opt_off, wanted);
    const uint8_t *identity_mac = (opt_mac && mac_is_unicast_nonzero(opt_mac)) ? opt_mac : frame_src_mac;
    char mac[18]; format_mac(identity_mac, mac);

    char target[INET6_ADDRSTRLEN] = "none";
    struct in6_addr target_addr; memset(&target_addr, 0, sizeof(target_addr));
    if (type == ND_NEIGHBOR_SOLICIT || type == ND_NEIGHBOR_ADVERT) {
        memcpy(&target_addr, icmp + 8, 16);
        if (!inet_ntop(AF_INET6, &target_addr, target, sizeof(target))) strcpy(target, "none");
    }

    char flags[8] = "-";
    if (type == ND_NEIGHBOR_ADVERT) {
        size_t f = 0; uint8_t b = icmp[4];
        if (b & 0x80U) flags[f++] = 'R';
        if (b & 0x40U) flags[f++] = 'S';
        if (b & 0x20U) flags[f++] = 'O';
        if (f == 0U) flags[f++] = '-';
        flags[f] = '\0';
    }

    int mismatch = owner6_mismatch(src_addr, identity_mac);
    const char *routed = (is_routed_source_ipv6(src_addr, ifindex) || mismatch) ? "|routed" : "";
    char sig[320]; snprintf(sig, sizeof(sig), "%s|%s|%s|%s|%s", src_ip, name, target, flags,
                            routed[0] ? "routed" : "direct");
    if (!dedup_should_suppress_discovery(mac, "NDP", sig, rl_enabled))
        emit_telemetry("NDP|%s|%s|%s|%s|%s%s\n", mac, src_ip, name, target, flags, routed);

    /* Source LLA owns the packet's source address. An NA TLLA additionally
     * claims the advertised target address. */
    owner6_note(src_addr, identity_mac);
    if (type == ND_NEIGHBOR_ADVERT) owner6_note(&target_addr, identity_mac);
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
    if (len < 241 || payload[236] != 0x63 || payload[237] != 0x82 || payload[238] != 0x53 || payload[239] != 0x63) return;
    char hostname_raw[64] = {0}, vendor_raw[64] = {0}, prl_raw[256] = {0};
    int have_host = 0, have_vendor = 0, have_prl = 0, pos = 240;
    while (pos < len) {
        uint8_t code = payload[pos++];
        if (code == 0xff) break;
        if (code == 0x00) continue; /* End / Pad */
        if (pos >= len) break;
        uint8_t olen = payload[pos++]; if (pos + olen > len) break;
        if (code == 12) { int n = olen < 63 ? olen : 63; memcpy(hostname_raw, payload + pos, (size_t)n); hostname_raw[n] = '\0'; have_host = 1; } /* option 12 = Host Name */
        else if (code == 60) { int n = olen < 63 ? olen : 63; memcpy(vendor_raw, payload + pos, (size_t)n); vendor_raw[n] = '\0'; have_vendor = 1; } /* option 60 = Vendor Class Identifier */
        else if (code == 55) { /* option 55 = Parameter Request List: one byte per requested DHCP option code */
            size_t used = 0;
            for (int j = 0; j < olen && used < sizeof(prl_raw) - 8; j++) {
                int n = snprintf(prl_raw + used, sizeof(prl_raw) - used, "%s%u", used ? "," : "", payload[pos + j]);
                if (n > 0) used += (size_t)n;
            }
            have_prl = 1;
        }
        pos += olen; /* skip to the next option, whether or not we cared about this one */
    }
    if (have_host || have_vendor || have_prl) {
        char host[64], vendor[64], prl[256], payload_sig[384], sig[512];
        sanitize_field((unsigned char*)hostname_raw, (int)strlen(hostname_raw), host, sizeof(host), 0);
        sanitize_field((unsigned char*)vendor_raw, (int)strlen(vendor_raw), vendor, sizeof(vendor), 0);
        sanitize_field((unsigned char*)prl_raw, (int)strlen(prl_raw), prl, sizeof(prl), 0);
        snprintf(payload_sig, sizeof(payload_sig), "%s|%s|%s", host, vendor, prl);
        source_dedup_signature(sig, sizeof(sig), src_ip, payload_sig, routed_str);
        if (!dedup_should_suppress(mac, "DHCP", sig, rl_enabled)) emit_telemetry("DHCP|%s|%s|%s|%s|%s%s\n", mac, src_ip, host, vendor, prl, routed_str);
    }
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
    int pos = start_pos, o = 0, guard = 0;
    int original_pos = -1;
    
    while (guard++ < 64) {
        if (pos >= payload_len) break;
        uint8_t label_len = payload[pos++];
        if (label_len == 0) {
            /* Zero-length label = end of name. If we got here by following
             * a compression pointer, resume at the byte right after that
             * pointer in the *original* record instead of stopping. */
            if (original_pos != -1) {
                pos = original_pos;
                original_pos = -1;
                continue;
            }
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression pointer: low 6 bits of this byte + all 8 bits of
             * the next byte form a 14-bit offset from the start of the DNS
             * message to jump to. */
            if (pos >= payload_len) break;
            int ptr = ((label_len & 0x3F) << 8) | payload[pos++];
            if (original_pos == -1) {
                original_pos = pos; /* remember only the first return address */
            }
            pos = ptr; 
            continue;
        }

        /* Ordinary label: `label_len` raw bytes follow. */
        if (label_len > 63 || pos + label_len > payload_len) break;
        if (o > 0 && o < out_max - 1) out[o++] = '.';
        for (int i = 0; i < label_len && pos < payload_len && o < out_max - 1; i++) {
            unsigned char c = payload[pos++];
            out[o++] = (isalnum(c) || c == '-' || c == '_') ? (char)tolower(c) : '.';
        }
    }
    out[o] = '\0'; 
    return o;
}

/**
 * Reads the QTYPE of a DNS question without expanding the name. The returned
 * offset follows the encoded QNAME, so normal labels and a terminal compression
 * pointer are both handled without allocating or walking unrelated records.
 */
static int dns_question_qtype(const unsigned char *payload, int payload_len, int start_pos, uint16_t *qtype) {
    if (!payload || !qtype || start_pos < 0 || start_pos >= payload_len) return 0;
    int pos = start_pos;
    int guard = 0;
    while (pos < payload_len && guard++ < 128) {
        uint8_t label_len = payload[pos++];
        if (label_len == 0) break;
        if ((label_len & 0xC0U) == 0xC0U) {
            if (pos >= payload_len) return 0;
            pos++;
            break;
        }
        if (label_len > 63U || pos + (int)label_len > payload_len) return 0;
        pos += (int)label_len;
    }
    if (pos + 4 > payload_len) return 0;
    *qtype = read_be16(payload + pos);
    return 1;
}

/**
 * Parses mDNS query records.
 */
static void parse_mdns(const unsigned char *payload, int len, const char *mac, const char *src_ip, int dport_or_sport, const char *routed_str, int rl_enabled) {
    if (len < 12 || read_be16(payload + 4) == 0) return;
    char qname[256], sig[384];
    if (decode_dns_name(payload, len, 12, qname, sizeof(qname)) > 0 && qname[0]) {
        source_dedup_signature(sig, sizeof(sig), src_ip, qname, routed_str);
        if (dedup_should_suppress(mac, "MDNS", sig, rl_enabled)) return;
        emit_telemetry("MDNS|%s|%s|%d|%s%s\n", mac, src_ip, dport_or_sport, qname, routed_str);
    }
}

/* ============================================================================
 * SECTION: Mode 1 - Target Packet Inspector
 * Dumps live captured packets in a tcpdump-like format when Mode 1 is active
 * (-z filter given). This is a read-only, best-effort human-readable printer;
 * it re-parses the packet independently of the main telemetry loop.
 * ============================================================================ */
#ifndef ARGOS_PORTABLE_TEST
static int ipv4_header_info(const unsigned char *buffer, int available, uint16_t *total_len_out, int *header_len_out) {
    if (!buffer || available < 20) return 0;
    struct iphdr ip_hdr;
    memcpy(&ip_hdr, buffer, sizeof(ip_hdr));
    if (ip_hdr.version != 4 || ip_hdr.ihl < 5) return 0;
    int header_len = ip_hdr.ihl * 4;
    if (header_len > available) return 0;
    uint16_t total_len = ntohs(ip_hdr.tot_len);
    if (total_len < (uint16_t)header_len || total_len > (uint16_t)available) return 0;
    if (total_len_out) *total_len_out = total_len;
    if (header_len_out) *header_len_out = header_len;
    return 1;
}

static int ipv6_packet_info(const unsigned char *buffer, int available, int *packet_len_out) {
    if (!buffer || available < 40) return 0;
    struct ip6_hdr ip6_hdr;
    memcpy(&ip6_hdr, buffer, sizeof(ip6_hdr));
    if ((ip6_hdr.ip6_vfc >> 4) != 6) return 0;
    uint32_t packet_len = 40U + (uint32_t)ntohs(ip6_hdr.ip6_plen);
    if (packet_len > (uint32_t)available) return 0;
    if (packet_len_out) *packet_len_out = (int)packet_len;
    return 1;
}

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

/**
 * Prints comprehensive command line help and documentation.
 */
static void print_help(const char *prog) {
    printf(
"argos-sniffer v" VERSION " - Passive LAN traffic fingerprinter & live inspector\n"
"                  for OpenWrt and any Linux gateway\n\n"
"USAGE:\n  %s [-i iface] [-r router_mac] [-x filter_expr] [-z filter_expr | -Z filter_expr] [-o path] [-u] [-U ip:port] [-f sec] [FLAGS...] [-W]\n"
"  OR:     %s [iface] (Automatically sets -i <iface> and enables all vectors with -a)\n\n"
"OPTIONS:\n"
"  -i <iface>      Interface to listen on (default: any). Comma-separated list or any.\n"
"                  'any' uses SOCK_RAW + per-packet sll_hatype (Ethernet/PPP/TUN).\n"
"                  LAN prefixes are learned from these interfaces (IPv6 GUA included).\n"
"  -r <mac>        Soft Exclude MAC. Excludes traffic but permits DNS responses for telemetry.\n"
"  -R <mac>        Hard Exclude MAC. Instantly and completely drops all outbound traffic from this MAC.\n"
"  -x <expr>       Exclude Filter: Drops traffic matching this expression before parsing.\n"
"  -z <expr>       Mode 1: Native Live Sniffer (replaces tcpdump). Matches MAC, IP, or logic.\n"
"  -Z <expr>       Mode 2 target filter: restricts telemetry vectors below to matches.\n"
"  -c <count>      Maximum packet count before exiting, Mode 1 only (default: 0 for unlimited)\n"
"  -p              Enable promiscuous mode (auto-enabled if -z is set)\n"
"  -f <seconds>    General deduplication window in seconds (default: 35).\n"
"                  Quiet ARP/NDP use >=900s and RA >=1800s fixed refresh windows.\n"
"  -o <path>       Stream telemetry output to a Unix domain socket.\n"
"  -u              Send telemetry only to local syslog (daemon.info).\n"
"  -U <ip>:<port>  Stream telemetry to a remote UDP collector and stdout.\n"
"                  Can be combined with -u for UDP + stdout + syslog fan-out.\n"
"                  (e.g. -U 10.0.0.5:5140 or -U [::1]:5140).\n"
"                  NOTE: telemetry is sent unencrypted/unauthenticated -- only\n"
"                  point this at a trusted host reachable over a trusted path\n"
"                  (management VLAN, VPN, etc).\n"
"  -W              Enable Stateful QUIC Inspection (reassembles fragmented Kyber ClientHellos)\n"
"  -E              Enable Extended Metrics (TCPLVL RTT, DNSEXT Latency, DNS Entropy)\n\n"
"TELEMETRY VECTORS (Lowercase = ENABLE WITH RATE LIMIT | Uppercase = ENABLE NO LIMIT):\n"
"  -s / -S         TCP SYN (p0f OS fingerprinting), SYNACK & TCPLVL latency tracking\n"
"  -m / -M         mDNS (5353) / SSDP (1900) / WSD (3702) payload logging\n"
"  -d / -D         DHCPv4 + DHCPv6 client fingerprint logging\n"
"  -n / -N         NetBIOS Name Service (UDP 137) logging\n"
"  -q / -Q         DNS Queries & DNSEXT latency/entropy tracking (UDP port 53)\n"
"  -h / -H         HTTP User-Agent extraction (port 80/8080)\n"
"  -t / -T         TLS ClientHello (SNI, JA4, ALPN) & QUIC extraction (port 443)\n"
"  -l / -L         LLDP + ARP + IPv6 NDP/Router Advertisement discovery\n"
"  -a / -A         Enable ALL vectors above (a = with limits, A = without limits)\n"
"  -v / -V         Enable IPv6 handling (subject to is_private_ipv6() filtering, see source)\n\n", prog, prog);
    fputs(
"OUTPUT FORMAT:\n"
"  SYN|mac|src_ip|ttl|window|wscale|mss|options|dst_port[|routed]\n"
"  SYNACK|mac|src_ip|ttl|window|wscale|mss|options|src_port[|routed]\n"
"  DNS|mac|src_ip|query_domain[|routed]\n"
"  TCPLVL|mac|src_ip|dst_ip|dst_port|rtt_us|retrans_count|state_event[|routed]\n"
"  TLS|mac|src_ip|dst_ip|dst_port|sni|ja4_fingerprint|alpn[|routed]\n"
"  QUIC|mac|src_ip|dst_ip|dst_port|sni|version[|routed]\n"
"  DNSEXT|mac|src_ip|dst_ip|query_domain|qtype|rcode|latency_ms|entropy[|routed]\n"
"  ALERT|mac|src_ip|HIGH_DNS_ENTROPY|query_domain|entropy[|routed]\n"
"  HTTP|mac|src_ip|user_agent[|routed]\n"
"  LLDP|mac|sysname|sysdesc[|routed]\n"
"  NBNS|mac|src_ip|netbios_name[|routed]\n"
"  DHCP|mac|src_ip|hostname|vendor_class|prl[|routed]\n"
"  DHCP6|mac|src_ip|msg_type|duid_type|vendor_class|oro|fqdn[|routed]\n"
"  ARP|mac|sender_ip|target_ip|op[|routed]\n"
"  NDP|mac|src_ip|type|target_ip|flags[|routed]\n"
"  RA|mac|src_ip|hop_limit|flags|router_lifetime|prefix|prefix_len|mtu[|routed]\n"
"  MDNS|mac|src_ip|port|qname[|routed]\n"
"  L7|mac|src_ip|dst_port|payload[|routed]\n\n"
"FEATURES EXPLAINED:\n"
"  [|routed]       Source is off-link behind a next-hop MAC or conflicts with ARP/NDP ownership.\n"
"  JA4-like FP     MD5-derived TLS cipher/extension fingerprint used for client correlation.\n"
"  DNS Entropy     Measures query randomness. >4.2 triggers HIGH_DNS_ENTROPY Alert (DGA/Tunnels).\n"
"  HTTP/3 (QUIC)   Decrypted Stateful QUIC handshakes output as TLS records with 'h3' ALPN.\n\n", stdout);
}

/* ============================================================================
 * SECTION: main()
 * Entry point: parses command-line arguments, sets up network interfaces, configures 
 * epoll, and runs the primary packet processing loop.
 * ============================================================================ */
#ifndef ARGOS_PORTABLE_TEST
int main(int argc, char *argv[]) {
    const char *iface = "any";
    
    filter_program_t filter_mode1 = {0}; 
    filter_program_t filter_mode2 = {0};
    filter_program_t filter_exclude = {0};

    int max_packets = 0, packet_count = 0;
    int opt_syn = 0, opt_multi = 0, opt_dhcp = 0, opt_netbios = 0, opt_dns = 0, opt_http = 0, opt_tls = 0, opt_l2 = 0, opt_v6 = 0, opt_promisc = 0;
    int opt_syn_rl = 0, opt_multi_rl = 0, opt_dhcp_rl = 0, opt_netbios_rl = 0, opt_dns_rl = 0, opt_http_rl = 0, opt_tls_rl = 0, opt_l2_rl = 0;
    int opt;

    if (argc == 1) { print_help(argv[0]); return 0; }

    /* CLI flag convention: for each telemetry category there is a lowercase
     * flag (enable + rate-limited/deduplicated output, the quiet default)
     * and an uppercase flag (enable + verbose/no rate-limiting, for
     * debugging). -a enables everything rate-limited; -A enables everything
     * verbose. -R/-r configure MAC address lists (hard/soft exclude) rather
     * than telemetry categories, and -x/-z/-Z compile capture filters. */
    while ((opt = getopt(argc, argv, "i:r:R:x:z:Z:o:uU:c:f:sSmMdDnNqQhHtTlLvVpaAWE")) != -1) {
        switch (opt) {
            case 'E': opt_ext_metrics = 1; break;
            case 'i': iface = optarg; break;
            case 'R': 
                if (hard_exclude_mac_count < MAX_HARD_EXCLUDE_MACS) {
                    uint8_t parsed_mac[6];
                    if (!parse_mac_address(optarg, parsed_mac)) {
                        fprintf(stderr, "Error: invalid MAC address for -R: %s\n", optarg); return 1;
                    }
                    memcpy(hard_exclude_macs[hard_exclude_mac_count], parsed_mac, 6);
                    hard_exclude_mac_count++;
                }
                break;
            case 'r':
                if (router_mac_count < MAX_ROUTER_MACS) {
                    uint8_t parsed_mac[6];
                    if (!parse_mac_address(optarg, parsed_mac)) {
                        fprintf(stderr, "Error: invalid MAC address for -r: %s\n", optarg); return 1;
                    }
                    memcpy(router_macs[router_mac_count], parsed_mac, 6);
                    router_mac_count++;
                }
                break;
            case 'x': if (compile_filter(optarg, &filter_exclude) < 0) return 1; break;
            case 'z': if (compile_filter(optarg, &filter_mode1) < 0) return 1; opt_promisc = 1; break;
            case 'Z': if (compile_filter(optarg, &filter_mode2) < 0) return 1; break;
            case 'o': 
                if (ipc_sock >= 0) close(ipc_sock); /* defensive: avoid leaking a fd if -o is given more than once */
                use_ipc = 1;
                if ((ipc_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) { perror("socket AF_UNIX"); return 1; }
                memset(&ipc_addr, 0, sizeof(struct sockaddr_un));
                ipc_addr.sun_family = AF_UNIX;
                strncpy(ipc_addr.sun_path, optarg, sizeof(ipc_addr.sun_path) - 1);
                break;
            case 'u':
#ifndef ARGOS_PORTABLE_TEST
                use_syslog = 1;
                openlog("argos-sniffer", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
                break;
            case 'U': /* Native Remote Socket: ship telemetry directly to a remote UDP collector.
                       * Caution: if the destination is reachable via one of the interfaces this
                       * process is itself capturing on (e.g. a WAN interface also passed to -i),
                       * the outgoing telemetry datagrams will be visible to the capture loop like
                       * any other traffic; use -x to exclude the collector's IP/port if that would
                       * create noise or a feedback loop. */
                if (remote_sock >= 0) close(remote_sock); /* defensive: avoid leaking a fd if -U is given more than once */
                if (parse_host_port(optarg, &remote_addr, &remote_addr_len) < 0) return 1; /* parse_host_port() already printed why */
                if ((remote_sock = socket(remote_addr.ss_family, SOCK_DGRAM, 0)) < 0) { perror("socket -U"); return 1; }
                use_remote = 1;
                fprintf(stderr, "warning: -U streams telemetry to %s over plain UDP and stdout; UDP is unencrypted, use only over a trusted path.\n", optarg);
                break;
            case 'c': { char *end = NULL; long v = strtol(optarg, &end, 10); if (!end || *end || v < 0 || v > INT32_MAX) { fprintf(stderr, "Error: invalid packet count: %s\n", optarg); return 1; } max_packets = (int)v; break; }
            case 'f': { char *end = NULL; long v = strtol(optarg, &end, 10); if (!end || *end || v < 0 || v > INT32_MAX) { fprintf(stderr, "Error: invalid deduplication window: %s\n", optarg); return 1; } rate_limit_ttl = (int)v; break; }
            case 'p': opt_promisc = 1; break;
            case 's': opt_syn = 1; opt_syn_rl = 1; break;
            case 'S': opt_syn = 1; opt_syn_rl = 0; break;
            case 'm': opt_multi = 1; opt_multi_rl = 1; break;
            case 'M': opt_multi = 1; opt_multi_rl = 0; break;
            case 'd': opt_dhcp = 1; opt_dhcp_rl = 1; break;
            case 'D': opt_dhcp = 1; opt_dhcp_rl = 0; break;
            case 'n': opt_netbios = 1; opt_netbios_rl = 1; break;
            case 'N': opt_netbios = 1; opt_netbios_rl = 0; break;
            case 'q': opt_dns = 1; opt_dns_rl = 1; break;
            case 'Q': opt_dns = 1; opt_dns_rl = 0; break;
            case 'h': opt_http = 1; opt_http_rl = 1; break;
            case 'H': opt_http = 1; opt_http_rl = 0; break;
            case 't': opt_tls = 1; opt_tls_rl = 1; break;
            case 'T': opt_tls = 1; opt_tls_rl = 0; break;
            case 'l': opt_l2 = 1; opt_l2_rl = 1; break;
            case 'L': opt_l2 = 1; opt_l2_rl = 0; break;
            case 'v':
            case 'V': opt_v6 = 1; break;
            case 'a':
                opt_syn = opt_multi = opt_dhcp = opt_netbios = opt_dns = opt_http = opt_tls = opt_l2 = 1;
                opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = opt_dns_rl = opt_http_rl = opt_tls_rl = opt_l2_rl = 1;
                opt_v6 = 1; break;
            case 'A':
                opt_syn = opt_multi = opt_dhcp = opt_netbios = opt_dns = opt_http = opt_tls = opt_l2 = 1;
                opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = opt_dns_rl = opt_http_rl = opt_tls_rl = opt_l2_rl = 0;
                opt_v6 = 1; break;
            case 'W': opt_quic_heavy = 1; break;    
            default: print_help(argv[0]); return 1;
        }
    }

    if (optind < argc) {
        iface = argv[optind++];
        opt_syn = opt_multi = opt_dhcp = opt_netbios = opt_dns = opt_http = opt_tls = opt_l2 = 1;
        opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = opt_dns_rl = opt_http_rl = opt_tls_rl = opt_l2_rl = 1;
        opt_v6 = 1;
    }

    if (optind < argc) { fprintf(stderr, "Error: Unrecognized extra argument.\n"); return 1; }

    if (filter_mode1.is_active && filter_mode2.is_active) {
        fprintf(stderr, "warning: -z and -Z both given; -Z ignored in live sniffer mode.\n");
    }

    if (opt_ext_metrics) {
        syn_table = (syn_track_t *)calloc(TRACK_SLOTS, sizeof(*syn_table));
        dns_table = (dns_track_t *)calloc(TRACK_SLOTS, sizeof(*dns_table));
        if (!syn_table || !dns_table) {
            fprintf(stderr, "Error: unable to allocate extended-metrics state.\n");
            free(syn_table); free(dns_table); free(dedup_table); free(owner4_table); free(owner6_table); return 1;
        }
    }

    if (!filter_mode1.is_active && !opt_syn && !opt_multi && !opt_dhcp && !opt_netbios && !opt_dns && !opt_http && !opt_tls && !opt_l2) {
        opt_syn = opt_multi = opt_dhcp = opt_netbios = 1;
        opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = 1;
        opt_v6 = 1;
    }

    install_signal_handlers();

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); return 1; }

    /* -i takes a comma-separated interface list (e.g. "eth0,wlan0"); make a
     * mutable copy since strtok() writes '\0' separators into it in place. */
    char *iface_list = strdup(iface);
    if (!iface_list) { fprintf(stderr, "Error: out of memory duplicating interface list.\n"); return 1; }
    char *token = strtok(iface_list, ",");
    
    /* Open one AF_PACKET raw socket per requested interface (or the special
     * "any" pseudo-interface, which captures on all interfaces at once using
     * Linux's "cooked" SLL framing instead of a real link-layer header) and
     * register each with epoll so the main loop can multiplex between them. */
    while (token != NULL && num_ifaces < MAX_INTERFACES) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) { token = strtok(NULL, ","); continue; }

        active_ifaces[num_ifaces].fd = sock;
        strncpy(active_ifaces[num_ifaces].name, token, IFNAMSIZ - 1);
        active_ifaces[num_ifaces].name[IFNAMSIZ - 1] = '\0';

        struct sockaddr_ll sll; memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (strcasecmp(token, "any") == 0) {
            /* SOCK_RAW + ifindex 0 delivers native L2 framing. Resolve the
             * actual link type from sockaddr_ll for each received packet. */
            if (num_ifaces > 0) {
                fprintf(stderr, "warning: 'any' should not be combined with explicit interfaces; skipping '%s'\n", token);
                close(sock); token = strtok(NULL, ","); continue;
            }
            active_ifaces[num_ifaces].ifindex = 0;
            active_ifaces[num_ifaces].type = LINK_PER_PACKET;
            sll.sll_ifindex = 0;
        } else {
            struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, token, IFNAMSIZ - 1);
            if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { close(sock); token = strtok(NULL, ","); continue; }
            active_ifaces[num_ifaces].ifindex = ifr.ifr_ifindex;
            sll.sll_ifindex = ifr.ifr_ifindex;

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                active_ifaces[num_ifaces].type = hatype_to_link((unsigned short)ifr.ifr_hwaddr.sa_family);
            } else {
                active_ifaces[num_ifaces].type = LINK_UNSUPPORTED;
            }
            if (active_ifaces[num_ifaces].type == LINK_UNSUPPORTED) {
                fprintf(stderr, "warning: unsupported link-layer type on %s; skipping\n", token);
                close(sock); token = strtok(NULL, ","); continue;
            }
        }
        
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) { close(sock); token = strtok(NULL, ","); continue; }

        if (opt_promisc && active_ifaces[num_ifaces].type == LINK_ETHERNET) {
            struct packet_mreq mr; memset(&mr, 0, sizeof(mr));
            mr.mr_ifindex = active_ifaces[num_ifaces].ifindex; mr.mr_type = PACKET_MR_PROMISC;
            setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
        }

        int rcvbuf = 1024 * 1024; setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        int one = 1;
        setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)); /* recover HW-stripped VLAN */
#ifdef SO_TIMESTAMPNS
        setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof(one));
#endif
        struct epoll_event ev; memset(&ev, 0, sizeof(ev)); ev.events = EPOLLIN; ev.data.ptr = &active_ifaces[num_ifaces];
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
            perror("epoll_ctl"); close(sock); token = strtok(NULL, ","); continue;
        }

        num_ifaces++; token = strtok(NULL, ",");
    }
    free(iface_list);
    if (opt_promisc && num_ifaces == 1 && active_ifaces[0].type == LINK_PER_PACKET) {
        fprintf(stderr, "warning: promiscuous mode with -i any is not enabled globally; use explicit interfaces with -p for full L2 visibility\n");
    }

    if (num_ifaces == 0) { fprintf(stderr, "No valid interfaces bound. Exiting.\n"); return 1; }
    learn_lan_prefixes();
    /* Keep stdout line-buffered whenever it is active. With -U it is a
     * deliberate local fan-out alongside the remote UDP sink. */
    if (!use_ipc || use_remote) setvbuf(stdout, NULL, _IOLBF, 0);

    struct epoll_event events[MAX_EPOLL_EVENTS];
    unsigned char buffer[CAPTURE_BUF];

    /* Main packet capture and processing loop */
    while (running) {
        static uint64_t last_gc = 0, last_stats = 0, max_loop_us = 0;
        uint64_t now_us = get_current_usec();
        if (opt_quic_heavy && (now_us - last_gc > 2000000ULL)) {
            quic_heavy_gc();
            last_gc = now_us;
        }
        if (now_us - last_stats > 10000000ULL) {
            for (int si = 0; si < num_ifaces; si++) {
                struct tpacket_stats st; memset(&st, 0, sizeof(st));
                socklen_t sl = sizeof(st);
                if (getsockopt(active_ifaces[si].fd, SOL_PACKET, PACKET_STATISTICS, &st, &sl) == 0) {
                    active_ifaces[si].total_packets += st.tp_packets;
                    active_ifaces[si].total_drops += st.tp_drops;
                    /* Keep reset-on-read accounting continuously, but avoid a
                     * zero-drop heartbeat in syslog every ten seconds. */
                    if (st.tp_drops) {
                        double drop_pct = st.tp_packets ? (100.0 * (double)st.tp_drops / (double)st.tp_packets) : 0.0;
                        fprintf(stderr, "argos: %s pkts=%u drops=%u drop=%.2f%% total_pkts=%llu total_drops=%llu",
                                active_ifaces[si].name, st.tp_packets, st.tp_drops, drop_pct,
                                (unsigned long long)active_ifaces[si].total_packets,
                                (unsigned long long)active_ifaces[si].total_drops);
                        if (opt_v6) fprintf(stderr, " max_loop_us=%llu", (unsigned long long)max_loop_us);
                        fputc('\n', stderr);
                    }
                }
            }
            if (opt_v6) max_loop_us = 0;
            last_stats = now_us;
        }
        int nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, 1000);
        if (nfds < 0 && errno != EINTR) break;
        uint64_t processing_start_us = opt_v6 ? get_current_usec() : 0;

        for (int i = 0; i < nfds; i++) {
            capture_iface_t *current_iface = (capture_iface_t *)events[i].data.ptr;

            struct sockaddr_ll from_ll;
            memset(&from_ll, 0, sizeof(from_ll));
            struct iovec iov;
            iov.iov_base = buffer;
            iov.iov_len = sizeof(buffer);
            char cmsg_buf[CMSG_SPACE(sizeof(struct tpacket_auxdata)) + CMSG_SPACE(sizeof(struct timespec))];
            struct msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &from_ll;
            msg.msg_namelen = sizeof(from_ll);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf;
            msg.msg_controllen = sizeof(cmsg_buf);

            ssize_t len = recvmsg(current_iface->fd, &msg, MSG_TRUNC);
            if (len <= 0) continue;
            if ((size_t)len > sizeof(buffer)) len = sizeof(buffer);

            uint64_t pkt_usec = 0;
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
#ifdef SO_TIMESTAMPNS
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMPNS) {
                    struct timespec ts;
                    memcpy(&ts, CMSG_DATA(c), sizeof(ts));
                    pkt_usec = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
                }
#endif
            }
            if (pkt_usec == 0) pkt_usec = get_current_usec();

            link_type_t pkt_type = current_iface->type;
            if (pkt_type == LINK_PER_PACKET) pkt_type = hatype_to_link(from_ll.sll_hatype);
            /* A socket bound to an explicit bridge is classified against that
             * bridge's connected prefixes. Some kernels report the ingress
             * bridge-port ifindex in sockaddr_ll; using it made valid off-link
             * IPv6 sources miss the br-lan prefix context. `any` still uses the
             * actual per-packet ifindex to avoid cross-interface false positives. */
            int packet_ifindex = prefix_context_ifindex(current_iface, from_ll.sll_ifindex);

            unsigned char src_mac[6], dst_mac[6]; uint16_t l3_proto = 0;
            int l3_offset = strip_l2(pkt_type, buffer, (int)len, src_mac, dst_mac, &l3_proto);
            if (l3_offset < 0) continue;

            static const unsigned char zero_mac[6] = {0,0,0,0,0,0};
            static const unsigned char bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
            /* RAW_IP (PPP/TUN/WireGuard) has no MAC, so zero-MAC validation
             * applies only to Ethernet and cooked link-layer frames. */
            if (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED) {
                if (memcmp(src_mac, zero_mac, 6) == 0 || memcmp(src_mac, bcast_mac, 6) == 0) continue;
            }

            uint32_t src_ip_num = 0, dst_ip_num = 0;
            int is_outbound = 0;
            int source_offlink_routed = 0;
            struct in6_addr src_ip6_addr, dst_ip6_addr;
            memset(&src_ip6_addr, 0, sizeof(src_ip6_addr));
            memset(&dst_ip6_addr, 0, sizeof(dst_ip6_addr));
            int is_ipv6_packet = 0;
            int is_ip_packet = 0;
            uint8_t ip_protocol = 0, ip_ttl = 0;
            int l4_offset = 0;
            int ipv4_is_frag = 0;

            if (l3_proto == 0x0800 && len >= l3_offset + 20) {
                uint16_t ip_total_len = 0; int ip_header_len = 0;
                if (!ipv4_header_info(buffer + l3_offset, (int)len - l3_offset, &ip_total_len, &ip_header_len)) continue;
                struct iphdr ip_hdr; memcpy(&ip_hdr, buffer + l3_offset, sizeof(ip_hdr));
                struct iphdr *ip = &ip_hdr;
                /* Skip non-first fragments -- they have no L4 header. First
                 * fragments (offset 0, MF=1) still carry L4 and are kept. */
                uint16_t frag = ntohs(ip->frag_off);
                if (frag & 0x1FFF) { ipv4_is_frag = 1; /* drop at L4 */ }
                src_ip_num = ip->saddr; dst_ip_num = ip->daddr;
                int src_lan = is_lan_ipv4(src_ip_num);
                int dst_lan = is_lan_ipv4(dst_ip_num);
                source_offlink_routed = is_routed_source_ipv4(src_ip_num, packet_ifindex);
                if (!src_lan && !dst_lan && !source_offlink_routed) continue;
                is_outbound = src_lan || source_offlink_routed;
                is_ip_packet = 1;
                ip_protocol = ip->protocol;
                ip_ttl = ip->ttl;
                l4_offset = l3_offset + ip_header_len;
            } else if (opt_v6 && l3_proto == 0x86dd) {
                if (len < l3_offset + 40) continue;
                int ip6_packet_len = 0;
                if (!ipv6_packet_info(buffer + l3_offset, (int)len - l3_offset, &ip6_packet_len)) continue;
                struct ip6_hdr ip6_hdr_local; memcpy(&ip6_hdr_local, buffer + l3_offset, sizeof(ip6_hdr_local));
                struct ip6_hdr *ip6 = &ip6_hdr_local;
                int src_lan = is_lan_ipv6(&ip6->ip6_src);
                int dst_lan = is_lan_ipv6(&ip6->ip6_dst);
                source_offlink_routed = is_routed_source_ipv6(&ip6->ip6_src, packet_ifindex);
                if (!src_lan && !dst_lan && !source_offlink_routed) continue;
                is_outbound = src_lan || source_offlink_routed;
                src_ip6_addr = ip6->ip6_src; dst_ip6_addr = ip6->ip6_dst;
                is_ipv6_packet = 1;
                is_ip_packet = 1;
                ip_ttl = ip6->ip6_hlim;
                if (skip_ipv6_exthdrs(buffer, (int)len, l3_offset, &ip_protocol, &l4_offset) < 0) continue;
            } else if (l3_proto == 0x88cc || l3_proto == 0x0806) {
                /* LLDP / ARP: no IP addresses. Filters can still match on MAC.
                 * Do NOT `continue` -- that was why -l never produced output. */
                is_ip_packet = 0;
            } else {
                continue;
            }

            /* L4 parsing must never consume Ethernet padding or bytes beyond the
             * IP total length advertised by the packet header. */
            int l3_packet_end = (int)len;
            if (l3_proto == 0x0800) {
                struct iphdr validated_ip;
                memcpy(&validated_ip, buffer + l3_offset, sizeof(validated_ip));
                l3_packet_end = l3_offset + (int)ntohs(validated_ip.tot_len);
            } else if (l3_proto == 0x86dd) {
                struct ip6_hdr validated_ip6;
                memcpy(&validated_ip6, buffer + l3_offset, sizeof(validated_ip6));
                l3_packet_end = l3_offset + 40 + (int)ntohs(validated_ip6.ip6_plen);
            }

            const struct in6_addr *filt_src_ip6 = is_ipv6_packet ? &src_ip6_addr : NULL;
            const struct in6_addr *filt_dst_ip6 = is_ipv6_packet ? &dst_ip6_addr : NULL;

            if (filter_exclude.is_active && evaluate_filter(&filter_exclude, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) {
                continue;
            }

            if (filter_mode1.is_active) {
                if (!evaluate_filter(&filter_mode1, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) continue;
                dump_target_packet(buffer, (int)len, l3_offset, l3_proto);
                packet_count++; if (max_packets > 0 && packet_count >= max_packets) running = 0;
                continue;
            }

            if (pkt_type == LINK_ETHERNET) {
                if (is_hard_excluded_mac(src_mac) && is_outbound) continue;

                if (is_router_mac(src_mac)) {
                    int allow_packet = 0;
                    if (is_ip_packet && ip_protocol == IPPROTO_UDP && len >= l4_offset + 8) {
                        struct udphdr udp_hdr; memcpy(&udp_hdr, buffer + l4_offset, sizeof(udp_hdr));
                        if (ntohs(udp_hdr.source) == 53) allow_packet = 1;
                    }
                    /* A forwarded Internet SYNACK appears on br-lan with the
                     * router as its Ethernet source. Let it reach only the TCP
                     * correlation path so -E can compute client RTT; the
                     * legacy SYNACK emitter below remains suppressed. */
                    if (!is_outbound && is_ip_packet && ip_protocol == IPPROTO_TCP &&
                        l4_offset + 20 <= l3_packet_end) {
                        struct tcphdr forwarded_tcp;
                        memcpy(&forwarded_tcp, buffer + l4_offset, sizeof(forwarded_tcp));
                        if (forwarded_tcp.syn && forwarded_tcp.ack) allow_packet = 1;
                    }
                    if (!allow_packet) continue;
                }
            }

            if (filter_mode2.is_active) {
                if (!evaluate_filter(&filter_mode2, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) continue;
            }

            int routed_evidence = source_offlink_routed;

            unsigned char device_mac[6];
            /* L2 discovery/control frames identify their sender by source MAC.
             * Using the destination MAC would turn multicast addresses such as
             * LLDP's 01:80:c2:00:00:0e into fake device identities. */
            if (l3_proto == 0x88cc || l3_proto == 0x0806) {
                memcpy(device_mac, src_mac, 6);
            } else if (pkt_type == LINK_RAW_IP) {
                memset(device_mac, 0, 6);
            } else if (is_outbound) {
                memcpy(device_mac, src_mac, 6);
            } else {
                memcpy(device_mac, dst_mac, 6);
            }
            if (pkt_type != LINK_RAW_IP) {
                if (memcmp(device_mac, zero_mac, 6) == 0 || memcmp(device_mac, bcast_mac, 6) == 0) continue;
            }

            char mac_str[18];
            const char *routed_str = routed_evidence ? "|routed" : "";

            if (pkt_type == LINK_RAW_IP) {
                snprintf(mac_str, sizeof(mac_str), "%s", current_iface->name);
            } else {
                snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                         device_mac[0], device_mac[1], device_mac[2], device_mac[3], device_mac[4], device_mac[5]);
            }

            /* L2 vectors must run even when there is no IP header. */
            if (opt_l2 && l3_proto == 0x88cc) {
                parse_lldp(buffer + l3_offset, (int)len - l3_offset, mac_str, routed_str, opt_l2_rl);
                continue;
            }
            if (l3_proto == 0x0806) {
                if (opt_l2) parse_arp_vector(buffer + l3_offset, (int)len - l3_offset, packet_ifindex, opt_l2_rl);
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

            uint32_t flow_src_key = is_ipv6_packet ? addr6_key(&src_ip6_addr) : src_ip_num;
            uint32_t flow_dst_key = is_ipv6_packet ? addr6_key(&dst_ip6_addr) : dst_ip_num;
            uint8_t flow_ip_version = is_ipv6_packet ? 6U : 4U;
            const uint8_t *flow_src_addr = is_ipv6_packet ? src_ip6_addr.s6_addr : (const uint8_t *)&src_ip_num;
            const uint8_t *flow_dst_addr = is_ipv6_packet ? dst_ip6_addr.s6_addr : (const uint8_t *)&dst_ip_num;

            if (protocol == IPPROTO_ICMPV6 && is_ipv6_packet) {
                if (opt_l2 && l4_offset >= 0 && l4_offset < l3_packet_end) {
                    parse_ndp_vector(buffer + l4_offset, l3_packet_end - l4_offset, src_mac,
                                     &src_ip6_addr, src_ip_str, packet_ifindex, opt_l2_rl);
                }
                continue;
            }

            if (protocol == IPPROTO_TCP) {
                if (l4_offset + 20 > l3_packet_end) continue;
                struct tcphdr tcp_hdr; memcpy(&tcp_hdr, buffer + l4_offset, sizeof(tcp_hdr));
                struct tcphdr *tcp = &tcp_hdr;
                uint16_t dport = ntohs(tcp->dest), sport = ntohs(tcp->source);
                int tcp_hl = tcp->doff * 4;
                if (tcp_hl < 20 || l4_offset + tcp_hl > l3_packet_end) continue;
                int payload_offset = l4_offset + tcp_hl, payload_len = l3_packet_end - payload_offset;
                int tcp_relevant = (opt_syn && (tcp->syn || tcp->rst || tcp->fin)) ||
                                   (opt_http && (dport == 80U || dport == 8080U)) ||
                                   (opt_tls && dport == 443U);
                if (!tcp_relevant) continue;
                if (!routed_evidence && is_outbound && (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED)) {
                    if (is_ipv6_packet ? owner6_mismatch(&src_ip6_addr, src_mac) : owner4_mismatch(src_ip_num, src_mac)) {
                        routed_evidence = 1; routed_str = "|routed";
                    }
                }

                if (opt_syn) {
                    uint64_t now_usec = pkt_usec;

                    if (tcp->syn && !tcp->ack) {
                        if (opt_ext_metrics) {
                            syn_track_t *tracked = syn_track_find(src_mac, sport, dport, flow_ip_version,
                                                                  flow_src_addr, flow_dst_addr, now_usec, 1);
                            if (tracked && tracked->ts_usec == 0) {
                                tracked->ts_usec = now_usec;
                                tracked->routed = (uint8_t)(routed_evidence ? 1 : 0);
                            }
                        }
                    }
                    else if (tcp->syn && tcp->ack) {
                        if (opt_ext_metrics) {
                            syn_track_t *tracked = syn_track_find(dst_mac, dport, sport, flow_ip_version,
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
                            syn_track_t *tracked = NULL;
                            const char *client_ip = NULL;
                            const char *server_ip = NULL;
                            uint16_t server_port = 0;

                            tracked = syn_track_find(src_mac, sport, dport, flow_ip_version,
                                                     flow_src_addr, flow_dst_addr, now_usec, 0);
                            if (tracked) {
                                client_ip = src_ip_str;
                                server_ip = dst_ip_str;
                                server_port = dport;
                            } else {
                                tracked = syn_track_find(dst_mac, dport, sport, flow_ip_version,
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

                if (opt_http && (dport == 80 || dport == 8080) && payload_len > 16) {
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
                                if (ua_str[0] && !dedup_should_suppress(mac_str, "HTTP", http_sig, opt_http_rl)) emit_telemetry("HTTP|%s|%s|%s%s\n", mac_str, src_ip_str, ua_str, routed_str);
                            }
                        }
                    }
                }
                else if (opt_tls && dport == 443 && payload_len > 44) {
                    parse_tls_sni(buffer + payload_offset, payload_len, mac_str, src_ip_str, dst_ip_str, dport, routed_str, opt_tls_rl);
                }
            }
            else if (protocol == IPPROTO_UDP) {
                if (l4_offset + 8 > l3_packet_end) continue;
                struct udphdr udp_hdr; memcpy(&udp_hdr, buffer + l4_offset, sizeof(udp_hdr));
                struct udphdr *udp = &udp_hdr;
                uint16_t dport = ntohs(udp->dest), sport = ntohs(udp->source);
                int udp_relevant = (opt_dhcp && ((is_ipv6_packet && sport == 546U && dport == 547U) ||
                                                  (!is_ipv6_packet && (dport == 67U || sport == 67U)))) ||
                                   (opt_netbios && (dport == 137U || sport == 137U)) ||
                                   (opt_multi && (dport == 1900U || sport == 1900U || dport == 3702U || sport == 3702U ||
                                                  dport == 5353U || sport == 5353U)) ||
                                   (opt_dns && (dport == 53U || sport == 53U)) ||
                                   (opt_tls && dport == 443U);
                if (!udp_relevant) continue;
                if (!routed_evidence && is_outbound && (pkt_type == LINK_ETHERNET || pkt_type == LINK_COOKED)) {
                    if (is_ipv6_packet ? owner6_mismatch(&src_ip6_addr, src_mac) : owner4_mismatch(src_ip_num, src_mac)) {
                        routed_evidence = 1; routed_str = "|routed";
                    }
                }
                uint16_t udp_len = ntohs(udp->len);
                if (udp_len < 8U || (int)udp_len > l3_packet_end - l4_offset) continue;
                int payload_offset = l4_offset + 8;
                int payload_len = (int)udp_len - 8;
                if (payload_len <= 0) continue;

                const unsigned char *payload = buffer + payload_offset;

                if (opt_dhcp && is_ipv6_packet && sport == 546U && dport == 547U) {
                    parse_dhcp6(payload, payload_len, mac_str, src_ip_str, routed_str, opt_dhcp_rl);
                }
                else if (opt_dhcp && !is_ipv6_packet && (dport == 67U || sport == 67U)) {
                    parse_dhcp(payload, payload_len, mac_str, src_ip_str, routed_str, opt_dhcp_rl);
                }
                else if (opt_netbios && (dport == 137 || sport == 137)) {
                    parse_netbios(payload, payload_len, mac_str, src_ip_str, routed_str, opt_netbios_rl);
                }
                else if (opt_multi && (dport == 1900 || sport == 1900 || dport == 3702 || sport == 3702)) {
                    char clean_payload[513]; int plen = (payload_len > 512) ? 512 : payload_len;
                    sanitize_field(payload, plen, clean_payload, sizeof(clean_payload), 1);
                    char l7_sig[640];
                    source_dedup_signature(l7_sig, sizeof(l7_sig), src_ip_str, clean_payload, routed_str);
                    if (clean_payload[0] && !dedup_should_suppress(mac_str, "L7", l7_sig, opt_multi_rl)) {
                        emit_telemetry("L7|%s|%s|%d|%s%s\n", mac_str, src_ip_str, (dport == 1900 || dport == 3702) ? dport : sport, clean_payload, routed_str);
                    }
                }
                else if (opt_multi && (dport == 5353 || sport == 5353)) {
                    parse_mdns(payload, payload_len, mac_str, src_ip_str, (dport == 5353) ? dport : sport, routed_str, opt_multi_rl);
                }
                else if (opt_dns && (dport == 53 || sport == 53)) {
                    if (payload_len > 12) {
                        uint16_t flags = read_be16(payload + 2);
                        int is_response = (flags & 0x8000) != 0;
                        uint16_t txid = read_be16(payload);

                        if (!is_response && dport == 53) {
                            char qname[256];
                            uint16_t qtype = 0;
                            if (decode_dns_name(payload, payload_len, 12, qname, sizeof(qname)) > 0 && qname[0]) {
                                (void)dns_question_qtype(payload, payload_len, 12, &qtype);
                                if (opt_ext_metrics) {
                                    uint32_t slot = (txid ^ flow_src_key) & (TRACK_SLOTS - 1);
                                    dns_table[slot].txid = txid;
                                    dns_table[slot].qtype = qtype;
                                    dns_table[slot].src_ip = flow_src_key;
                                    dns_table[slot].ts_usec = pkt_usec;
                                    dns_table[slot].routed = (uint8_t)(routed_evidence ? 1 : 0);
                                    memcpy(dns_table[slot].mac, src_mac, 6);
                                    size_t domain_len = strlen(qname);
                                    if (domain_len >= sizeof(dns_table[slot].domain)) domain_len = sizeof(dns_table[slot].domain) - 1U;
                                    memcpy(dns_table[slot].domain, qname, domain_len);
                                    dns_table[slot].domain[domain_len] = '\0';
                                }
                                char dns_sig[384];
                                source_dedup_signature(dns_sig, sizeof(dns_sig), src_ip_str, qname, routed_str);
                                if (!dedup_should_suppress(mac_str, "DNS", dns_sig, opt_dns_rl)) {
                                    emit_telemetry("DNS|%s|%s|%s%s\n", mac_str, src_ip_str, qname, routed_str);
                                }
                            }
                        }
                        else if (is_response && sport == 53) {
                            if (opt_ext_metrics) {
                                uint32_t slot = (txid ^ flow_dst_key) & (TRACK_SLOTS - 1);
                                if (dns_table[slot].txid == txid && dns_table[slot].src_ip == flow_dst_key
                                    && pkt_usec >= dns_table[slot].ts_usec
                                    && (pkt_usec - dns_table[slot].ts_usec) < 5000000ULL) {
                                    uint8_t rcode = flags & 0x000F;
                                    uint64_t latency_us = pkt_usec - dns_table[slot].ts_usec;
                                    float ent = calculate_entropy(dns_table[slot].domain);

                                    char client_mac_str[18];
                                    snprintf(client_mac_str, sizeof(client_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                                             dns_table[slot].mac[0], dns_table[slot].mac[1], dns_table[slot].mac[2],
                                             dns_table[slot].mac[3], dns_table[slot].mac[4], dns_table[slot].mac[5]);

                                    char dnsext_sig[384];
                                    source_dedup_signature(dnsext_sig, sizeof(dnsext_sig), dst_ip_str,
                                                           dns_table[slot].domain,
                                                           dns_table[slot].routed ? "|routed" : "");
                                    if (!dedup_should_suppress(client_mac_str, "DNSEXT", dnsext_sig, opt_dns_rl)) {
                                        emit_telemetry("DNSEXT|%s|%s|%s|%s|%u|%u|%.2f|%.2f%s\n",
                                            client_mac_str, dst_ip_str, src_ip_str, dns_table[slot].domain,
                                            (unsigned)dns_table[slot].qtype, (unsigned)rcode,
                                            (float)latency_us / 1000.0f, ent,
                                            dns_table[slot].routed ? "|routed" : "");
                                    }
                                    char alert_sig[192];
                                    source_dedup_signature(alert_sig, sizeof(alert_sig), dst_ip_str,
                                                           "HIGH_DNS_ENTROPY",
                                                           dns_table[slot].routed ? "|routed" : "");
                                    if (ent >= 4.2f &&
                                        !dedup_should_suppress(client_mac_str, "ALERT", alert_sig, opt_dns_rl)) {
                                        emit_telemetry("ALERT|%s|%s|HIGH_DNS_ENTROPY|%s|%.2f%s\n",
                                                       client_mac_str, dst_ip_str, dns_table[slot].domain, ent,
                                                       dns_table[slot].routed ? "|routed" : "");
                                    }
                                    dns_table[slot].txid = 0;
                                }
                            }
                        }
                    }
                }
                else if (opt_tls && dport == 443) {
                    parse_quic(payload, payload_len, mac_str, src_ip_str, dst_ip_str, dport, routed_str, opt_tls_rl);
                }
            }
        }
        if (opt_v6) {
            uint64_t processing_end_us = get_current_usec();
            if (processing_end_us >= processing_start_us && processing_end_us - processing_start_us > max_loop_us)
                max_loop_us = processing_end_us - processing_start_us;
        }
    }

    /* Cleanup sockets and resources */
    for (int i = 0; i < num_ifaces; i++) close(active_ifaces[i].fd);
    if (ipc_sock >= 0) close(ipc_sock);
    if (remote_sock >= 0) close(remote_sock);
    free(syn_table); free(dns_table); free(dedup_table); free(owner4_table); free(owner6_table);
    close(epoll_fd);
    return 0;
}
#endif
