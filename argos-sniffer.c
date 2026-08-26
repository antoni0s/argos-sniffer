/* ============================================================================
 * argos-sniffer.c - passive LAN traffic fingerprinter & live packet inspector
 *                    for OpenWrt routers.
 * Version: 4.9.1 (Target-Filtered Telemetry + IPv6-Aware Capture + WSD)
 *
 * Core Features:
 *  - Native Target Packet Inspector mode (-z <mac> [-c <count>]): a self
 *    contained replacement for tcpdump, dumping live packets to/from one MAC.
 *  - Target-Filtered Telemetry mode (-Z <mac>): restricts the normal
 *    Telemetry Daemon Profiler (Mode 2, all the -s/-d/-q/... vectors) to a
 *    single device, instead of fingerprinting every device on the LAN.
 *  - Explicit MAC Exclusion (-x <mac>): drops telemetry for chosen devices.
 *    Multiple values supported.
 *  - Promiscuous mode is OFF by default; enabled with -p, or automatically
 *    when -z is used (Mode 1 needs to see traffic not addressed to us).
 *  - Full TCP Options parsing (MSS, WScale, SACK, TS) for exact p0f-style
 *    classification of SYN/SYNACK packets.
 *  - IPv4 privacy filtering: 0.0.0.0 (pre-DHCP), 169.254.0.0/16 (APIPA
 *    link-local), and RFC1918 (10/8, 172.16/12, 192.168/16) are treated as
 *    "on my LAN" source addresses.
 *  - IPv6 privacy filtering: the unspecified address :: (pre-SLAAC/DHCPv6,
 *    the IPv6 equivalent of 0.0.0.0), fe80::/10 link-local (the IPv6
 *    equivalent of APIPA), and fc00::/7 Unique Local Addresses (the IPv6
 *    equivalent of RFC1918) are treated the same way.
 *  - No unaligned / strict-aliasing-violating reads (safe on aarch64+musl).
 *  - 802.1Q VLAN tag support (both kernel BPF and userspace L2 extraction).
 *  - All log fields sanitized (no '|' or control-char injection).
 *  - Stateful Telemetry Deduplication / Rate-Limiting per vector via
 *    lowercase/uppercase flags, backed by a 4096-slot hash table.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#define VERSION "4.9.1"

/* ============================================================================
 * SECTION: Graceful shutdown
 *
 * A single sig_atomic_t flag drives the main capture loop. SIGINT/SIGTERM
 * flip it to 0 so the loop exits cleanly (closes the socket, etc.) instead
 * of being killed mid-packet.
 * ============================================================================ */

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

static void install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /*
     * This runs as an unattended daemon writing every emitted line to
     * stdout via printf(), typically piped into a log collector
     * (`argos-sniffer ... | logger`, `| nc host port`, a systemd/procd
     * StandardOutput pipe, etc.). If the reading end of that pipe ever
     * goes away (consumer restarts, connection drops), the *next* write
     * to stdout raises SIGPIPE - and SIGPIPE's default disposition is to
     * terminate the process immediately, with no log message and no
     * chance for procd/systemd to tell you why it died.
     *
     * Ignoring SIGPIPE turns that into an ordinary failed write instead:
     * printf() (and the underlying write()) will just return -1 with
     * errno == EPIPE, letting the daemon keep running rather than dying
     * silently the moment nobody is listening on the other end of stdout.
     */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* ============================================================================
 * SECTION: Telemetry deduplication / rate-limiting engine
 *
 * Every emitted telemetry line is optionally passed through
 * dedup_should_suppress() first. Each per-vector CLI flag has a lowercase
 * ("rate limited") and uppercase ("no limit") form; the caller decides
 * which policy applies per-event via the rl_enabled argument.
 *
 * Implementation: a fixed-size, direct-mapped hash table keyed on
 * FNV-1a(mac|event_type|payload). On a collision (two different keys
 * mapping to the same slot) the newer event simply evicts the older one -
 * this is a deliberate speed/memory tradeoff, not a correctness bug, but
 * it does mean a busy LAN can occasionally cause a device's suppression
 * window to reset early. DEDUP_SLOTS below controls how often that
 * happens; bigger table = fewer accidental evictions, at a small RAM cost.
 * ============================================================================ */

/*
 * 4096 slots (up from the original 512) at sizeof(dedup_entry_t) == 16
 * bytes (uint64_t key + time_t last_seen on a typical 64-bit build) works
 * out to 4096 * 16 = 65536 bytes (64KB) of static BSS. That is trivial
 * even on the most RAM-constrained OpenWrt targets that can run this
 * program at all (raw AF_PACKET sockets + a BPF filter already implies a
 * "real" Linux kernel, not a handful-of-MB embedded target). If you are
 * deploying on an unusually tight device and want to trade collision
 * resistance for a smaller footprint, this can be dropped back down (must
 * stay a power of two, since slot selection uses a bitmask: h & (N-1)).
 */
#define DEDUP_SLOTS 4096
static int rate_limit_ttl = 35; /* Default suppression window in seconds (-f) */

typedef struct {
    uint64_t key;       /* hash of mac + event_type + payload signature */
    time_t   last_seen;
} dedup_entry_t;
static dedup_entry_t dedup_table[DEDUP_SLOTS];

/* Simple FNV-1a style hash over arbitrary bytes. Used only for dedup
 * bucketing, not for anything security-sensitive. */
static uint64_t hash_bytes(const void *data, size_t len) {
    const unsigned char *p = data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/*
 * Returns 1 if this event should be SUPPRESSED (an identical event from
 * the same MAC was already emitted within the last `rate_limit_ttl`
 * seconds), or 0 if it should be emitted (and is now recorded as "seen").
 *
 * rl_enabled is the per-vector policy passed down from main(): telemetry
 * vectors enabled with their uppercase CLI flag pass 0 here (never
 * suppress, always emit); vectors enabled with their lowercase CLI flag
 * pass 1 (rate-limit against repeats).
 */
static int dedup_should_suppress(const char *mac, const char *evtype, const char *payload, int rl_enabled) {
    /* Vector-level opt-out (uppercase flag) or globally disabled (-f 0): emit everything. */
    if (!rl_enabled || rate_limit_ttl <= 0) return 0;

    char buf[512];
    int n = snprintf(buf, sizeof(buf), "%s|%s|%s", mac, evtype, payload ? payload : "");
    if (n < 0) n = 0;
    else if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;

    uint64_t h = hash_bytes(buf, (size_t)n);
    size_t slot = h & (DEDUP_SLOTS - 1);
    time_t now = time(NULL);

    if (dedup_table[slot].key == h && (now - dedup_table[slot].last_seen) < rate_limit_ttl) {
        dedup_table[slot].last_seen = now; /* refresh window without re-emitting */
        return 1; /* suppress */
    }

    dedup_table[slot].key = h;
    dedup_table[slot].last_seen = now;
    return 0; /* emit */
}

/* ============================================================================
 * SECTION: Router self-exclusion (-r)
 *
 * The router's own MAC(s) are excluded from telemetry so the daemon
 * profiles *other* devices on the LAN, not itself. Multiple -r flags are
 * supported (e.g. a router with several LAN-side interfaces/MACs).
 * ============================================================================ */

#define MAX_ROUTER_MACS 8
static unsigned char router_macs[MAX_ROUTER_MACS][6];
static int router_mac_count = 0;

/* Checks if the source MAC belongs to one of the configured router MACs. */
static inline int is_router_mac(const unsigned char *shost) {
    for (int i = 0; i < router_mac_count; i++) {
        if (memcmp(shost, router_macs[i], 6) == 0) return 1;
    }
    return 0;
}

/* ============================================================================
 * SECTION: Explicit MAC exclusion (-x)
 *
 * Exclude specific MAC addresses from being profiled. Multiple -x flags
 * are supported (e.g. to ignore trusted or chatty devices).
 * ============================================================================ */

#define MAX_EXCLUDED_MACS 16
static unsigned char excluded_macs[MAX_EXCLUDED_MACS][6];
static int excluded_mac_count = 0;

/* Checks if the source MAC belongs to one of the explicitly excluded MACs. */
static inline int is_excluded_mac(const unsigned char *shost) {
    for (int i = 0; i < excluded_mac_count; i++) {
        if (memcmp(shost, excluded_macs[i], 6) == 0) return 1;
    }
    return 0;
}

/* ============================================================================
 * SECTION: Kernel-side BPF pre-filter
 *
 * Attached to the raw socket in Mode 2 (Telemetry Profiler) only - Mode 1
 * (-z live sniffer) needs to see every ethertype, so it skips this filter
 * entirely and does its own matching in userspace.
 *
 * This program accepts frames at the kernel level (avoiding a userspace
 * copy+syscall for everything else on the wire) whose EtherType at offset
 * 12 is one of: IPv4 (0x0800), IPv6 (0x86dd), LLDP (0x88cc), or 802.1Q
 * VLAN (0x8100). Everything else (bare ARP, other L2 protocols, etc.) is
 * dropped before it ever reaches this process. VLAN-tagged frames are
 * accepted unconditionally here; the *inner* ethertype (after the tag) is
 * re-checked in userspace once the frame arrives.
 * ============================================================================ */

static struct sock_filter bpf_code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 1, 0x00000800 },
    { 0x06, 0, 0, 0x00040000 },
    { 0x15, 0, 1, 0x000086dd },
    { 0x06, 0, 0, 0x00040000 },
    { 0x15, 0, 1, 0x000088cc },
    { 0x06, 0, 0, 0x00040000 },
    { 0x15, 0, 1, 0x00008100 },
    { 0x06, 0, 0, 0x00040000 },
    { 0x06, 0, 0, 0x00000000 },
};
static struct sock_fprog bpf_prog = {
    .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
    .filter = bpf_code,
};

/* ============================================================================
 * SECTION: Small byte/buffer helpers shared by every protocol parser below
 * ============================================================================ */

/* Big-endian 16-bit read that never triggers unaligned-access or strict-
 * aliasing UB (reads raw bytes, no pointer cast to uint16_t*). */
static inline uint16_t read_be16(const unsigned char *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Case-sensitive byte-string search (memmem-alike, but portable). */
static const unsigned char *find_bytes(const unsigned char *haystack, size_t haystacklen, const unsigned char *needle, size_t needlelen) {
    if (needlelen == 0 || haystacklen < needlelen) return NULL;
    size_t last = haystacklen - needlelen;
    for (size_t i = 0; i <= last; i++) {
        if (haystack[i] == needle[0] && memcmp(haystack + i, needle, needlelen) == 0) return haystack + i;
    }
    return NULL;
}

/* Case-insensitive byte-string search, used for the "User-Agent:" header
 * match (HTTP header names are case-insensitive per RFC 7230). */
static const unsigned char *find_bytes_ci(const unsigned char *haystack, size_t haystacklen, const char *needle, size_t needlelen) {
    if (needlelen == 0 || haystacklen < needlelen) return NULL;
    size_t last = haystacklen - needlelen;
    for (size_t i = 0; i <= last; i++) {
        size_t j = 0;
        for (; j < needlelen; j++) {
            unsigned char hc = haystack[i + j];
            unsigned char nc = (unsigned char)needle[j];
            if (tolower(hc) != tolower(nc)) break;
        }
        if (j == needlelen) return haystack + i;
    }
    return NULL;
}

/* ============================================================================
 * SECTION: "Is this address on my LAN?" privacy filters
 *
 * These decide which source addresses Mode 2 (the Telemetry Profiler)
 * will actually process. The IPv4 and IPv6 versions are intentionally
 * structured as direct analogues of each other:
 *
 *   IPv4                         IPv6                         Meaning
 *   ------------------------     --------------------------   -------------------------
 *   0.0.0.0                      :: (unspecified)             "no address yet" (pre-DHCP
 *                                                              / pre-DHCPv6 / pre-SLAAC)
 *   169.254.0.0/16 (APIPA)       fe80::/10 (link-local)       link-local-only address
 *   10/8, 172.16/12, 192.168/16  fc00::/7 (ULA)               private, LAN-routable space
 *   (RFC1918)                    (RFC4193)
 *
 * Note on IPv6 in particular: unlike IPv4 private space, it is completely
 * normal for a LAN client to talk to the internet using a *global* unicast
 * address (2000::/3) obtained via SLAAC/DHCPv6-PD from the router's
 * delegated prefix - there is no NAT hiding it the way RFC1918 does for
 * IPv4. That means a flow's IPv6 source can legitimately be a GUA even
 * though the device is sitting right there on the LAN. is_private_ipv6()
 * deliberately does NOT treat GUAs as "private" (mirroring is_private_ipv4
 * exactly, which likewise doesn't special-case a NAT'd public IPv4), so a
 * device's IPv6-sourced flows to the internet (e.g. TLS ClientHellos, DNS
 * queries over IPv6) will not be captured by this filter alone. In
 * practice this is usually fine: the same device's link-local traffic
 * (mDNS, LLDP, NDP, DHCPv6) still gets through and is normally enough to
 * fingerprint it. If you specifically want GUA-sourced IPv6 flows
 * captured too, add a 2000::/3 check below.
 * ============================================================================ */

static int is_private_ipv4(uint32_t ip_be) {
    uint32_t ip = ntohl(ip_be);
    if (ip == 0) return 1;
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return 1;
    if ((ip & 0xFF000000) == 0x0A000000) return 1;
    if ((ip & 0xFFF00000) == 0xAC100000) return 1;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return 1;
    return 0;
}

static int is_private_ipv6(const struct in6_addr *addr) {
    const unsigned char *a = addr->s6_addr;

    /* Unspecified address :: - all 16 bytes zero. IPv6 equivalent of
     * IPv4's 0.0.0.0: seen as a source address before a device has
     * finished acquiring an address (e.g. early DHCPv6 Solicit/Duplicate
     * Address Detection exchanges). */
    int all_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (a[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) return 1;

    /* Link-local unicast fe80::/10 - first 10 bits are 1111111010,
     * i.e. byte0 == 0xfe and the top two bits of byte1 are 10.
     * IPv6 equivalent of IPv4 APIPA (169.254.0.0/16). */
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 1;

    /* Unique Local Address fc00::/7 - top 7 bits are 1111110, i.e.
     * byte0 is 0xfc or 0xfd. IPv6 equivalent of RFC1918 private space. */
    if ((a[0] & 0xfe) == 0xfc) return 1;

    return 0;
}

/* ============================================================================
 * SECTION: Output sanitization
 *
 * Every string pulled out of a packet and destined for a printf() line
 * goes through here first, so a malicious/malformed payload can't inject
 * '|' (the log field delimiter) or control characters into the output.
 * ============================================================================ */

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
 * SECTION: Protocol-specific telemetry parsers (Mode 2 vectors)
 *
 * Each function here corresponds to one -x/-X CLI vector. They all follow
 * the same shape: bounds-check as they walk the packet, extract whatever
 * fields the protocol offers, sanitize them, run the result past
 * dedup_should_suppress(), and printf() a pipe-delimited log line.
 * ============================================================================ */

/* TLS ClientHello -> Server Name Indication (-t / -T). Walks the record
 * header, session ID, cipher suites, compression methods, then the
 * extensions list looking for extension type 0 (server_name). */
static void parse_tls_sni(const unsigned char *payload, int len, const char *mac, const char *src_ip, int rl_enabled) {
    if (len < 44) return;
    if (payload[0] != 0x16 || payload[5] != 0x01) return;

    int pos = 43;
    if (pos >= len) return;
    pos += payload[pos] + 1;               /* skip session ID */

    if (pos + 2 > len) return;
    pos += (read_be16(payload + pos)) + 2; /* skip cipher suites */

    if (pos + 1 > len) return;
    pos += payload[pos] + 1;               /* skip compression methods */

    if (pos + 2 > len) return;
    int ext_len = read_be16(payload + pos);
    pos += 2;
    int end = pos + ext_len;
    if (end > len) end = len;

    while (pos + 4 <= end) {
        int e_type = read_be16(payload + pos);
        int e_len = read_be16(payload + pos + 2);
        pos += 4;
        if (e_type == 0 && pos + e_len <= end && e_len >= 5) {
            int sn_len = read_be16(payload + pos + 3);
            if (payload[pos + 2] == 0 && pos + 5 + sn_len <= end && sn_len < 256) {
                char sni[256];
                sanitize_field(payload + pos + 5, sn_len, sni, sizeof(sni), 0);
                if (sni[0] && !dedup_should_suppress(mac, "SNI", sni, rl_enabled)) {
                    printf("SNI|%s|%s|%s\n", mac, src_ip, sni);
                }
            }
            break;
        }
        pos += e_len;
    }
}

/* LLDP neighbor announcements (-l / -L). Pulls System Name (TLV type 5)
 * and System Description (TLV type 6). */
static void parse_lldp(const unsigned char *payload, int len, const char *mac, int rl_enabled) {
    int pos = 0;
    char sysname_raw[128] = {0};
    char sysdesc_raw[256] = {0};
    int have_name = 0, have_desc = 0;

    while (pos + 2 <= len) {
        uint16_t tlv = read_be16(payload + pos);
        int type = tlv >> 9;
        int tlv_len = tlv & 0x01ff;
        pos += 2;

        if (type == 0 || pos + tlv_len > len) break; /* type 0 = End-of-LLDPDU */
        if (type == 5) {
            int n = tlv_len < (int)sizeof(sysname_raw) - 1 ? tlv_len : (int)sizeof(sysname_raw) - 1;
            memcpy(sysname_raw, payload + pos, n);
            sysname_raw[n] = '\0';
            have_name = 1;
        } else if (type == 6) {
            int n = tlv_len < (int)sizeof(sysdesc_raw) - 1 ? tlv_len : (int)sizeof(sysdesc_raw) - 1;
            memcpy(sysdesc_raw, payload + pos, n);
            sysdesc_raw[n] = '\0';
            have_desc = 1;
        }
        pos += tlv_len;
    }
    if (have_name || have_desc) {
        char sysname[128], sysdesc[256], payload_sig[384];
        sanitize_field((unsigned char*)sysname_raw, (int)strlen(sysname_raw), sysname, sizeof(sysname), 0);
        sanitize_field((unsigned char*)sysdesc_raw, (int)strlen(sysdesc_raw), sysdesc, sizeof(sysdesc), 0);
        snprintf(payload_sig, sizeof(payload_sig), "%s|%s", sysname, sysdesc);

        if (!dedup_should_suppress(mac, "LLDP", payload_sig, rl_enabled)) {
            printf("LLDP|%s|%s|%s\n", mac, sysname, sysdesc);
        }
    }
}

/* Decodes the classic NetBIOS "first-level encoding" (each name byte
 * split into two nibbles, each nibble offset into 'A'..'P'). */
static void decode_netbios_name(const unsigned char *enc, char *out, int outsize) {
    int o = 0;
    for (int i = 0; i + 1 < 32 && o < outsize - 1; i += 2) {
        if (enc[i] < 'A' || enc[i] > 'P' || enc[i+1] < 'A' || enc[i+1] > 'P') break;
        unsigned char hi = enc[i] - 'A';
        unsigned char lo = enc[i+1] - 'A';
        unsigned char c = (unsigned char)((hi << 4) | lo);
        if (c == 0 || c == 0x20) break; /* NUL / padding marks end of name */
        out[o++] = (c >= 32 && c <= 126 && c != '|') ? (char)c : ' ';
    }
    out[o] = '\0';
    while (o > 0 && out[o-1] == ' ') out[--o] = '\0'; /* trim trailing padding */
}

/* NetBIOS Name Service query (-n / -N), UDP/137. */
static void parse_netbios(const unsigned char *payload, int len, const char *mac, const char *src_ip, int rl_enabled) {
    if (len < 50) return;
    if (payload[12] != 0x20) return; /* expect the standard 0x20-byte name length prefix */
    char name[17];
    decode_netbios_name(payload + 13, name, sizeof(name));
    if (name[0] && !dedup_should_suppress(mac, "NBNS", name, rl_enabled)) {
        printf("NBNS|%s|%s|%s\n", mac, src_ip, name);
    }
}

/* DHCP options (-d / -D), UDP/67: Hostname (option 12), Vendor Class
 * Identifier (option 60), and Parameter Request List (option 55). */
static void parse_dhcp(const unsigned char *payload, int len, const char *mac, const char *src_ip, int rl_enabled) {
    if (len < 241) return;
    if (payload[236] != 0x63 || payload[237] != 0x82 || payload[238] != 0x53 || payload[239] != 0x63) return; /* magic cookie */

    char hostname_raw[64] = {0}, vendor_raw[64] = {0}, prl_raw[256] = {0};
    int have_host = 0, have_vendor = 0, have_prl = 0;
    int pos = 240;

    while (pos < len) {
        uint8_t code = payload[pos++];
        if (code == 0xff) break;   /* End option */
        if (code == 0x00) continue; /* Pad option */
        if (pos >= len) break;
        uint8_t olen = payload[pos++];
        if (pos + olen > len) break;

        if (code == 12) {
            int n = olen < (int)sizeof(hostname_raw) - 1 ? olen : (int)sizeof(hostname_raw) - 1;
            memcpy(hostname_raw, payload + pos, n);
            hostname_raw[n] = '\0';
            have_host = 1;
        } else if (code == 60) {
            int n = olen < (int)sizeof(vendor_raw) - 1 ? olen : (int)sizeof(vendor_raw) - 1;
            memcpy(vendor_raw, payload + pos, n);
            vendor_raw[n] = '\0';
            have_vendor = 1;
        } else if (code == 55) {
            size_t used = 0;
            for (int j = 0; j < olen && used < sizeof(prl_raw) - 8; j++) {
                int n = snprintf(prl_raw + used, sizeof(prl_raw) - used, "%s%u", used ? "," : "", payload[pos + j]);
                if (n > 0) used += n;
            }
            have_prl = 1;
        }
        pos += olen;
    }

    if (have_host || have_vendor || have_prl) {
        char host[64], vendor[64], prl[256], payload_sig[384];
        sanitize_field((unsigned char*)hostname_raw, (int)strlen(hostname_raw), host, sizeof(host), 0);
        sanitize_field((unsigned char*)vendor_raw, (int)strlen(vendor_raw), vendor, sizeof(vendor), 0);
        sanitize_field((unsigned char*)prl_raw, (int)strlen(prl_raw), prl, sizeof(prl), 0);
        snprintf(payload_sig, sizeof(payload_sig), "%s|%s|%s", host, vendor, prl);

        if (!dedup_should_suppress(mac, "DHCP", payload_sig, rl_enabled)) {
            printf("DHCP|%s|%s|%s|%s|%s\n", mac, src_ip, host, vendor, prl);
        }
    }
}

/* Decodes a DNS-wire-format name starting at start_pos. Compression
 * pointers (top two bits set) are detected and stop decoding rather than
 * being followed - conservative, but avoids any pointer-loop hazards. */
static int decode_dns_name(const unsigned char *payload, int payload_len, int start_pos, char *out, int out_max) {
    int pos = start_pos;
    int o = 0;
    int guard = 0;
    while (pos < payload_len && payload[pos] != 0 && o < out_max - 1 && guard++ < 64) {
        int label_len = payload[pos++];
        if ((label_len & 0xC0) == 0xC0) break; /* compression pointer: not followed */
        if (label_len > 63 || pos + label_len > payload_len) break;
        if (o > 0) out[o++] = '.';
        for (int i = 0; i < label_len && pos < payload_len && o < out_max - 1; i++) {
            unsigned char c = payload[pos++];
            out[o++] = (isalnum(c) || c == '-' || c == '_') ? (char)tolower(c) : '.';
        }
    }
    out[o] = '\0';
    return o;
}

/* mDNS (-m / -M), UDP/5353: logs the first question name in the packet. */
static void parse_mdns(const unsigned char *payload, int len, const char *mac, const char *src_ip, int dport_or_sport, int rl_enabled) {
    if (len < 12) return;
    uint16_t qdcount = read_be16(payload + 4);
    if (qdcount == 0) return;

    int pos = 12;
    char qname[256];
    int n = decode_dns_name(payload, len, pos, qname, sizeof(qname));
    if (n <= 0) return;

    if (qname[0] && !dedup_should_suppress(mac, "MDNS", qname, rl_enabled)) {
        printf("MDNS|%s|%s|%d|%s\n", mac, src_ip, dport_or_sport, qname);
    }
}

/* ============================================================================
 * SECTION: Mode 1 - Native Target Packet Inspector (-z)
 *
 * A self-contained, tcpdump-style formatter used only when -z is given.
 * Every matching frame (src or dst MAC == target) is dumped here instead
 * of being run through the Mode 2 telemetry vectors.
 * ============================================================================ */

static void dump_target_packet(const unsigned char *buffer, int len, int l2_len, uint16_t eth_type) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    char tmbuf[32];
    strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", tm_info);

    if (eth_type == 0x0800 && len >= l2_len + 20) {
        struct iphdr *ip = (struct iphdr *)(buffer + l2_len);
        char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
        struct in_addr s_in, d_in;

        s_in.s_addr = ip->saddr;
        d_in.s_addr = ip->daddr;
        inet_ntop(AF_INET, &s_in, s_ip, sizeof(s_ip));
        inet_ntop(AF_INET, &d_in, d_ip, sizeof(d_ip));

        int l4_offset = l2_len + (ip->ihl * 4);

        if (ip->protocol == IPPROTO_TCP && len >= l4_offset + 20) {
            struct tcphdr *tcp = (struct tcphdr *)(buffer + l4_offset);
            char flags[16] = {0};
            int fi = 0;
            if (tcp->syn) flags[fi++] = 'S';
            if (tcp->ack) flags[fi++] = '.';
            if (tcp->psh) flags[fi++] = 'P';
            if (tcp->fin) flags[fi++] = 'F';
            if (tcp->rst) flags[fi++] = 'R';
            flags[fi] = '\0';

            printf("%s.%06d IP %s.%u > %s.%u: Flags [%s], seq %u, win %u, length %d\n",
                   tmbuf, (int)tv.tv_usec, s_ip, ntohs(tcp->source), d_ip, ntohs(tcp->dest),
                   flags[0] ? flags : "none", (uint32_t)ntohl(tcp->seq), ntohs(tcp->window), (int)len - l4_offset - (tcp->doff * 4));

        } else if (ip->protocol == IPPROTO_UDP && len >= l4_offset + 8) {
            struct udphdr *udp = (struct udphdr *)(buffer + l4_offset);
            printf("%s.%06d IP %s.%u > %s.%u: UDP, length %u\n",
                   tmbuf, (int)tv.tv_usec, s_ip, ntohs(udp->source), d_ip, ntohs(udp->dest), ntohs(udp->len));

        } else if (ip->protocol == IPPROTO_ICMP) {
            printf("%s.%06d IP %s > %s: ICMP, length %d\n", tmbuf, (int)tv.tv_usec, s_ip, d_ip, (int)len - l4_offset);
        } else {
            printf("%s.%06d IP %s > %s: proto %u, length %d\n", tmbuf, (int)tv.tv_usec, s_ip, d_ip, ip->protocol, (int)len - l2_len);
        }

    } else if (eth_type == 0x86dd && len >= l2_len + 40) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + l2_len);
        char s_ip6[INET6_ADDRSTRLEN], d_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, s_ip6, sizeof(s_ip6));
        inet_ntop(AF_INET6, &ip6->ip6_dst, d_ip6, sizeof(d_ip6));
        printf("%s.%06d IP6 %s > %s: next-hdr %u, length %d\n",
               tmbuf, (int)tv.tv_usec, s_ip6, d_ip6, ip6->ip6_nxt, ntohs(ip6->ip6_plen));

    } else if (eth_type == 0x0806) {
        printf("%s.%06d ARP, length %d\n", tmbuf, (int)tv.tv_usec, (int)len - l2_len);
    } else {
        printf("%s.%06d ethertype 0x%04x, length %d\n", tmbuf, (int)tv.tv_usec, eth_type, (int)len);
    }
    fflush(stdout);
}

/* ============================================================================
 * SECTION: CLI help text
 * ============================================================================ */

static void print_help(const char *prog) {
    printf(
"argos-sniffer v" VERSION " - Passive LAN traffic fingerprinter & live inspector for OpenWrt\n\n"
"USAGE:\n  %s [-i iface] [-r router_mac] [-x exclude_mac] [-z target_mac | -Z target_mac] [-f seconds] [FLAGS...]\n"
"  OR:     %s [iface] (Automatically sets -i <iface> and enables all vectors with -a)\n\n"
"OPTIONS:\n"
"  -i <iface>      Interface to listen on (default: br-lan)\n"
"  -r <mac>        Router's own MAC (can be used multiple times) to exclude self-profiling\n"
"  -x <mac>        Exclude a specific MAC address from telemetry (can be used multiple times)\n"
"  -z <target_mac> Mode 1: Native Live Sniffer for one MAC (replaces tcpdump). Exclusive:\n"
"                  when set, no telemetry vectors run and -Z is ignored.\n"
"  -Z <target_mac> Mode 2 target filter: restricts the telemetry vectors below (-s/-d/-q/...)\n"
"                  to a single device instead of the whole LAN. Combine with -p if you also\n"
"                  need to see that device's traffic to/from other LAN peers, not just the\n"
"                  router. Has no effect if -z is also given (see above).\n"
"  -c <count>      Maximum packet count before exiting, Mode 1 only (default: 0 for unlimited)\n"
"  -p              Enable promiscuous mode (auto-enabled if -z is set)\n"
"  -f <seconds>    Deduplication window in seconds (default: 35)\n\n"
"TELEMETRY VECTORS (Lowercase = ENABLE WITH RATE LIMIT | Uppercase = ENABLE NO LIMIT):\n"
"  -s / -S         TCP SYN (p0f) & SYNACK (open ports) fingerprinting\n"
"  -m / -M         mDNS (5353) / SSDP (1900) / WSD (3702) payload logging\n"
"  -d / -D         DHCP options (Hostname, VCI, PRL Option 55) logging\n"
"  -n / -N         NetBIOS Name Service (UDP 137) logging\n"
"  -q / -Q         DNS Queries (UDP port 53)\n"
"  -h / -H         HTTP User-Agent extraction (port 80/8080)\n"
"  -t / -T         TLS ClientHello SNI extraction (port 443)\n"
"  -l / -L         LLDP (L2 neighbor discovery)\n"
"  -a / -A         Enable ALL vectors above (a = with limits, A = without limits)\n"
"  -v / -V         Enable IPv6 handling (subject to is_private_ipv6() filtering, see source)\n\n"
"OUTPUT FORMAT (pipe-delimited for daemon, or formatted text for -z):\n"
"  SYN|mac|src_ip|ttl|window|wscale|mss|opts_layout|dst_port\n"
"  SYNACK|mac|src_ip|ttl|window|wscale|mss|opts_layout|src_port\n"
"  HTTP|mac|src_ip|user_agent\n"
"  SNI|mac|src_ip|hostname\n"
"  LLDP|mac|sysname|sysdesc\n"
"  NBNS|mac|src_ip|netbios_name\n"
"  DHCP|mac|src_ip|hostname|vendor_class|prl\n"
"  DNS|mac|src_ip|query_domain\n"
"  MDNS|mac|src_ip|port|qname\n"
"  L7|mac|src_ip|dst_port|payload\n", prog, prog);
}

/* ============================================================================
 * SECTION: main() - CLI parsing, socket setup, and the capture loop
 * ============================================================================ */

int main(int argc, char *argv[]) {
    const char *iface = "br-lan";

    /* Mode 1 (-z): live packet inspector target. */
    unsigned char target_mac[6];
    int have_target_mac = 0;
    int max_packets = 0;
    int packet_count = 0;

    /* Mode 2 (-Z): telemetry-vector target filter (only meaningful when
     * -z is NOT set - Mode 1 takes exclusive control of the capture loop
     * whenever it's active). */
    unsigned char telemetry_target_mac[6];
    int have_telemetry_target = 0;

    /* Vector activation flags (Mode 2). */
    int opt_syn = 0, opt_multi = 0, opt_dhcp = 0, opt_netbios = 0, opt_dns = 0;
    int opt_http = 0, opt_tls = 0, opt_l2 = 0;
    int opt_v6 = 0, opt_promisc = 0;

    /* Per-Vector Rate Limiting flags (1 = limited, 0 = unlimited). */
    int opt_syn_rl = 0, opt_multi_rl = 0, opt_dhcp_rl = 0, opt_netbios_rl = 0;
    int opt_dns_rl = 0, opt_http_rl = 0, opt_tls_rl = 0, opt_l2_rl = 0;

    int opt;

    if (argc == 1) { print_help(argv[0]); return 0; }

    /* ---- Argument parsing --------------------------------------------- */
    while ((opt = getopt(argc, argv, "i:r:x:z:Z:c:f:sSmMdDnNqQhHtTlLvVpaA")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'r': {
                if (router_mac_count < MAX_ROUTER_MACS) {
                    unsigned int m[6];
                    if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                        for (int i = 0; i < 6; i++) router_macs[router_mac_count][i] = (unsigned char)m[i];
                        router_mac_count++;
                    }
                }
                break;
            }
            case 'x': { /* Exclude specific MAC from telemetry */
                if (excluded_mac_count < MAX_EXCLUDED_MACS) {
                    unsigned int m[6];
                    if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                        for (int i = 0; i < 6; i++) excluded_macs[excluded_mac_count][i] = (unsigned char)m[i];
                        excluded_mac_count++;
                    }
                }
                break;
            }
            case 'z': { /* Mode 1: Target MAC for the live sniffer/packet inspector */
                unsigned int m[6];
                if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) target_mac[i] = (unsigned char)m[i];
                    have_target_mac = 1;
                    opt_promisc = 1; /* Auto-enable promiscuous mode for target inspection */
                }
                break;
            }
            case 'Z': { /* Mode 2: Target MAC to filter telemetry vectors down to */
                unsigned int m[6];
                if (sscanf(optarg, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) telemetry_target_mac[i] = (unsigned char)m[i];
                    have_telemetry_target = 1;
                }
                break;
            }
            case 'c': max_packets = atoi(optarg); break;
            case 'f': if (optarg) rate_limit_ttl = atoi(optarg); break;
            case 'p': opt_promisc = 1; break;

            /* Vector Flags - Lowercase (With Rate Limit) vs Uppercase (No Rate Limit) */
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
                opt_v6 = 1;
                break;
            case 'A':
                opt_syn = opt_multi = opt_dhcp = opt_netbios = opt_dns = opt_http = opt_tls = opt_l2 = 1;
                opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = opt_dns_rl = opt_http_rl = opt_tls_rl = opt_l2_rl = 0;
                opt_v6 = 1;
                break;

            default: print_help(argv[0]); return 1;
        }
    }

    /* ---- Check for leftover positional arguments ------------------------ */
    if (optind < argc) {
        /* If there's an unattended argument, use it as the interface
         * and automatically enable the -a baseline flag (All vectors limited). */
        iface = argv[optind++];
        opt_syn = opt_multi = opt_dhcp = opt_netbios = opt_dns = opt_http = opt_tls = opt_l2 = 1;
        opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = opt_dns_rl = opt_http_rl = opt_tls_rl = opt_l2_rl = 1;
        opt_v6 = 1;
    }

    /* Reject any further unrecognized extra arguments */
    if (optind < argc) {
        fprintf(stderr, "Error: Unrecognized extra argument '%s'.\n", argv[optind]);
        fprintf(stderr, "Usage: %s [interface] [flags]\n", argv[0]);
        return 1;
    }

    /* -Z only makes sense in Mode 2; Mode 1 (-z) always wins the capture
     * loop below, so warn rather than silently ignoring the user's -Z. */
    if (have_target_mac && have_telemetry_target) {
        fprintf(stderr, "argos-sniffer: warning: -z and -Z both given; -z's live sniffer mode "
                         "takes exclusive control of the capture loop, so -Z will have no effect.\n");
    }

    /* Set default baseline if no specific vectors are chosen (and not in Mode 1). */
    if (!have_target_mac && !opt_syn && !opt_multi && !opt_dhcp && !opt_netbios && !opt_dns && !opt_http && !opt_tls && !opt_l2) {
        opt_syn = opt_multi = opt_dhcp = opt_netbios = 1;
        opt_syn_rl = opt_multi_rl = opt_dhcp_rl = opt_netbios_rl = 1; /* Default to rate-limited */
    }

    install_signal_handlers();

    /* ---- Raw socket setup ---------------------------------------------- */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    if (!have_target_mac) {
        if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog)) < 0) {
            perror("setsockopt(SO_ATTACH_FILTER)");
            close(sock); return 1;
        }
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "ioctl(SIOCGIFINDEX) on '%s': %s\n", iface, strerror(errno));
        close(sock); return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); close(sock); return 1;
    }

    if (opt_promisc) {
        struct packet_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = ifr.ifr_ifindex;
        mr.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
            perror("setsockopt(PACKET_ADD_MEMBERSHIP)");
        }
    }

    int rcvbuf = 524288;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ---- Capture loop ---------------------------------------------------
     * Every iteration reads one raw Ethernet frame and routes it into
     * exactly one of two modes:
     *   Mode 1 (-z): dump matching frames tcpdump-style, then continue.
     *   Mode 2:      run the frame through whichever telemetry vectors
     *                are enabled (-s/-d/-q/...), honoring -r (router
     *                exclusion), -x (mac exclusion), and -Z (single
     *                target filter) along the way.
     * --------------------------------------------------------------- */
    unsigned char buffer[4096];
    while (running) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 14) continue;

        struct ether_header *eth = (struct ether_header *)buffer;

        /* ----------------------------------------------------------------- */
        /* MODE 1: Target Live Sniffer Inspection (-z <mac>)                 */
        /* ----------------------------------------------------------------- */
        if (have_target_mac) {
            if (memcmp(eth->ether_shost, target_mac, 6) != 0 && memcmp(eth->ether_dhost, target_mac, 6) != 0) {
                continue;
            }

            uint16_t eth_type = ntohs(eth->ether_type);
            int l2_len = 14;

            if (eth_type == 0x8100 && len >= 18) {
                eth_type = read_be16(buffer + 16);
                l2_len = 18;
            }

            dump_target_packet(buffer, (int)len, l2_len, eth_type);

            packet_count++;
            if (max_packets > 0 && packet_count >= max_packets) {
                break;
            }
            continue;
        }

        /* ----------------------------------------------------------------- */
        /* MODE 2: Argos Telemetry Daemon Profiler Engine                    */
        /* ----------------------------------------------------------------- */

        /* --- Sub-step: exclude the router itself from its own telemetry --- */
        if (is_router_mac(eth->ether_shost)) continue;

        /* --- Sub-step: exclude explicitly ignored MACs (-x) --- */
        if (is_excluded_mac(eth->ether_shost)) continue;

        /* --- Sub-step: -Z single-device filter (if configured) ---
         * All telemetry below is keyed on eth->ether_shost (the sender),
         * exactly like the router-exclusion check above, so filtering on
         * the same field here keeps the two checks consistent: this
         * restricts "whose traffic gets profiled" the same way -r
         * restricts "whose traffic never gets profiled". */
        if (have_telemetry_target && memcmp(eth->ether_shost, telemetry_target_mac, 6) != 0) {
            continue;
        }

        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                 eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

        uint16_t eth_type = ntohs(eth->ether_type);
        int l2_len = 14;

        if (eth_type == 0x8100) {
            if (len < 18) continue;
            eth_type = read_be16(buffer + 16);
            l2_len = 18;
        }

        /* --- L2 Protocol: LLDP --- */
        if (opt_l2 && eth_type == 0x88cc) {
            parse_lldp(buffer + l2_len, (int)len - l2_len, mac, opt_l2_rl);
            continue;
        }

        char src_ip[INET6_ADDRSTRLEN] = {0};
        uint8_t protocol = 0;
        uint8_t ttl = 0;
        int l4_offset = 0;

        /* --- Network Layer Extraction (IPv4) --- */
        if (eth_type == 0x0800) {
            if (len < l2_len + 20) continue;
            struct iphdr *ip = (struct iphdr *)(buffer + l2_len);
            if (ip->ihl * 4 < 20) continue;

            if (!is_private_ipv4(ip->saddr)) continue;

            struct in_addr s_addr; s_addr.s_addr = ip->saddr;
            inet_ntop(AF_INET, &s_addr, src_ip, sizeof(src_ip));
            protocol = ip->protocol;
            ttl = ip->ttl;
            l4_offset = l2_len + (ip->ihl * 4);
        }
        /* --- Network Layer Extraction (IPv6) --- */
        else if (opt_v6 && eth_type == 0x86dd) {
            if (len < l2_len + 40) continue;
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + l2_len);

            /* IPv6 counterpart of the is_private_ipv4() gate above - see
             * the "Is this address on my LAN?" section comment for the
             * exact ranges accepted and the GUA caveat. */
            if (!is_private_ipv6(&ip6->ip6_src)) continue;

            inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
            protocol = ip6->ip6_nxt;
            ttl = ip6->ip6_hlim;
            l4_offset = l2_len + 40;
        } else {
            continue;
        }

        /* --- Transport Layer Extraction: TCP --- */
        if (protocol == IPPROTO_TCP) {
            if (len < l4_offset + 20) continue;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + l4_offset);
            uint16_t dport = ntohs(tcp->dest);
            int tcp_hl = tcp->doff * 4;
            if (tcp_hl < 20) continue;
            int payload_offset = l4_offset + tcp_hl;
            if (payload_offset > len) continue;
            int payload_len = (int)len - payload_offset;

            /* Connection Setup: TCP SYN (p0f) & SYNACK (Port Scanning) */
            if (opt_syn && tcp->syn) {
                int mss = -1;
                int wscale = -1;
                char opts_str[64] = {0};
                int opt_pos = 0;

                if (tcp_hl > 20) {
                    const unsigned char *opts = (const unsigned char*)tcp + 20;
                    int opt_total = tcp_hl - 20;
                    int op = 0;
                    while (op < opt_total && opt_pos < (int)sizeof(opts_str) - 4) {
                        uint8_t kind = opts[op];
                        if (kind == 0) {
                            if (opt_pos > 0 && opts_str[opt_pos-1] != ',') opts_str[opt_pos++] = ',';
                            opts_str[opt_pos++] = 'E';
                            break;
                        }
                        if (kind == 1) {
                            if (opt_pos > 0 && opts_str[opt_pos-1] != ',') opts_str[opt_pos++] = ',';
                            opts_str[opt_pos++] = 'N';
                            op++;
                            continue;
                        }
                        if (op + 1 >= opt_total) break;
                        uint8_t olen = opts[op+1];
                        if (olen < 2 || op + olen > opt_total) break;

                        if (opt_pos > 0 && opts_str[opt_pos-1] != ',') opts_str[opt_pos++] = ',';

                        if (kind == 2 && olen == 4) {
                            mss = read_be16(opts + op + 2);
                            opts_str[opt_pos++] = 'M';
                            opts_str[opt_pos++] = '*';
                        } else if (kind == 3 && olen == 3) {
                            wscale = opts[op + 2];
                            opts_str[opt_pos++] = 'W';
                            opts_str[opt_pos++] = '*';
                        } else if (kind == 4 && olen == 2) {
                            opts_str[opt_pos++] = 'S';
                        } else if (kind == 8 && olen == 10) {
                            opts_str[opt_pos++] = 'T';
                        } else {
                            opts_str[opt_pos++] = '?';
                        }
                        op += olen;
                    }
                }
                opts_str[opt_pos] = '\0';
                if (opts_str[0] == '\0') strcpy(opts_str, "none");

                if (tcp->ack) {
                    char syn_sig[32];
                    snprintf(syn_sig, sizeof(syn_sig), "%u", ntohs(tcp->source));
                    if (!dedup_should_suppress(mac, "SYNACK", syn_sig, opt_syn_rl)) {
                        printf("SYNACK|%s|%s|%u|%u|%d|%d|%s|%u\n", mac, src_ip, ttl, ntohs(tcp->window), wscale, mss, opts_str, ntohs(tcp->source));
                    }
                } else {
                    char syn_sig[32];
                    snprintf(syn_sig, sizeof(syn_sig), "%u", ntohs(tcp->dest));
                    if (!dedup_should_suppress(mac, "SYN", syn_sig, opt_syn_rl)) {
                        printf("SYN|%s|%s|%u|%u|%d|%d|%s|%u\n", mac, src_ip, ttl, ntohs(tcp->window), wscale, mss, opts_str, ntohs(tcp->dest));
                    }
                }
            }

            /* Application Layer Extraction: HTTP (Cleartext User-Agents) */
            if (opt_http && (dport == 80 || dport == 8080) && payload_len > 16) {
                const unsigned char *p = buffer + payload_offset;
                if ((payload_len >= 4 && memcmp(p, "GET ", 4) == 0) ||
                    (payload_len >= 5 && memcmp(p, "POST ", 5) == 0)) {
                    const unsigned char *ua_hdr = find_bytes_ci(p, (size_t)payload_len, "\r\nUser-Agent: ", 14);
                    if (ua_hdr) {
                        const unsigned char *ua = ua_hdr + 14;
                        size_t ua_avail = (size_t)((p + payload_len) - ua);
                        const unsigned char *end = find_bytes(ua, ua_avail, (const unsigned char *)"\r\n", 2);
                        if (end) {
                            int ualen = (int)(end - ua);
                            if (ualen > 255) ualen = 255;
                            char ua_str[256];
                            sanitize_field(ua, ualen, ua_str, sizeof(ua_str), 0);
                            if (ua_str[0] && !dedup_should_suppress(mac, "HTTP", ua_str, opt_http_rl)) {
                                printf("HTTP|%s|%s|%s\n", mac, src_ip, ua_str);
                            }
                        }
                    }
                }
            }
            /* Application Layer Extraction: TLS (Encrypted Server Name Indication) */
            else if (opt_tls && dport == 443 && payload_len > 44) {
                parse_tls_sni(buffer + payload_offset, payload_len, mac, src_ip, opt_tls_rl);
            }
        }
        /* --- Transport Layer Extraction: UDP --- */
        else if (protocol == IPPROTO_UDP) {
            if (len < l4_offset + 8) continue;
            struct udphdr *udp = (struct udphdr *)(buffer + l4_offset);
            uint16_t dport = ntohs(udp->dest);
            uint16_t sport = ntohs(udp->source);

            int payload_offset = l4_offset + 8;
            int payload_len = (int)len - payload_offset;
            if (payload_len <= 0) continue;
            const unsigned char *payload = buffer + payload_offset;

            /* Dynamic Host Configuration Protocol */
            if (opt_dhcp && (dport == 67 || sport == 67)) {
                parse_dhcp(payload, payload_len, mac, src_ip, opt_dhcp_rl);
            }
            /* NetBIOS Name Service */
            else if (opt_netbios && (dport == 137 || sport == 137)) {
                parse_netbios(payload, payload_len, mac, src_ip, opt_netbios_rl);
            }
            /* L7 Multicast & Discovery (WS-Discovery / SSDP / UPnP) */
            else if (opt_multi && (dport == 1900 || sport == 1900 || dport == 3702 || sport == 3702)) {
                char clean_payload[513];
                int plen = (payload_len > 512) ? 512 : payload_len;
                sanitize_field(payload, plen, clean_payload, sizeof(clean_payload), 1);
                if (clean_payload[0] && !dedup_should_suppress(mac, "L7", clean_payload, opt_multi_rl)) {
                    printf("L7|%s|%s|%d|%s\n", mac, src_ip, (dport == 1900 || dport == 3702) ? dport : sport, clean_payload);
                }
            }
            /* L7 Multicast & Discovery (mDNS) */
            else if (opt_multi && (dport == 5353 || sport == 5353)) {
                parse_mdns(payload, payload_len, mac, src_ip, (dport == 5353) ? dport : sport, opt_multi_rl);
            }
            /* Domain Name System Queries */
            else if (opt_dns && dport == 53) {
                if (payload_len > 12) {
                    char qname[256];
                    if (decode_dns_name(payload, payload_len, 12, qname, sizeof(qname)) > 0) {
                        if (qname[0] && !dedup_should_suppress(mac, "DNS", qname, opt_dns_rl)) {
                            printf("DNS|%s|%s|%s\n", mac, src_ip, qname);
                        }
                    }
                }
            }
        }
    }

    close(sock);
    return 0;
}
