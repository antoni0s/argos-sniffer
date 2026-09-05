#ifndef ARGOS_ENTERPRISE_H
#define ARGOS_ENTERPRISE_H

#include "argos_enterprise_ports.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Argos Sniffer v6 enterprise fingerprint engine.
 *
 * Design rules:
 *  - parse only handshake/discovery/control payloads useful for fingerprinting;
 *  - mark bulk/data flows complete as soon as their application command is known;
 *  - never allocate on the packet hot path;
 *  - bound every string copy and parser walk;
 *  - emit device/product metadata, not credentials or message bodies.
 */

typedef struct {
    char proto[24];
    char detail[512];
    uint8_t emit;
    uint8_t complete;
} argos_enterprise_result_t;

static inline uint16_t ae_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint16_t ae_le16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

static inline uint32_t ae_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t ae_le32(const unsigned char *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static inline const unsigned char *ae_find(const unsigned char *p, int len,
                                           const unsigned char *needle, int nlen) {
    if (!p || !needle || len < nlen || nlen <= 0) return NULL;
    for (int i = 0; i <= len - nlen; ++i) {
        if (p[i] == needle[0] && memcmp(p + i, needle, (size_t)nlen) == 0) return p + i;
    }
    return NULL;
}

static inline const unsigned char *ae_find_ci(const unsigned char *p, int len,
                                              const char *needle) {
    int nlen = (int)strlen(needle);
    if (!p || !needle || len < nlen || nlen <= 0) return NULL;
    for (int i = 0; i <= len - nlen; ++i) {
        int ok = 1;
        for (int j = 0; j < nlen; ++j) {
            if (tolower((unsigned char)p[i + j]) != tolower((unsigned char)needle[j])) {
                ok = 0; break;
            }
        }
        if (ok) return p + i;
    }
    return NULL;
}

static inline void ae_clean(const unsigned char *src, int len, char *dst, size_t cap) {
    size_t o = 0;
    if (!dst || cap == 0U) return;
    if (!src || len <= 0) { dst[0] = '\0'; return; }
    for (int i = 0; i < len && o + 1U < cap; ++i) {
        unsigned char c = src[i];
        if (c >= 32U && c <= 126U) {
            dst[o++] = (c == '|') ? '/' : (char)c;
        } else if (o > 0U && dst[o - 1U] != ' ') {
            dst[o++] = ' ';
        }
    }
    while (o > 0U && dst[o - 1U] == ' ') --o;
    dst[o] = '\0';
}

static inline void ae_set(argos_enterprise_result_t *r, const char *proto,
                          int complete, const char *fmt, ...) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    snprintf(r->proto, sizeof(r->proto), "%s", proto ? proto : "unknown");
    r->complete = (uint8_t)(complete ? 1 : 0);
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->detail, sizeof(r->detail), fmt, ap);
    va_end(ap);
    for (char *q = r->detail; *q; ++q) if (*q == '|') *q = '/';
    r->emit = r->detail[0] ? 1U : 0U;
}

static inline void ae_exporter_token(const unsigned char *p, size_t n,
                                     char *out, size_t cap) {
    size_t o = 0;
    if (!out || cap == 0U) return;
    for (size_t i = 0; p && i < n && o + 1U < cap; ++i) {
        unsigned char c = p[i];
        out[o++] = (c >= 33U && c <= 126U && c != '|') ? (char)c : '_';
    }
    out[o] = '\0';
}

static inline int ae_syslog_token(const unsigned char *p, size_t n,
                                  size_t *pos, size_t *off, size_t *len) {
    size_t start;
    if (!p || !pos || *pos >= n) return 0;
    start = *pos;
    while (*pos < n && p[*pos] != ' ' && p[*pos] != '\r' && p[*pos] != '\n')
        ++*pos;
    if (*pos == start) return 0;
    if (off) *off = start;
    if (len) *len = *pos - start;
    if (*pos < n && p[*pos] == ' ') ++*pos;
    return 1;
}

/* Exporter parsers retain only bounded header identity. They never inspect a
 * Syslog message body, NetFlow records, IPFIX set bodies, or sFlow samples. */
static inline int ae_syslog(const unsigned char *p, int len,
                            argos_enterprise_result_t *r) {
    size_t n, pos = 1U, off = 0U, tok_len = 0U;
    unsigned pri = 0U, digits = 0U;
    char hostname[96] = "-", appname[64] = "-";
    if (!p || !r || len < 3 || len > 4096 || p[0] != '<') return 0;
    n = (size_t)len;
    while (pos < n && p[pos] >= '0' && p[pos] <= '9' && digits < 3U) {
        pri = pri * 10U + (unsigned)(p[pos++] - '0');
        ++digits;
    }
    if (digits == 0U || pos >= n || p[pos++] != '>' || pri > 191U) return 0;

    if (pos < n && p[pos] >= '1' && p[pos] <= '9') {
        unsigned version = 0U;
        size_t version_off = pos, version_len;
        while (pos < n && p[pos] >= '0' && p[pos] <= '9' && pos - version_off < 3U)
            version = version * 10U + (unsigned)(p[pos++] - '0');
        version_len = pos - version_off;
        if (version_len == 0U || version == 0U || pos >= n || p[pos++] != ' ')
            return 0;
        if (!ae_syslog_token(p, n, &pos, NULL, NULL) ||
            !ae_syslog_token(p, n, &pos, &off, &tok_len)) return 0;
        ae_exporter_token(p + off, tok_len, hostname, sizeof(hostname));
        if (!ae_syslog_token(p, n, &pos, &off, &tok_len)) return 0;
        ae_exporter_token(p + off, tok_len, appname, sizeof(appname));
        if (!ae_syslog_token(p, n, &pos, NULL, NULL) ||
            !ae_syslog_token(p, n, &pos, NULL, NULL) || pos >= n) return 0;
        if (p[pos] == '-') {
            ++pos;
            if (pos < n && p[pos] != ' ' && p[pos] != '\r' && p[pos] != '\n') return 0;
            ae_set(r, "syslog", 1,
                   "format=rfc5424 facility=%u severity=%u version=%u hostname=%s appname=%s structured_data=0",
                   pri / 8U, pri % 8U, version, hostname, appname);
            return 1;
        }
        if (p[pos] == '[') {
            int depth = 0, escaped = 0;
            size_t walked = 0U;
            do {
                unsigned char c = p[pos++];
                if (++walked > 512U) return 0;
                if (escaped) escaped = 0;
                else if (c == '\\') escaped = 1;
                else if (c == '[') ++depth;
                else if (c == ']') --depth;
                if (depth < 0) return 0;
            } while (pos < n && (depth > 0 || p[pos] == '['));
            if (depth != 0) return 0;
            ae_set(r, "syslog", 1,
                   "format=rfc5424 facility=%u severity=%u version=%u hostname=%s appname=%s structured_data=1",
                   pri / 8U, pri % 8U, version, hostname, appname);
            return 1;
        }
        return 0;
    }

    /* RFC 3164's timestamp is optional in observed traffic. When present, it
     * has the fixed "Mmm dd hh:mm:ss" shape and is skipped without retention. */
    if (n - pos >= 16U && p[pos + 3U] == ' ' && p[pos + 6U] == ' ' &&
        p[pos + 9U] == ':' && p[pos + 12U] == ':' && p[pos + 15U] == ' ')
        pos += 16U;
    if (ae_syslog_token(p, n, &pos, &off, &tok_len)) {
        ae_exporter_token(p + off, tok_len, hostname, sizeof(hostname));
        if (pos < n) {
            size_t start = pos;
            while (pos < n && p[pos] != ':' && p[pos] != '[' &&
                   p[pos] != ' ' && p[pos] != '\r' && p[pos] != '\n') ++pos;
            if (pos > start) ae_exporter_token(p + start, pos - start, appname, sizeof(appname));
        }
    }
    ae_set(r, "syslog", 1,
           "format=rfc3164 facility=%u severity=%u version=- hostname=%s appname=%s structured_data=0",
           pri / 8U, pri % 8U, hostname, appname);
    return 1;
}

static inline int ae_netflow(const unsigned char *p, int len,
                             argos_enterprise_result_t *r) {
    uint16_t version, count;
    if (!p || !r || len < 4 || len > 4096) return 0;
    version = ae_be16(p); count = ae_be16(p + 2);
    if (version == 9U) {
        if (len < 20) return 0;
        ae_set(r, "netflow", 1,
               "version=9 count=%u sequence=%u engine_type=- engine_id=- source_id=%u uptime=%u",
               count, ae_be32(p + 12), ae_be32(p + 16), ae_be32(p + 4));
        return 1;
    }
    if (version == 5U) {
        if (len < 24) return 0;
        ae_set(r, "netflow", 1,
               "version=5 count=%u sequence=%u engine_type=%u engine_id=%u source_id=- uptime=%u",
               count, ae_be32(p + 16), p[20], p[21], ae_be32(p + 4));
        return 1;
    }
    if (version == 7U) {
        if (len < 24) return 0;
        ae_set(r, "netflow", 1,
               "version=7 count=%u sequence=%u engine_type=- engine_id=- source_id=- uptime=%u",
               count, ae_be32(p + 16), ae_be32(p + 4));
        return 1;
    }
    return 0;
}

static inline int ae_ipfix(const unsigned char *p, int len,
                           argos_enterprise_result_t *r) {
    uint16_t declared;
    size_t pos = 16U;
    unsigned sets = 0U;
    if (!p || !r || len < 16 || len > 4096 || ae_be16(p) != 10U) return 0;
    declared = ae_be16(p + 2);
    if (declared < 16U || declared > (uint16_t)len) return 0;
    while (pos < declared) {
        uint16_t set_len;
        if ((size_t)declared - pos < 4U) return 0;
        set_len = ae_be16(p + pos + 2U);
        if (set_len < 4U || set_len > (size_t)declared - pos) return 0;
        pos += set_len; ++sets;
    }
    ae_set(r, "ipfix", 1,
           "version=10 length=%u sequence=%u observation_domain=%u export_time=%u sets=%u",
           declared, ae_be32(p + 8), ae_be32(p + 12), ae_be32(p + 4), sets);
    return 1;
}

static inline int ae_sflow(const unsigned char *p, int len,
                           argos_enterprise_result_t *r) {
    uint32_t type;
    size_t off;
    char agent[48];
    if (!p || !r || len < 28 || len > 4096 || ae_be32(p) != 5U) return 0;
    type = ae_be32(p + 4);
    if (type == 1U) {
        off = 12U;
        snprintf(agent, sizeof(agent), "%u.%u.%u.%u", p[8], p[9], p[10], p[11]);
    } else if (type == 2U) {
        off = 24U;
        if (len < 40) return 0;
        snprintf(agent, sizeof(agent),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                 p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23]);
    } else return 0;
    if ((size_t)len < off + 16U) return 0;
    ae_set(r, "sflow", 1,
           "version=5 agent_type=%s agent=%s sub_agent=%u sequence=%u samples=%u",
           type == 1U ? "ipv4" : "ipv6", agent, ae_be32(p + off),
           ae_be32(p + off + 4U), ae_be32(p + off + 12U));
    return 1;
}

static inline int argos_enterprise_tcp_port(uint16_t sport, uint16_t dport) {
    for (size_t i = 0; i < ARGOS_ENTERPRISE_TCP_PORT_COUNT; ++i)
        if (sport == ARGOS_ENTERPRISE_TCP_PORTS[i] || dport == ARGOS_ENTERPRISE_TCP_PORTS[i]) return 1;
    return 0;
}

static inline int argos_enterprise_udp_port(uint16_t sport, uint16_t dport) {
    for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i)
        if (sport == ARGOS_ENTERPRISE_UDP_PORTS[i] || dport == ARGOS_ENTERPRISE_UDP_PORTS[i]) return 1;
    return 0;
}

static inline int ae_rpc(const unsigned char *p, int len, int tcp,
                         argos_enterprise_result_t *r) {
    int off = tcp ? 4 : 0;
    if (len < off + 24) return 0;
    if (tcp) {
        uint32_t marker = ae_be32(p);
        uint32_t fraglen = marker & 0x7fffffffU;
        if (fraglen < 24U || fraglen > (uint32_t)(len - 4)) return 0;
    }
    uint32_t msgtype = ae_be32(p + off + 4);
    if (msgtype != 0U) return 0; /* calls are the useful client fingerprint side */
    if (ae_be32(p + off + 8) != 2U) return 0;
    uint32_t prog = ae_be32(p + off + 12);
    uint32_t vers = ae_be32(p + off + 16);
    uint32_t proc = ae_be32(p + off + 20);

    if (prog == 100003U && (proc == 6U || proc == 7U)) {
        ae_set(r, "nfs", 1, NULL);
        return 1;
    }

    uint32_t auth = 0xffffffffU;
    char machine[128] = {0};
    if (len >= off + 32) {
        auth = ae_be32(p + off + 24);
        uint32_t credlen = ae_be32(p + off + 28);
        if (auth == 1U && credlen >= 12U && credlen <= 512U && len >= off + 40) {
            uint32_t mlen = ae_be32(p + off + 36);
            if (mlen > 0U && mlen < sizeof(machine) && off + 40 + (int)mlen <= len)
                ae_clean(p + off + 40, (int)mlen, machine, sizeof(machine));
        }
    }

    if (prog == 100003U) {
        const char *name = proc == 0U ? "NULL" : proc == 1U ? "GETATTR" :
                           proc == 19U ? "FSINFO" : "RPC";
        ae_set(r, "nfs", (proc == 0U || proc == 1U || proc == 19U),
               "program=100003 version=%u proc=%u(%s) auth=%u machine=%s",
               vers, proc, name, auth, machine[0] ? machine : "-");
        return 1;
    }
    if (prog == 100000U) {
        ae_set(r, "sunrpc", 1, "program=portmap version=%u proc=%u auth=%u machine=%s",
               vers, proc, auth, machine[0] ? machine : "-");
        return 1;
    }
    return 0;
}

static inline int ae_iscsi(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 48) return 0;
    uint8_t op = (uint8_t)(p[0] & 0x3fU);
    if (op != 0x03U && op != 0x23U) {
        if (op == 0x01U || op == 0x05U || op == 0x25U) {
            ae_set(r, "iscsi", 1, NULL);
            return 1;
        }
        return 0;
    }
    uint32_t dlen = ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
    int avail = len - 48;
    if ((uint32_t)avail > dlen) avail = (int)dlen;
    char ini[192] = {0}, tgt[192] = {0}, sess[64] = {0};
    int pos = 48;
    while (pos < 48 + avail) {
        int end = pos;
        while (end < 48 + avail && p[end] != 0) ++end;
        int sl = end - pos;
        if (sl > 14 && memcmp(p + pos, "InitiatorName=", 14) == 0)
            ae_clean(p + pos + 14, sl - 14, ini, sizeof(ini));
        else if (sl > 11 && memcmp(p + pos, "TargetName=", 11) == 0)
            ae_clean(p + pos + 11, sl - 11, tgt, sizeof(tgt));
        else if (sl > 12 && memcmp(p + pos, "SessionType=", 12) == 0)
            ae_clean(p + pos + 12, sl - 12, sess, sizeof(sess));
        pos = end + 1;
    }
    ae_set(r, "iscsi", 1, "opcode=0x%02x initiator=%s target=%s session=%s",
           op, ini[0] ? ini : "-", tgt[0] ? tgt : "-", sess[0] ? sess : "-");
    return 1;
}

static inline int ae_tds(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8) return 0;
    uint8_t type = p[0];
    if (type != 0x12U) {
        if (type == 0x01U || type == 0x03U || type == 0x04U) {
            ae_set(r, "mssql", 1, NULL);
            return 1;
        }
        return 0;
    }
    int plen = ae_be16(p + 2);
    if (plen > len) plen = len;
    int pos = 8;
    unsigned major = 0, minor = 0, build = 0, sub = 0;
    while (pos + 5 <= plen && p[pos] != 0xffU) {
        uint8_t tok = p[pos];
        int off = ae_be16(p + pos + 1);
        int olen = ae_be16(p + pos + 3);
        if (tok == 0x00U && olen >= 6 && 8 + off + 6 <= plen) {
            const unsigned char *v = p + 8 + off;
            major = v[0]; minor = v[1]; build = ae_be16(v + 2); sub = ae_be16(v + 4);
            break;
        }
        pos += 5;
    }
    ae_set(r, "mssql", 1, "prelogin version=%u.%u build=%u subbuild=%u",
           major, minor, build, sub);
    return 1;
}

static inline int ae_tns(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8) return 0;
    uint8_t type = p[4];
    if (type != 0x01U) {
        if (type == 0x06U) { ae_set(r, "oracle-tns", 1, NULL); return 1; }
        return 0;
    }
    int n = len > 512 ? 512 : len;
    char text[513]; ae_clean(p, n, text, sizeof(text));
    const char *keys[] = {"PROGRAM=", "HOST=", "SERVICE_NAME=", "CID=", "VERSION="};
    char out[384] = {0}; size_t used = 0;
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); ++k) {
        char *q = strstr(text, keys[k]);
        if (!q) continue;
        char *e = strchr(q, ')');
        size_t l = e ? (size_t)(e - q) : strlen(q);
        if (l > 96U) l = 96U;
        int w = snprintf(out + used, sizeof(out) - used, "%s%.*s",
                         used ? " " : "", (int)l, q);
        if (w < 0 || (size_t)w >= sizeof(out) - used) break;
        used += (size_t)w;
    }
    ae_set(r, "oracle-tns", 1, "connect %s", out[0] ? out : "metadata-unavailable");
    return 1;
}

static inline void ae_utf16le(const unsigned char *p, int len, char *out, size_t cap) {
    size_t o = 0;
    for (int i = 0; i + 1 < len && o + 1U < cap; i += 2) {
        unsigned char c = p[i];
        if (p[i + 1] != 0U || c < 32U || c > 126U) c = '?';
        if (c == '|') c = '/';
        out[o++] = (char)c;
    }
    out[o] = '\0';
}

static inline int ae_smb2(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    static const unsigned char sig[] = {0xfe,'S','M','B'};
    if (len < 64 || memcmp(p, sig, sizeof(sig)) != 0) return 0;
    uint16_t cmd = ae_le16(p + 12); /* SMB2 SYNC header Command */
    if (cmd == 0x0008U || cmd == 0x0009U) {
        ae_set(r, "smb2", 1, NULL);
        return 1;
    }
    if (cmd != 0x0001U) return 0;

    static const unsigned char ntlm[] = {'N','T','L','M','S','S','P',0};
    const unsigned char *n = ae_find(p, len, ntlm, 8);
    if (!n || n + 12 > p + len) {
        /* SESSION_SETUP can span multiple authentication tokens. Keep this
         * flow inspectable until a terminal NTLM Type 3 is observed; the
         * global packet budget still bounds non-NTLM/SPNEGO sessions. */
        ae_set(r, "smb2", 0, "command=session-setup auth=spnego");
        return 1;
    }
    int remain = (int)((p + len) - n);
    uint32_t mt = ae_le32(n + 8);
    unsigned maj = 0, min = 0, build = 0;
    char domain[96] = {0}, workstation[96] = {0};
    if ((mt == 2U && remain >= 56) || (mt == 3U && remain >= 72)) {
        int voff = (mt == 2U) ? 48 : 64;
        if (remain >= voff + 8) {
            maj = n[voff]; min = n[voff + 1]; build = ae_le16(n + voff + 2);
        }
    }
    if (mt == 3U && remain >= 64) {
        uint16_t dlen = ae_le16(n + 28); uint32_t doff = ae_le32(n + 32);
        uint16_t wlen = ae_le16(n + 44); uint32_t woff = ae_le32(n + 48);
        if (doff < (uint32_t)remain && dlen <= (uint16_t)(remain - (int)doff))
            ae_utf16le(n + doff, dlen, domain, sizeof(domain));
        if (woff < (uint32_t)remain && wlen <= (uint16_t)(remain - (int)woff))
            ae_utf16le(n + woff, wlen, workstation, sizeof(workstation));
    }
    unsigned domain_present = domain[0] ? 1U : 0U;
    unsigned workstation_present = workstation[0] ? 1U : 0U;
    unsigned domain_len = domain_present ? (unsigned)strlen(domain) : 0U;
    unsigned workstation_len = workstation_present ? (unsigned)strlen(workstation) : 0U;
    uint32_t domain_hash = 0U, workstation_hash = 0U;
    if (domain_present) {
        domain_hash = 2166136261U;
        for (unsigned i = 0; i < domain_len; ++i) {
            domain_hash ^= (unsigned char)domain[i];
            domain_hash *= 16777619U;
        }
    }
    if (workstation_present) {
        workstation_hash = 2166136261U;
        for (unsigned i = 0; i < workstation_len; ++i) {
            workstation_hash ^= (unsigned char)workstation[i];
            workstation_hash *= 16777619U;
        }
    }
    /* NTLM authentication is multi-message. Type 1/2 must not mark the TCP
     * flow DONE before the client Type 3 identity-bearing message arrives. */
    ae_set(r, "smb2-ntlm", mt == 3U,
           "message=%u windows=%u.%u build=%u domain_present=%u domain_len=%u domain_hash=%08x workstation_present=%u workstation_len=%u workstation_hash=%08x",
           mt, maj, min, build,
           domain_present, domain_len, domain_hash,
           workstation_present, workstation_len, workstation_hash);
    return 1;
}

static inline int ae_bgp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 19) return 0;
    for (int i = 0; i < 16; ++i) if (p[i] != 0xffU) return 0;
    int mlen = ae_be16(p + 16); if (mlen < 19 || mlen > len) return 0;
    uint8_t type = p[18];
    if (type == 2U) { ae_set(r, "bgp", 1, NULL); return 1; }
    if (type != 1U || mlen < 29) return 0;
    uint16_t asn = ae_be16(p + 20), hold = ae_be16(p + 22);
    char rid[32]; snprintf(rid, sizeof(rid), "%u.%u.%u.%u", p[24],p[25],p[26],p[27]);
    char caps[160] = {0}; size_t used = 0;
    int pos = 29, end = 29 + p[28]; if (end > mlen) end = mlen;
    while (pos + 2 <= end) {
        uint8_t ptype = p[pos], plen = p[pos + 1]; pos += 2;
        if (pos + plen > end) break;
        if (ptype == 2U) {
            int q = pos;
            while (q + 2 <= pos + plen) {
                uint8_t c = p[q], cl = p[q + 1];
                int w = snprintf(caps + used, sizeof(caps) - used, "%s%u", used ? "," : "", c);
                if (w < 0 || (size_t)w >= sizeof(caps) - used) break;
                used += (size_t)w; q += 2 + cl;
            }
        }
        pos += plen;
    }
    ae_set(r, "bgp", 1, "open version=%u asn=%u hold=%u router_id=%s caps=%s",
           p[19], asn, hold, rid, caps[0] ? caps : "-");
    return 1;
}

static inline int ae_modbus(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8 || ae_be16(p + 2) != 0U) return 0;
    uint8_t fc = p[7];
    if (fc == 3U || fc == 4U) { ae_set(r, "modbus", 1, NULL); return 1; }
    if (fc != 43U || len < 14 || p[8] != 0x0eU) return 0;
    char vendor[96] = {0}, product[96] = {0}, rev[96] = {0};
    int pos = 14, count = p[13];
    for (int i = 0; i < count && pos + 2 <= len; ++i) {
        uint8_t id = p[pos++], vl = p[pos++]; if (pos + vl > len) break;
        if (id == 0U) ae_clean(p + pos, vl, vendor, sizeof(vendor));
        else if (id == 1U) ae_clean(p + pos, vl, product, sizeof(product));
        else if (id == 2U) ae_clean(p + pos, vl, rev, sizeof(rev));
        pos += vl;
    }
    ae_set(r, "modbus", 1, "device-id vendor=%s product=%s revision=%s",
           vendor[0]?vendor:"-", product[0]?product:"-", rev[0]?rev:"-");
    return 1;
}

static inline int ae_sip(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 12) return 0;
    int interesting = !memcmp(p, "REGISTER ", 9) || !memcmp(p, "INVITE ", 7) || !memcmp(p, "SIP/2.0 ", 8);
    if (!interesting) return 0;
    const unsigned char *u = ae_find_ci(p, len, "\r\nUser-Agent:");
    const char *label = "user-agent";
    int skip = 13;
    if (!u) { u = ae_find_ci(p, len, "\r\nServer:"); label = "server"; skip = 9; }
    if (!u) { ae_set(r, "sip", 1, "signaling"); return 1; }
    u += skip; while (u < p + len && (*u == ' ' || *u == '\t')) ++u;
    const unsigned char *e = ae_find(u, (int)((p + len) - u), (const unsigned char *)"\r\n", 2);
    int n = e ? (int)(e - u) : (int)((p + len) - u); if (n > 220) n = 220;
    char value[224]; ae_clean(u, n, value, sizeof(value));
    ae_set(r, "sip", 1, "%s=%s", label, value[0] ? value : "-");
    return 1;
}

static inline int ae_pjl(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    int n = len > 256 ? 256 : len;
    const unsigned char *q = ae_find_ci(p, n, "@PJL INFO ID");
    if (!q) q = ae_find_ci(p, n, "@PJL COMMENT");
    if (!q) return 0;
    const unsigned char *e = ae_find(q, (int)((p + n) - q), (const unsigned char *)"\r\n", 2);
    int l = e ? (int)(e - q) : (int)((p + n) - q); if (l > 220) l = 220;
    char text[224]; ae_clean(q, l, text, sizeof(text));
    ae_set(r, "pjl", 1, "%s", text);
    return 1;
}

/* RFC 1179 daemon command only. The caller stops this direction after its
 * first payload, successful or not: receive-job subcommands and file bodies
 * must never be revisited as independent commands. No stream reassembly. */
static inline int ae_lpd_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\v' || c == '\f';
}

static inline int ae_lpd(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (!r) return 0;
    memset(r, 0, sizeof(*r));
    if (!p || len < 3 || p[0] < 1U || p[0] > 5U) return 0;
    int end = 1, cap = len < 1024 ? len : 1024;
    while (end < cap && p[end] != '\n') {
        if ((p[end] < 33U || p[end] > 126U) && !ae_lpd_space(p[end])) return 0;
        ++end;
    }
    if (end == cap) return 0;
    int qend = 1;
    while (qend < end && !ae_lpd_space(p[qend])) ++qend;
    if (qend == 1 || qend - 1 > 95) return 0;
    int pos = qend;
    while (pos < end && ae_lpd_space(p[pos])) ++pos;
    if (p[0] <= 2U && pos != end) return 0;
    int user = pos, uend = pos;
    if (p[0] == 5U) {
        while (uend < end && !ae_lpd_space(p[uend])) ++uend;
        if (uend == user || uend - user > 63 ||
            (p[user] >= '0' && p[user] <= '9')) return 0;
    }
    char queue[96], username[64] = "-";
    for (int i = 1; i < qend; ++i)
        queue[i - 1] = strchr("|;=\\", p[i]) ? '_' : (char)p[i];
    queue[qend - 1] = '\0';
    if (p[0] == 5U) {
        for (int i = user; i < uend; ++i)
            username[i - user] = strchr("|;=\\", p[i]) ? '_' : (char)p[i];
        username[uend - user] = '\0';
    }
    const char *command = p[0] == 1U ? "restart" : p[0] == 2U ? "receive-job" :
        p[0] == 3U ? "short-queue" : p[0] == 4U ? "long-queue" : "remove-jobs";
    ae_set(r, "lpd", 1, "command=%s queue=%s username=%s", command, queue, username);
    return 1;
}

static inline int ae_ipp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    const unsigned char *name = ae_find(p, len, (const unsigned char *)"printer-make-and-model", 22);
    if (name) {
        const unsigned char *v = name + 22;
        if (v + 2 <= p + len) {
            uint16_t vl = ae_be16(v); v += 2;
            if (vl > 0U && vl < 240U && v + vl <= p + len) {
                char model[244]; ae_clean(v, vl, model, sizeof(model));
                ae_set(r, "ipp", 1, "printer-make-and-model=%s", model);
                return 1;
            }
        }
    }
    if (ae_find_ci(p, len, "application/ipp") || ae_find_ci(p, len, "/ipp/") || ae_find_ci(p, len, "/printers/")) {
        ae_set(r, "ipp", 0, "ipp-session");
        return 1;
    }
    return 0;
}

static inline int ae_ssh(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8 || memcmp(p, "SSH-", 4) != 0) return 0;
    const unsigned char *e = ae_find(p, len, (const unsigned char *)"\r\n", 2);
    int n = e ? (int)(e - p) : len; if (n > 240) n = 240;
    char banner[244]; ae_clean(p, n, banner, sizeof(banner));
    ae_set(r, "ssh", 1, "banner=%s", banner);
    return 1;
}

static inline int ae_mysql(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8) return 0;
    uint32_t plen = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
    if (plen + 4U > (uint32_t)len || p[3] != 0U || p[4] != 0x0aU) return 0;
    int e = 5; while (e < len && p[e] != 0) ++e;
    if (e <= 5 || e >= len) return 0;
    char ver[160]; ae_clean(p + 5, e - 5, ver, sizeof(ver));
    ae_set(r, "mysql", 1, "server-version=%s", ver);
    return 1;
}

static inline int ae_postgres(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8) return 0;
    uint32_t plen = ae_be32(p);
    if (plen > (uint32_t)len || plen < 8U) return 0;
    uint32_t ver = ae_be32(p + 4);
    if (ver != 196608U) return 0; /* startup protocol 3.0 */
    char app[128] = {0}, db[128] = {0};
    int pos = 8;
    while (pos < (int)plen && p[pos] != 0) {
        int k0 = pos; while (pos < (int)plen && p[pos] != 0) ++pos; if (pos >= (int)plen) break;
        int kl = pos - k0; ++pos;
        int v0 = pos; while (pos < (int)plen && p[pos] != 0) ++pos; if (pos > (int)plen) break;
        int vl = pos - v0; ++pos;
        if (kl == 16 && memcmp(p + k0, "application_name", 16) == 0) ae_clean(p + v0, vl, app, sizeof(app));
        else if (kl == 8 && memcmp(p + k0, "database", 8) == 0) ae_clean(p + v0, vl, db, sizeof(db));
    }
    ae_set(r, "postgresql", 1, "protocol=3.0 application=%s database=%s",
           app[0]?app:"-", db[0]?db:"-");
    return 1;
}

static inline int ae_mqtt_varint(const unsigned char *p, int len, int *pos, uint32_t *out) {
    if (!p || !pos || !out || *pos < 0 || *pos >= len) return 0;
    uint32_t value = 0U, mult = 1U;
    for (unsigned i = 0; i < 4U; ++i) {
        if (*pos >= len) return 0;
        uint8_t b = p[(*pos)++];
        value += (uint32_t)(b & 0x7fU) * mult;
        if ((b & 0x80U) == 0U) { *out = value; return 1; }
        mult *= 128U;
    }
    return 0;
}

static inline int ae_mqtt_utf8_span(const unsigned char *p, int end, int *pos,
                                    const unsigned char **s, uint16_t *n) {
    if (!p || !pos || !s || !n || *pos < 0 || *pos + 2 > end) return 0;
    uint16_t l = ae_be16(p + *pos); *pos += 2;
    if (*pos + (int)l > end) return 0;
    *s = p + *pos; *n = l; *pos += (int)l;
    return 1;
}

/* MQTT CONNECT-only fingerprinting. The client identifier can be a stable
 * device/application identifier, so Argos emits only its length and FNV-1a
 * hash. Username, password and Will topic/payload are represented only by
 * presence/flags and are never copied into telemetry. A successful CONNECT
 * parse is marked complete so the existing app-flow DONE path suppresses all
 * later PUBLISH/SUBSCRIBE traffic for that TCP flow. */
static inline int ae_mqtt(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (!p || !r || len < 10 || p[0] != 0x10U) return 0; /* CONNECT, flags=0 */
    int pos = 1; uint32_t rem = 0U;
    if (!ae_mqtt_varint(p, len, &pos, &rem) || rem > (uint32_t)(len - pos)) return 0;
    int end = pos + (int)rem;

    const unsigned char *proto = NULL; uint16_t proto_len = 0U;
    if (!ae_mqtt_utf8_span(p, end, &pos, &proto, &proto_len)) return 0;
    if (!((proto_len == 4U && memcmp(proto,"MQTT",4U)==0) ||
          (proto_len == 6U && memcmp(proto,"MQIsdp",6U)==0))) return 0;
    if (pos + 4 > end) return 0;
    uint8_t level=p[pos++], flags=p[pos++]; uint16_t keepalive=ae_be16(p+pos); pos+=2;
    if (!((proto_len==4U && (level==4U || level==5U)) || (proto_len==6U && level==3U))) return 0;
    if ((flags & 0x01U) != 0U) return 0;
    unsigned clean=(flags & 0x02U)?1U:0U, will=(flags & 0x04U)?1U:0U;
    unsigned will_qos=(flags >> 3) & 0x03U, will_retain=(flags & 0x20U)?1U:0U;
    unsigned password=(flags & 0x40U)?1U:0U, username=(flags & 0x80U)?1U:0U;
    if (will_qos == 3U || (!will && (will_qos || will_retain))) return 0;

    uint32_t property_len=0U;
    if (level == 5U) {
        if (!ae_mqtt_varint(p,end,&pos,&property_len) || property_len > (uint32_t)(end-pos)) return 0;
        pos += (int)property_len;
    }

    const unsigned char *cid=NULL; uint16_t cid_len=0U;
    if (!ae_mqtt_utf8_span(p,end,&pos,&cid,&cid_len)) return 0;
    uint32_t cid_hash=2166136261U;
    for (uint16_t i=0U; i<cid_len; ++i) { cid_hash ^= cid[i]; cid_hash *= 16777619U; }

    /* Remaining CONNECT payload may contain Will, username and password. We
     * deliberately do not walk/copy those private fields; flags are enough for
     * fingerprinting and the fixed-header Remaining Length already bounded it. */
    const char *version = level==5U ? "5.0" : level==4U ? "3.1.1" : "3.1";
    ae_set(r,"mqtt",1,
           "connect version=%s clean=%u keepalive=%u will=%u will_qos=%u will_retain=%u username_present=%u password_present=%u properties_len=%u client_id_len=%u client_id_hash=%08x",
           version,clean,(unsigned)keepalive,will,will_qos,will_retain,username,password,
           (unsigned)property_len,(unsigned)cid_len,(unsigned)cid_hash);
    return 1;
}

static inline int ae_rdp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 11 || p[0] != 0x03U || p[1] != 0x00U) return 0; /* TPKT */
    if (p[5] != 0xe0U && p[5] != 0xd0U) return 0;             /* X.224 CR/CC */

    /* mstshash is often derived from a login/user identifier. Enterprise mode
     * must never expose it verbatim. Keep only bounded presence/length/hash
     * metadata; explicit identity extraction is handled by a separate opt-in
     * vector rather than weakening the default ENT privacy contract. */
    unsigned cookie_present = 0U, cookie_len = 0U;
    uint32_t cookie_hash = 0U;
    const unsigned char *c = ae_find_ci(p, len, "Cookie: mstshash=");
    if (c) {
        c += 17; /* strlen("Cookie: mstshash=") */
        const unsigned char *e = ae_find(c, (int)((p + len) - c),
                                         (const unsigned char *)"\r\n", 2);
        if (e && e > c) {
            size_t n = (size_t)(e - c);
            if (n > 120U) n = 120U;
            cookie_present = 1U;
            cookie_len = (unsigned)n;
            cookie_hash = 2166136261U;
            for (size_t i = 0; i < n; ++i) {
                cookie_hash ^= c[i];
                cookie_hash *= 16777619U;
            }
        }
    }
    ae_set(r, "rdp", 1,
           "x224=%s cookie_present=%u cookie_len=%u cookie_hash=%08x",
           p[5] == 0xe0U ? "connection-request" : "connection-confirm",
           cookie_present, cookie_len, cookie_hash);
    return 1;
}


static inline int ae_sccp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 12) return 0;
    uint32_t data_len = ae_le32(p);
    uint32_t msgid = ae_le32(p + 8);
    if (msgid != 0x00000001U) return 0; /* RegisterMessage only */
    if (len < 48) return 0;
    char device[32];
    ae_clean(p + 12, 16, device, sizeof(device));
    uint32_t device_type = ae_le32(p + 40);
    uint32_t max_streams = ae_le32(p + 44);
    ae_set(r, "sccp", 1, "register device=%s device_type=%u max_streams=%u data_len=%u",
           device[0] ? device : "-", device_type, max_streams, data_len);
    return 1;
}

/* Defined below with the UDP identity parsers; forward declaration lets TCP/88
 * reuse the exact same bounded Kerberos request parser. */
static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r);
static inline int ae_cip(const unsigned char *p, int len, argos_enterprise_result_t *r);

static inline int argos_enterprise_parse_tcp(uint16_t sport, uint16_t dport,
                                             const unsigned char *p, int len,
                                             argos_enterprise_result_t *r) {
    if (!p || len <= 0 || !r) return 0;
    memset(r, 0, sizeof(*r));
    uint16_t port = dport;
    if (!argos_enterprise_tcp_port(sport, dport)) return 0;
    if (!argos_enterprise_tcp_port(0, port)) port = sport;

    switch (port) {
        case 22: return ae_ssh(p, len, r);
        case 88: return ae_kerberos(p, len, r);
        case 111: case 2049: return ae_rpc(p, len, 1, r);
        case 179: return ae_bgp(p, len, r);
        case 445: return ae_smb2(p, len, r);
        case 502: return ae_modbus(p, len, r);
        case 514: return ae_syslog(p, len, r);
        case 515: return dport == 515U ? ae_lpd(p, len, r) : 0;
        case 631: return ae_ipp(p, len, r);
        case 1433: return ae_tds(p, len, r);
        case 1521: return ae_tns(p, len, r);
        case 1883: return ae_mqtt(p, len, r);
        case 2000: return ae_sccp(p, len, r);
        case 3260: return ae_iscsi(p, len, r);
        case 3306: return ae_mysql(p, len, r);
        case 3389: return ae_rdp(p, len, r);
        case 4739: return ae_ipfix(p, len, r);
        case 5060: return ae_sip(p, len, r);
        case 5432: return ae_postgres(p, len, r);
        case 9100: return ae_pjl(p, len, r);
        case 44818: return ae_cip(p, len, r);
        default: return 0;
    }
}

static inline int ae_der_tlv(const unsigned char *p, size_t n, size_t pos,
                             uint8_t *tag, size_t *voff, size_t *vlen, size_t *next) {
    if (!p || pos >= n || !tag || !voff || !vlen || !next) return 0;
    uint8_t t = p[pos++];
    if ((t & 0x1fU) == 0x1fU || pos >= n) return 0; /* high-tag form not needed here */
    uint8_t lb = p[pos++];
    size_t l = 0;
    if ((lb & 0x80U) == 0U) {
        l = lb;
    } else {
        unsigned octets = lb & 0x7fU;
        if (octets == 0U || octets > 4U || pos + octets > n) return 0;
        for (unsigned i = 0; i < octets; ++i) l = (l << 8) | p[pos++];
    }
    if (l > n - pos) return 0;
    *tag = t; *voff = pos; *vlen = l; *next = pos + l;
    return 1;
}

static inline int ae_der_int32(const unsigned char *p, size_t n, int32_t *out) {
    if (!p || !out || n == 0U || n > 4U) return 0;
    int32_t v = (p[0] & 0x80U) ? -1 : 0;
    for (size_t i = 0; i < n; ++i) v = (int32_t)((uint32_t)v << 8 | p[i]);
    *out = v;
    return 1;
}

static inline uint32_t ae_hash_bytes32(const unsigned char *p, size_t n) {
    uint32_t h = 2166136261U;
    if (!p) return 0U;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 16777619U; }
    return h;
}

/* SNMPv3/USM fingerprinting. RFC 3414 wraps UsmSecurityParameters as the
 * msgSecurityParameters OCTET STRING. The authoritative EngineID is a stable
 * device/engine identifier, so Argos emits only a hash plus RFC 3411
 * enterprise/format metadata -- never the raw EngineID, userName, auth or
 * privacy parameter bytes. */
static inline int ae_snmp_v3_usm(const unsigned char *p, size_t n,
                                 argos_enterprise_result_t *r) {
    uint8_t tag; size_t voff, vlen, next;
    if (!p || !r || !ae_der_tlv(p, n, 0U, &tag, &voff, &vlen, &next) || tag != 0x30U) return 0;
    size_t end = voff + vlen, pos = voff;

    uint8_t vt; size_t vv, vl, vn;
    if (!ae_der_tlv(p,end,pos,&vt,&vv,&vl,&vn) || vt != 0x02U) return 0;
    int32_t version = -1; if (!ae_der_int32(p+vv,vl,&version) || version != 3) return 0; pos=vn;

    uint8_t ht; size_t hv, hl, hn;
    if (!ae_der_tlv(p,end,pos,&ht,&hv,&hl,&hn) || ht != 0x30U) return 0;
    size_t hend=hv+hl, hp=hv; int32_t tmp=0, security_model=0; uint8_t flags=0;
    for (unsigned field=0; field<4U; ++field) {
        uint8_t ft; size_t fv, fl, fn;
        if (!ae_der_tlv(p,hend,hp,&ft,&fv,&fl,&fn)) return 0;
        if (field < 2U) { if (ft != 0x02U || !ae_der_int32(p+fv,fl,&tmp)) return 0; }
        else if (field == 2U) { if (ft != 0x04U || fl != 1U) return 0; flags=p[fv]; }
        else { if (ft != 0x02U || !ae_der_int32(p+fv,fl,&security_model)) return 0; }
        hp=fn;
    }
    if (security_model != 3) return 0;
    pos=hn;

    uint8_t st; size_t sv, sl, sn;
    if (!ae_der_tlv(p,end,pos,&st,&sv,&sl,&sn) || st != 0x04U || sl < 2U) return 0;
    (void)sn;
    uint8_t ut; size_t uv, ul, un;
    if (!ae_der_tlv(p+sv,sl,0U,&ut,&uv,&ul,&un) || ut != 0x30U) return 0;
    size_t uend=uv+ul, up=uv;

    uint8_t et; size_t ev, el, en;
    if (!ae_der_tlv(p+sv,uend,up,&et,&ev,&el,&en) || et != 0x04U || el > 32U) return 0;
    const unsigned char *engine=p+sv+ev; size_t engine_len=el; up=en;
    if (engine_len == 0U) return 0; /* discovery request has no remote identity yet */

    int32_t boots=0, etime=0; unsigned user_present=0U;
    for (unsigned field=0; field<5U; ++field) {
        uint8_t ft; size_t fv, fl, fn;
        if (!ae_der_tlv(p+sv,uend,up,&ft,&fv,&fl,&fn)) return 0;
        if (field == 0U || field == 1U) {
            if (ft != 0x02U || !ae_der_int32(p+sv+fv,fl, field==0U ? &boots : &etime)) return 0;
        } else {
            if (ft != 0x04U) return 0;
            if (field == 2U) user_present = fl ? 1U : 0U;
        }
        up=fn;
    }

    uint32_t enterprise=0U; unsigned format=0U, modern=0U;
    if (engine_len >= 4U) {
        modern=(engine[0] & 0x80U) ? 1U : 0U;
        enterprise=((uint32_t)(engine[0] & 0x7fU)<<24)|((uint32_t)engine[1]<<16)|((uint32_t)engine[2]<<8)|engine[3];
        if (modern && engine_len >= 5U) format=engine[4];
    }
    ae_set(r,"snmpv3-usm",0,
           "engine_hash=%08x engine_len=%u enterprise=%u format=%u modern=%u boots=%d time=%d auth=%u priv=%u reportable=%u user_present=%u",
           (unsigned)ae_hash_bytes32(engine,engine_len),(unsigned)engine_len,(unsigned)enterprise,
           format,modern,boots,etime,(flags&0x01U)?1U:0U,(flags&0x02U)?1U:0U,
           (flags&0x04U)?1U:0U,user_present);
    return 1;
}

static inline int ae_snmp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (p && len > 0 && ae_snmp_v3_usm(p,(size_t)len,r)) return 1;
    static const unsigned char sysdescr[] = {0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00};
    static const unsigned char sysobj[]   = {0x2b,0x06,0x01,0x02,0x01,0x01,0x02,0x00};
    const unsigned char *q = ae_find(p, len, sysdescr, (int)sizeof(sysdescr));
    const char *label = "sysDescr";
    if (!q) { q = ae_find(p, len, sysobj, (int)sizeof(sysobj)); label = "sysObjectID"; }
    if (!q) return 0;
    q += 8;
    int remain = (int)((p + len) - q);
    if (remain < 2) return 0;
    uint8_t vtag = q[0], qlen = q[1];
    if ((qlen & 0x80U) || 2 + qlen > remain) { ae_set(r,"snmp",0,"%s-present",label); return 1; }
    char value[256];
    if (vtag == 0x04U) ae_clean(q+2,qlen,value,sizeof(value));
    else {
        size_t used=0; value[0]='\0';
        for (int i=0;i<qlen && used+3U<sizeof(value);++i) {
            int w=snprintf(value+used,sizeof(value)-used,"%s%02x",i?":":"",q[2+i]);
            if (w<0 || (size_t)w>=sizeof(value)-used) break;
            used+=(size_t)w;
        }
    }
    ae_set(r,"snmp",0,"%s=%s",label,value[0]?value:"-");
    return 1;
}

/* RFC 4120: KDC-REQ req-body is context [4]; inside KDC-REQ-BODY, etype is
 * context [8] containing SEQUENCE OF Int32 in client preference order. Walk
 * only those containers so integers in PA-DATA/principal fields cannot be
 * mistaken for encryption types. */
static inline int ae_kerberos_etypes(const unsigned char *p, size_t n, size_t off,
                                     char *out, size_t cap, unsigned *count) {
    if (!p || !out || cap == 0U || !count || off >= n) return 0;
    out[0] = '\0'; *count = 0U;
    uint8_t tag; size_t voff, vlen, next;
    if (!ae_der_tlv(p, n, off, &tag, &voff, &vlen, &next) ||
        (tag != 0x6aU && tag != 0x6cU)) return 0;
    (void)next;

    uint8_t stag; size_t svoff, svlen, snext;
    if (!ae_der_tlv(p, voff + vlen, voff, &stag, &svoff, &svlen, &snext) || stag != 0x30U) return 0;
    size_t seq_end = svoff + svlen, body_voff = 0U, body_vlen = 0U;
    for (size_t pos = svoff; pos < seq_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!ae_der_tlv(p, seq_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa4U) { body_voff = cv; body_vlen = cl; break; }
        pos = cn;
    }
    if (!body_vlen) return 0;

    uint8_t btag; size_t bvoff, bvlen, bnext;
    if (!ae_der_tlv(p, body_voff + body_vlen, body_voff, &btag, &bvoff, &bvlen, &bnext) || btag != 0x30U) return 0;
    (void)bnext;
    size_t body_end = bvoff + bvlen, et_voff = 0U, et_vlen = 0U;
    for (size_t pos = bvoff; pos < body_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!ae_der_tlv(p, body_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa8U) { et_voff = cv; et_vlen = cl; break; }
        pos = cn;
    }
    if (!et_vlen) return 0;

    uint8_t qtag; size_t qvoff, qvlen, qnext;
    if (!ae_der_tlv(p, et_voff + et_vlen, et_voff, &qtag, &qvoff, &qvlen, &qnext) || qtag != 0x30U) return 0;
    (void)qnext;
    size_t qend = qvoff + qvlen, used = 0U;
    for (size_t pos = qvoff; pos < qend && *count < 16U; ) {
        uint8_t itag; size_t ivoff, ivlen, inext;
        if (!ae_der_tlv(p, qend, pos, &itag, &ivoff, &ivlen, &inext) || itag != 0x02U) return 0;
        int32_t etype;
        if (!ae_der_int32(p + ivoff, ivlen, &etype)) return 0;
        int w = snprintf(out + used, cap - used, "%s%d", *count ? "," : "", etype);
        if (w < 0 || (size_t)w >= cap - used) return 0;
        used += (size_t)w; (*count)++; pos = inext;
    }
    return *count > 0U;
}

static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8) return 0;
    int off = 0;
    if (len >= 12 && p[0] == 0 && p[1] == 0) { /* TCP 4-byte record length */
        uint32_t n = ae_be32(p); if (n + 4U > (uint32_t)len) return 0; off = 4;
    }
    uint8_t tag = p[off];
    const char *kind = tag == 0x6aU ? "AS-REQ" : tag == 0x6cU ? "TGS-REQ" : NULL;
    if (!kind) return 0;
    char realm[128] = {0};
    /* Realm is carried as a KerberosString. Prefer an uppercase dotted token,
     * but do not emit principal/user names. */
    for (int i = off; i + 4 < len && !realm[0]; ++i) {
        if (p[i] < 'A' || p[i] > 'Z') continue;
        int j = i;
        while (j < len && j - i < 120 &&
               ((p[j] >= 'A' && p[j] <= 'Z') || (p[j] >= '0' && p[j] <= '9') || p[j] == '.' || p[j] == '-' || p[j] == '_')) ++j;
        if (j - i >= 3) ae_clean(p + i, j - i, realm, sizeof(realm));
    }
    char etypes[160] = {0}; unsigned etype_count = 0U;
    (void)ae_kerberos_etypes(p, (size_t)len, (size_t)off, etypes, sizeof(etypes), &etype_count);
    ae_set(r, "kerberos", 0, "request=%s realm=%s etype_count=%u etypes=%s",
           kind, realm[0] ? realm : "-", etype_count, etypes[0] ? etypes : "-");
    return 1;
}

static inline int ae_ascii_equal_ci(const unsigned char *p, size_t n, const char *s) {
    if (!p || !s || strlen(s) != n) return 0;
    for (size_t i = 0; i < n; ++i)
        if (tolower(p[i]) != tolower((unsigned char)s[i])) return 0;
    return 1;
}

/* Locate the netlogon attribute value in an LDAP SearchResultEntry. This is a
 * bounded BER walk through LDAPMessage -> SearchResultEntry [APPLICATION 4]
 * -> PartialAttribute(type="netlogon", vals SET OF OCTET STRING). */
static inline int ae_cldap_netlogon_value(const unsigned char *p, size_t n,
                                          const unsigned char **value, size_t *value_len) {
    if (!p || !value || !value_len || n < 8U) return 0;
    uint8_t tag; size_t voff, vlen, next;
    if (!ae_der_tlv(p, n, 0U, &tag, &voff, &vlen, &next) || tag != 0x30U) return 0;
    size_t outer_end = voff + vlen;
    for (size_t pos = voff; pos < outer_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!ae_der_tlv(p, outer_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0x64U) { /* SearchResultEntry, IMPLICIT SEQUENCE */
            size_t app_end = cv + cl, apos = cv;
            uint8_t ot; size_t ov, ol, on;
            if (!ae_der_tlv(p, app_end, apos, &ot, &ov, &ol, &on) || ot != 0x04U) return 0;
            apos = on;
            uint8_t at; size_t av, al, an;
            if (!ae_der_tlv(p, app_end, apos, &at, &av, &al, &an) || at != 0x30U) return 0;
            size_t attrs_end = av + al;
            for (size_t q = av; q < attrs_end; ) {
                uint8_t pt; size_t pv, pl, pn;
                if (!ae_der_tlv(p, attrs_end, q, &pt, &pv, &pl, &pn) || pt != 0x30U) return 0;
                size_t pa_end = pv + pl, z = pv;
                uint8_t tt; size_t tv, tl, tn;
                if (!ae_der_tlv(p, pa_end, z, &tt, &tv, &tl, &tn) || tt != 0x04U) return 0;
                z = tn;
                uint8_t st; size_t sv, sl, sn;
                if (!ae_der_tlv(p, pa_end, z, &st, &sv, &sl, &sn) || st != 0x31U) return 0;
                if (ae_ascii_equal_ci(p + tv, tl, "netlogon")) {
                    uint8_t vt; size_t vv, vl, vn;
                    if (!ae_der_tlv(p, sv + sl, sv, &vt, &vv, &vl, &vn) || vt != 0x04U) return 0;
                    (void)vn;
                    *value = p + vv; *value_len = vl; return 1;
                }
                q = pn;
            }
            return 0;
        }
        pos = cn;
    }
    (void)next;
    return 0;
}

/* Decode one RFC1035-compressed name from a Netlogon blob. `next` advances
 * over the encoded field while compression pointers are followed only for
 * decoding, with hard limits against loops and malformed offsets. */
static inline int ae_netlogon_dns_name(const unsigned char *p, size_t n, size_t start,
                                       char *out, size_t cap, size_t *next) {
    if (!p || !out || cap == 0U || !next || start >= n) return 0;
    size_t pos = start, o = 0U; unsigned jumps = 0U, labels = 0U; int jumped = 0;
    out[0] = '\0';
    while (pos < n && labels++ < 64U) {
        uint8_t b = p[pos];
        if (b == 0U) {
            if (!jumped) *next = pos + 1U;
            out[o] = '\0'; return 1;
        }
        if ((b & 0xc0U) == 0xc0U) {
            if (pos + 1U >= n || jumps++ >= 16U) return 0;
            size_t ptr = ((size_t)(b & 0x3fU) << 8) | p[pos + 1U];
            if (ptr >= n) return 0;
            if (!jumped) { *next = pos + 2U; jumped = 1; }
            pos = ptr; continue;
        }
        if ((b & 0xc0U) != 0U || b > 63U || pos + 1U + b > n) return 0;
        if (o && o + 1U < cap) out[o++] = '.';
        if (o + b >= cap) return 0;
        for (unsigned i = 0; i < b; ++i) {
            unsigned char c = p[pos + 1U + i];
            out[o++] = (c >= 32U && c <= 126U) ? (char)c : '?';
        }
        pos += 1U + b;
    }
    return 0;
}

static inline uint32_t ae_hash_ci32(const char *s) {
    uint32_t h = 2166136261U;
    if (!s) return 0U;
    for (; *s; ++s) { h ^= (uint8_t)tolower((unsigned char)*s); h *= 16777619U; }
    return h;
}

/* NETLOGON_SAM_LOGON_RESPONSE_EX (opcodes 23/24/25). Site/domain/DC names are
 * useful topology fingerprints but can reveal internal naming, so Argos emits
 * stable case-insensitive hashes instead of the raw strings. Flags and
 * NtVersion describe DC capabilities/protocol generation, not an exact OS. */
static inline int ae_cldap_netlogon_ex(const unsigned char *p, size_t n,
                                       argos_enterprise_result_t *r) {
    if (!p || !r || n < 32U) return 0;
    uint16_t opcode = ae_le16(p), sbz = ae_le16(p + 2U);
    if ((opcode < 23U || opcode > 25U) || sbz != 0U) return 0;
    if (ae_le16(p + n - 4U) != 0xffffU || ae_le16(p + n - 2U) != 0xffffU) return 0;
    uint32_t flags = ae_le32(p + 4U), ntver = ae_le32(p + n - 8U);

    char names[8][192]; size_t pos = 24U;
    for (unsigned i = 0; i < 8U; ++i) {
        size_t nx = 0U;
        if (!ae_netlogon_dns_name(p, n - 8U, pos, names[i], sizeof(names[i]), &nx)) return 0;
        pos = nx;
    }
    if (pos > n - 8U) return 0;
    const char *relation = (!names[6][0] || !names[7][0]) ? "unknown" :
                           (ae_hash_ci32(names[6]) == ae_hash_ci32(names[7]) ? "same" : "different");
    ae_set(r, "cldap-netlogon", 0,
           "response_ex opcode=%u flags=0x%08x ntver=0x%08x forest_hash=%08x domain_hash=%08x dc_hash=%08x dc_site_hash=%08x client_site_hash=%08x site_relation=%s",
           (unsigned)opcode, (unsigned)flags, (unsigned)ntver,
           (unsigned)ae_hash_ci32(names[0]), (unsigned)ae_hash_ci32(names[1]),
           (unsigned)ae_hash_ci32(names[2]), (unsigned)ae_hash_ci32(names[6]),
           (unsigned)ae_hash_ci32(names[7]), relation);
    return 1;
}

static inline int ae_cldap(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    const unsigned char *nv = NULL; size_t nvlen = 0U;
    if (p && len > 0 && ae_cldap_netlogon_value(p, (size_t)len, &nv, &nvlen) &&
        ae_cldap_netlogon_ex(nv, nvlen, r)) return 1;

    const unsigned char *d = ae_find_ci(p, len, "DnsDomain");
    const unsigned char *n = ae_find_ci(p, len, "NtVer");
    if (!d && !n) return 0;
    ae_set(r, "cldap-netlogon", 0, "locator-query dns-domain=%s ntver=%s",
           d ? "present" : "-", n ? "present" : "-");
    return 1;
}

static inline int ae_ipmi(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 4 || p[0] != 0x06U) return 0;
    uint8_t cls = (uint8_t)(p[3] & 0x1fU);
    if (cls == 0x06U && len >= 12) {
        uint32_t iana = ae_be32(p + 4); uint8_t mt = p[8];
        ae_set(r, "rmcp-asf", 0, "class=ASF iana=%u message=0x%02x", iana, mt);
        return 1;
    }
    if (cls == 0x07U) {
        ae_set(r, "ipmi-rmcp", 0, "class=IPMI rmcp-seq=%u", p[2]);
        return 1;
    }
    return 0;
}

static inline int ae_slp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    const unsigned char *v = ae_find_ci(p, len, "service:vmware");
    if (!v) v = ae_find_ci(p, len, "service:wbem");
    if (!v) v = ae_find_ci(p, len, "vmware");
    if (!v) return 0;
    int n = (int)((p + len) - v); if (n > 220) n = 220;
    char s[224]; ae_clean(v, n, s, sizeof(s));
    ae_set(r, "slp-vmware", 0, "%s", s);
    return 1;
}

static inline int ae_mndp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8) return 0;
    const unsigned char *m = ae_find_ci(p, len, "MikroTik");
    if (!m && !ae_find_ci(p, len, "RouterOS")) return 0;
    char text[320]; ae_clean(p, len > 300 ? 300 : len, text, sizeof(text));
    ae_set(r, "mndp", 0, "%s", text[0] ? text : "mikrotik-neighbor");
    return 1;
}

static inline int ae_cip(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 24 || ae_le16(p) != 0x0063U) return 0;
    if (len < 44) { ae_set(r, "ethernet-ip", 0, "ListIdentity request"); return 1; }
    int pos = 24;
    uint16_t count = ae_le16(p + pos); pos += 2;
    if (!count || pos + 4 > len) return 0;
    pos += 2; uint16_t ilen = ae_le16(p + pos); pos += 2;
    if (ilen < 30U || pos + ilen > len) return 0;
    if (pos + 29 > len) return 0;
    pos += 2 + 16;
    uint16_t vendor = ae_le16(p + pos); pos += 2;
    uint16_t dtype = ae_le16(p + pos); pos += 2;
    uint16_t product = ae_le16(p + pos); pos += 2;
    uint8_t maj = p[pos++], min = p[pos++]; pos += 2; /* status */
    uint32_t serial = ae_le32(p + pos); pos += 4;
    if (pos >= len) return 0;
    uint8_t nl = p[pos++]; if (pos + nl > len) nl = (uint8_t)(len - pos);
    char name[128]; ae_clean(p + pos, nl, name, sizeof(name));
    ae_set(r, "ethernet-ip", 0,
           "ListIdentity vendor=%u device_type=%u product=%u firmware=%u.%u serial=%08x name=%s",
           vendor, dtype, product, maj, min, serial, name[0] ? name : "-");
    return 1;
}

static inline int ae_bacnet(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 8 || p[0] != 0x81U) return 0; /* BVLL */
    if (p[1] != 0x0aU && p[1] != 0x0bU) return 0;
    /* Locate an Unconfirmed-Request/I-Am APDU. NPDU length varies with control flags. */
    for (int i = 6; i + 1 < len && i < 32; ++i) {
        if ((p[i] & 0xf0U) == 0x10U && p[i + 1] == 0x00U) {
            ae_set(r, "bacnet-ip", 0, "I-Am announcement");
            return 1;
        }
    }
    return 0;
}

static inline const char *ae_radius_code(uint8_t code) {
    switch (code) {
        case 1U: return "Access-Request"; case 2U: return "Access-Accept";
        case 3U: return "Access-Reject"; case 4U: return "Accounting-Request";
        case 5U: return "Accounting-Response"; case 11U: return "Access-Challenge";
        case 12U: return "Status-Server"; case 13U: return "Status-Client";
        default: return "Other";
    }
}

/* Privacy-minimized RADIUS fingerprinting. Attribute values that can identify
 * a user, station or NAS (User-Name, Calling/Called-Station-Id,
 * NAS-Identifier), password material and the 16-byte Authenticator are never
 * emitted. Only protocol/state/capability metadata is retained. */
static inline int ae_radius(const unsigned char *p, int len, uint16_t port,
                            argos_enterprise_result_t *r) {
    if (!p || !r || len < 20) return 0;
    uint16_t plen = ae_be16(p + 2);
    if (plen < 20U || plen > 4096U || plen > (uint16_t)len) return 0;
    uint8_t code = p[0];
    if (!(code == 1U || code == 2U || code == 3U || code == 4U || code == 5U ||
          code == 11U || code == 12U || code == 13U)) return 0;

    unsigned user = 0, password = 0, nas_ip = 0, nas_port_seen = 0;
    unsigned called = 0, calling = 0, nas_id = 0, eap = 0, msg_auth = 0;
    uint32_t nas_port = 0, service_type = 0, nas_port_type = 0, acct_status = 0;
    uint32_t vendor = 0;
    int pos = 20;
    while (pos < (int)plen) {
        if (pos + 2 > (int)plen) return 0;
        uint8_t type = p[pos], alen = p[pos + 1];
        if (alen < 2U || pos + (int)alen > (int)plen) return 0;
        const unsigned char *v = p + pos + 2;
        int vl = (int)alen - 2;
        switch (type) {
            case 1U: user = 1; break;
            case 2U: case 3U: password = 1; break;
            case 4U: if (vl == 4) nas_ip = 1; break;
            case 5U: if (vl == 4) { nas_port_seen = 1; nas_port = ae_be32(v); } break;
            case 6U: if (vl == 4) service_type = ae_be32(v); break;
            case 26U: if (vl >= 4 && vendor == 0U) vendor = ae_be32(v); break;
            case 30U: called = 1; break;
            case 31U: calling = 1; break;
            case 32U: nas_id = 1; break;
            case 40U: if (vl == 4) acct_status = ae_be32(v); break;
            case 61U: if (vl == 4) nas_port_type = ae_be32(v); break;
            case 79U: eap = 1; break;
            case 80U: if (vl == 16) msg_auth = 1; break;
            default: break;
        }
        pos += (int)alen;
    }

    const char *plane = port == 1813U ? "accounting" : "auth";
    ae_set(r, "radius", 0,
           "plane=%s code=%u(%s) user_present=%u password_attr=%u nas_ip_present=%u nas_port_present=%u nas_port=%u service_type=%u nas_port_type=%u acct_status=%u called_station_present=%u calling_station_present=%u nas_identifier_present=%u eap=%u message_auth=%u vendor_id=%u",
           plane, (unsigned)code, ae_radius_code(code), user, password, nas_ip,
           nas_port_seen, (unsigned)nas_port, (unsigned)service_type,
           (unsigned)nas_port_type, (unsigned)acct_status, called, calling, nas_id,
           eap, msg_auth, (unsigned)vendor);
    return 1;
}

static inline const char *ae_stun_class(unsigned c) {
    return c == 0U ? "request" : c == 1U ? "indication" :
           c == 2U ? "success" : c == 3U ? "error" : "other";
}

static inline const char *ae_stun_method(unsigned m) {
    switch (m) {
        case 0x001U: return "Binding";
        case 0x003U: return "Allocate";
        case 0x004U: return "Refresh";
        case 0x006U: return "Send";
        case 0x007U: return "Data";
        case 0x008U: return "CreatePermission";
        case 0x009U: return "ChannelBind";
        default: return "Other";
    }
}

/* Privacy/performance-minimized RFC 8489 / RFC 8656 control fingerprint.
 * Transaction IDs and address attributes are never emitted. USERNAME, REALM,
 * NONCE, USERHASH and authentication values remain opaque. TURN Send/Data and
 * DATA attributes carry application payload and are rejected here; Ethernet
 * capture additionally fast-drops Send/Data and ChannelData in classic BPF. */
static inline int ae_stun_turn(const unsigned char *p, int len,
                               argos_enterprise_result_t *r) {
    if (!p || !r || len < 20 || (p[0] & 0xc0U) != 0U) return 0;
    uint16_t type = ae_be16(p);
    uint16_t mlen = ae_be16(p + 2);
    if ((mlen & 3U) != 0U || 20U + (uint32_t)mlen > (uint32_t)len) return 0;
    if (ae_be32(p + 4) != 0x2112a442U) return 0;

    unsigned method = (unsigned)(type & 0x000fU) |
                      (unsigned)((type & 0x00e0U) >> 1) |
                      (unsigned)((type & 0x3e00U) >> 2);
    unsigned cls = (unsigned)((type & 0x0010U) >> 4) |
                   (unsigned)((type & 0x0100U) >> 7);
    /* TURN Send/Data indications are relay payload, not fingerprints. */
    if (method == 0x006U || method == 0x007U) return 0;

    char software[128] = {0};
    uint32_t priority = 0U, lifetime = 0U;
    unsigned use_candidate = 0U, ice_controlled = 0U, ice_controlling = 0U;
    unsigned integrity = 0U, integrity256 = 0U, fingerprint = 0U;
    unsigned requested_transport = 0U, address_family = 0U, channel_present = 0U;

    size_t pos = 20U, end = 20U + (size_t)mlen;
    while (pos < end) {
        if (pos + 4U > end) return 0;
        uint16_t at = ae_be16(p + pos), alen = ae_be16(p + pos + 2U);
        size_t value = pos + 4U;
        size_t padded = ((size_t)alen + 3U) & ~(size_t)3U;
        if (value + padded > end || value + (size_t)alen > end) return 0;
        const unsigned char *v = p + value;
        switch (at) {
            case 0x0008U: integrity = 1U; break;                 /* MESSAGE-INTEGRITY */
            case 0x000cU: if (alen == 4U) channel_present = 1U; break;
            case 0x000dU: if (alen == 4U) lifetime = ae_be32(v); break;
            case 0x0013U: return 0;                             /* DATA: relay payload */
            case 0x0017U: if (alen == 4U) address_family = v[0]; break;
            case 0x0019U: if (alen == 4U) requested_transport = v[0]; break;
            case 0x001cU: integrity256 = 1U; break;              /* MESSAGE-INTEGRITY-SHA256 */
            case 0x0024U: if (alen == 4U) priority = ae_be32(v); break;
            case 0x0025U: if (alen == 0U) use_candidate = 1U; break;
            case 0x8022U:
                if (alen > 0U) {
                    int n = alen > 120U ? 120 : (int)alen;
                    ae_clean(v, n, software, sizeof(software));
                }
                break;
            case 0x8028U: if (alen == 4U) fingerprint = 1U; break;
            case 0x8029U: if (alen == 8U) ice_controlled = 1U; break;
            case 0x802aU: if (alen == 8U) ice_controlling = 1U; break;
            default: break; /* includes all identity/address/auth values */
        }
        pos = value + padded;
    }
    if (pos != end) return 0;

    const char *proto = (method == 0x003U || method == 0x004U ||
                         method == 0x008U || method == 0x009U) ? "turn" : "stun";
    const char *ice = ice_controlled && ice_controlling ? "both" :
                      ice_controlled ? "controlled" : ice_controlling ? "controlling" : "-";
    ae_set(r, proto, 0,
           "method=%s class=%s software=%s priority=%u use_candidate=%u ice=%s integrity=%u integrity_sha256=%u fingerprint=%u requested_transport=%u lifetime=%u address_family=%u channel_present=%u",
           ae_stun_method(method), ae_stun_class(cls), software[0] ? software : "-",
           (unsigned)priority, use_candidate, ice, integrity, integrity256, fingerprint,
           requested_transport, (unsigned)lifetime, address_family, channel_present);
    return 1;
}

static inline const char *ae_coap_type(unsigned t) {
    return t == 0U ? "CON" : t == 1U ? "NON" : t == 2U ? "ACK" : t == 3U ? "RST" : "-";
}

static inline const char *ae_coap_method(unsigned detail) {
    return detail == 1U ? "GET" : detail == 2U ? "POST" :
           detail == 3U ? "PUT" : detail == 4U ? "DELETE" : "Other";
}

static inline int ae_coap_ext(const unsigned char *p, int end, int *pos,
                              unsigned nibble, unsigned *out) {
    if (!p || !pos || !out || *pos < 0 || *pos > end) return 0;
    if (nibble < 13U) { *out = nibble; return 1; }
    if (nibble == 13U) {
        if (*pos >= end) return 0;
        *out = 13U + p[(*pos)++];
        return 1;
    }
    if (nibble == 14U) {
        if (*pos + 2 > end) return 0;
        *out = 269U + ae_be16(p + *pos);
        *pos += 2;
        return 1;
    }
    return 0; /* 15 is reserved */
}

/* RFC 7252 CoAP metadata fingerprinting. Token, Message ID, Uri-Host,
 * Uri-Path, Uri-Query, Proxy-Uri and payload bytes can expose identifiers or
 * application data and are never emitted. Only bounded structural metadata
 * and safe option presence/counts are retained. */
static inline int ae_coap(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (!p || !r || len < 4) return 0;
    unsigned ver=(p[0]>>6)&0x03U, type=(p[0]>>4)&0x03U, tkl=p[0]&0x0fU;
    if (ver != 1U || tkl > 8U || 4U+tkl > (unsigned)len) return 0;
    unsigned code=p[1], cls=(code>>5)&0x07U, detail=code&0x1fU;
    if (!(cls==0U || cls==2U || cls==4U || cls==5U)) return 0;
    if (cls==0U && detail>4U) return 0;

    int pos=4+(int)tkl; unsigned optnum=0U, option_count=0U;
    unsigned uri_path_count=0U, uri_query_count=0U, proxy_uri=0U;
    unsigned observe=0U, oscore=0U, payload=0U;
    unsigned content_format=0xffffffffU, accept=0xffffffffU;
    while (pos < len) {
        if (p[pos] == 0xffU) { if (pos+1 >= len) return 0; payload=1U; break; }
        uint8_t h=p[pos++]; unsigned delta=0U, olen=0U;
        if (!ae_coap_ext(p,len,&pos,(h>>4)&0x0fU,&delta) ||
            !ae_coap_ext(p,len,&pos,h&0x0fU,&olen)) return 0;
        if (delta > 65535U-optnum || olen > (unsigned)(len-pos)) return 0;
        optnum += delta; option_count++;
        const unsigned char *v=p+pos;
        if (optnum==6U) observe=1U;
        else if (optnum==9U) oscore=1U;
        else if (optnum==11U) uri_path_count++;
        else if (optnum==12U && olen<=2U) { content_format=0U; for(unsigned i=0;i<olen;i++) content_format=(content_format<<8)|v[i]; }
        else if (optnum==15U) uri_query_count++;
        else if (optnum==17U && olen<=2U) { accept=0U; for(unsigned i=0;i<olen;i++) accept=(accept<<8)|v[i]; }
        else if (optnum==35U) proxy_uri=1U;
        pos += (int)olen;
        if (option_count > 64U) return 0;
    }
    const char *method = cls==0U && detail ? ae_coap_method(detail) : "-";
    char cf[16], ac[16];
    if (content_format == 0xffffffffU) snprintf(cf,sizeof(cf),"-"); else snprintf(cf,sizeof(cf),"%u",content_format);
    if (accept == 0xffffffffU) snprintf(ac,sizeof(ac),"-"); else snprintf(ac,sizeof(ac),"%u",accept);
    ae_set(r,"coap",0,
           "type=%s code=%u.%02u method=%s token_len=%u options=%u uri_path_segments=%u uri_query_parts=%u observe=%u oscore=%u proxy_uri=%u content_format=%s accept=%s payload=%u",
           ae_coap_type(type),cls,detail,method,tkl,option_count,uri_path_count,uri_query_count,
           observe,oscore,proxy_uri,cf,ac,payload);
    return 1;
}

static inline const char *ae_ntp_mode(unsigned mode) {
    return mode == 1U ? "symmetric-active" :
           mode == 2U ? "symmetric-passive" :
           mode == 3U ? "client" :
           mode == 4U ? "server" :
           mode == 5U ? "broadcast" : "-";
}

/* NTP time-message fingerprinting. The Reference ID and all four 64-bit
 * timestamps are deliberately opaque: they can expose server identity and
 * timing data but add little device-classification value. Modes 6/7 use
 * control/private packet formats and are not interpreted as time messages. */
static inline int ae_ntp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (!p || !r || len < 48) return 0;
    unsigned li=(p[0] >> 6) & 0x03U;
    unsigned vn=(p[0] >> 3) & 0x07U;
    unsigned mode=p[0] & 0x07U;
    if (vn < 1U || vn > 4U || mode < 1U || mode > 5U) return 0;
    unsigned stratum=p[1];
    int poll=(int)(int8_t)p[2];
    int precision=(int)(int8_t)p[3];
    unsigned extra=(unsigned)(len - 48);
    ae_set(r,"ntp",0,
           "version=%u mode=%s li=%u stratum=%u poll=%d precision=%d extra_bytes=%u",
           vn,ae_ntp_mode(mode),li,stratum,poll,precision,extra);
    return 1;
}

static inline int argos_enterprise_parse_udp(uint16_t sport, uint16_t dport,
                                             const unsigned char *p, int len,
                                             argos_enterprise_result_t *r) {
    if (!p || len <= 0 || !r || !argos_enterprise_udp_port(sport, dport)) return 0;
    memset(r, 0, sizeof(*r));
    uint16_t port = dport;
    if (!argos_enterprise_udp_port(0, port)) port = sport;
    switch (port) {
        case 88: return ae_kerberos(p, len, r);
        case 111: case 2049: return ae_rpc(p, len, 0, r);
        case 123: return ae_ntp(p, len, r);
        case 161: case 162: return ae_snmp(p, len, r);
        case 389: return ae_cldap(p, len, r);
        case 427: return ae_slp(p, len, r);
        case 514: return ae_syslog(p, len, r);
        case 623: return ae_ipmi(p, len, r);
        case 1812: case 1813: return ae_radius(p, len, port, r);
        case 2055: case 9995: case 9996: return ae_netflow(p, len, r);
        case 3478: return ae_stun_turn(p, len, r);
        case 4739: return ae_ipfix(p, len, r);
        case 5060: return ae_sip(p, len, r);
        case 5678: return ae_mndp(p, len, r);
        case 5683: return ae_coap(p, len, r);
        case 6343: return ae_sflow(p, len, r);
        case 47808: return ae_bacnet(p, len, r);
        case 44818: return ae_cip(p, len, r);
        default: return 0;
    }
}

static inline int argos_enterprise_parse_l2(uint16_t proto, const unsigned char *p, int len,
                                            argos_enterprise_result_t *r) {
    if (!p || len <= 0 || !r) return 0;
    memset(r, 0, sizeof(*r));
    if (proto == 0x888eU) {
        if (len < 4) return 0;
        uint8_t eapol_type = p[1];
        if (eapol_type != 0U || len < 9) {
            ae_set(r, "eapol", 0, "version=%u eapol_type=%u", p[0], eapol_type);
            return 1;
        }
        uint8_t code = p[4], type = p[8];
        const char *tn = type == 1U ? "Identity" : type == 4U ? "MD5" : type == 13U ? "TLS" :
                         type == 21U ? "TTLS" : type == 25U ? "PEAP" : type == 43U ? "FAST" : "Other";
        /* Identity values may be usernames. Classify rather than logging raw identity. */
        const char *kind = "-";
        if (type == 1U && len > 9) {
            if (memchr(p + 9, '$', (size_t)(len - 9))) kind = "machine";
            else if (memchr(p + 9, '@', (size_t)(len - 9)) || memchr(p + 9, '\\', (size_t)(len - 9))) kind = "user";
            else kind = "opaque";
        }
        ae_set(r, "eapol", 0, "code=%u eap_type=%u(%s) identity_class=%s", code, type, tn, kind);
        return 1;
    }
    if (proto == 0x8892U) {
        if (len < 12) return 0;
        uint16_t frameid = ae_be16(p);
        if (frameid != 0xfefeU && frameid != 0xfeffU) return 0;
        if (p[2] != 0x05U) return 0; /* DCP Identify */
        int dlen = ae_be16(p + 10), pos = 12, end = 12 + dlen; if (end > len) end = len;
        char station[128] = {0}; unsigned vendor = 0, device = 0;
        while (pos + 4 <= end) {
            uint8_t opt = p[pos], sub = p[pos+1]; uint16_t bl = ae_be16(p + pos + 2); pos += 4;
            if (pos + bl > end) break;
            if (opt == 2U && sub == 2U && bl > 2U) ae_clean(p + pos + 2, bl - 2, station, sizeof(station));
            else if (opt == 2U && sub == 3U && bl >= 6U) { vendor = ae_be16(p + pos + 2); device = ae_be16(p + pos + 4); }
            pos += bl + (bl & 1U);
        }
        ae_set(r, "profinet-dcp", 0, "identify type=%u station=%s vendor_id=%u device_id=%u",
               p[3], station[0]?station:"-", vendor, device);
        return 1;
    }

    if (proto == 0x00bbU) { /* Extreme Discovery Protocol */
        if (len < 16) return 0;
        uint8_t version = p[0];
        uint16_t advertised = ae_be16(p + 2);
        int end = advertised >= 16U && advertised <= (uint16_t)len ? advertised : len;
        int pos = 16;
        char name[128] = {0};
        unsigned slot = 0, port = 0, v1 = 0, v2 = 0, vs = 0, vi = 0;
        while (pos + 4 <= end) {
            uint8_t type = p[pos + 1];
            uint16_t tl = ae_be16(p + pos + 2);
            if (tl < 4U || pos + tl > end) break;
            if (type == 0x01U && tl > 4U) {
                ae_clean(p + pos + 4, (int)tl - 4, name, sizeof(name));
            } else if (type == 0x02U && tl >= 20U) {
                slot = ae_be16(p + pos + 4) + 1U;
                port = ae_be16(p + pos + 6) + 1U;
                v1 = p[pos + 16]; v2 = p[pos + 17]; vs = p[pos + 18]; vi = p[pos + 19];
            }
            pos += tl;
        }
        ae_set(r, "edp", 0, "version=%u name=%s slot=%u port=%u software=%u.%u.%u.%u",
               version, name[0] ? name : "-", slot, port, v1, v2, vs, vi);
        return 1;
    }
    if (proto == 0xf200U) { /* Foundry Discovery Protocol */
        if (len < 4) return 0;
        uint8_t version = p[0], hold = p[1];
        int pos = 4;
        char name[128] = {0}, iface[96] = {0}, release[160] = {0}, model[128] = {0};
        while (pos + 4 <= len) {
            uint16_t type = ae_be16(p + pos), tl = ae_be16(p + pos + 2);
            if (tl < 4U || pos + tl > len) break;
            if (type == 1U) ae_clean(p + pos + 4, (int)tl - 4, name, sizeof(name));
            else if (type == 3U) ae_clean(p + pos + 4, (int)tl - 4, iface, sizeof(iface));
            else if (type == 5U) ae_clean(p + pos + 4, (int)tl - 4, release, sizeof(release));
            else if (type == 6U) ae_clean(p + pos + 4, (int)tl - 4, model, sizeof(model));
            pos += tl;
        }
        ae_set(r, "fdp", 0, "version=%u hold=%u device=%s model=%s software=%s interface=%s",
               version, hold, name[0] ? name : "-", model[0] ? model : "-",
               release[0] ? release : "-", iface[0] ? iface : "-");
        return 1;
    }
    if (proto == 0x00feU) { /* ISO IS-IS after LLC FE:FE:03 */
        if (len < 20 || p[0] != 0x83U) return 0;
        uint8_t pdu_type = (uint8_t)(p[4] & 0x1fU);
        if (pdu_type != 15U && pdu_type != 16U && pdu_type != 17U) return 0;
        char sysid[32];
        snprintf(sysid, sizeof(sysid), "%02x%02x.%02x%02x.%02x%02x",
                 p[9], p[10], p[11], p[12], p[13], p[14]);
        uint16_t hold = ae_be16(p + 15);
        uint16_t plen = ae_be16(p + 17);
        unsigned circuit = p[8] & 0x03U;
        if (pdu_type == 15U || pdu_type == 16U) {
            unsigned priority = p[19] & 0x7fU;
            ae_set(r, "isis", 0, "hello=%s system_id=%s circuit=%u hold=%u pdu_len=%u priority=%u",
                   pdu_type == 15U ? "L1-LAN" : "L2-LAN", sysid, circuit, hold, plen, priority);
        } else {
            ae_set(r, "isis", 0, "hello=P2P system_id=%s circuit=%u hold=%u pdu_len=%u local_circuit=%u",
                   sysid, circuit, hold, plen, p[19]);
        }
        return 1;
    }
    if (proto == 0x2000U) { /* CDP SNAP PID */
        if (len < 4) return 0;
        char dev[128] = {0}, platform[128] = {0}, software[192] = {0}; unsigned vlan = 0;
        int pos = 4;
        while (pos + 4 <= len) {
            uint16_t t = ae_be16(p + pos), tl = ae_be16(p + pos + 2); if (tl < 4U || pos + tl > len) break;
            const unsigned char *v = p + pos + 4; int vl = (int)tl - 4;
            if (t == 0x0001U) ae_clean(v, vl, dev, sizeof(dev));
            else if (t == 0x0005U) ae_clean(v, vl, software, sizeof(software));
            else if (t == 0x0006U) ae_clean(v, vl, platform, sizeof(platform));
            else if (t == 0x000aU && vl >= 2) vlan = ae_be16(v);
            pos += tl;
        }
        ae_set(r, "cdp", 0, "device=%s platform=%s software=%s native_vlan=%u",
               dev[0]?dev:"-", platform[0]?platform:"-", software[0]?software:"-", vlan);
        return 1;
    }
    return 0;
}

static inline int argos_enterprise_parse_ipproto(uint8_t proto, const unsigned char *p, int len,
                                                 argos_enterprise_result_t *r) {
    if (!p || len <= 0 || !r || proto != 89U) return 0;
    memset(r, 0, sizeof(*r));
    if (len < 16) return 0;
    uint8_t ver = p[0], type = p[1];
    if (type != 1U) return 0; /* Hellos only */
    char rid[32]; snprintf(rid, sizeof(rid), "%u.%u.%u.%u", p[4],p[5],p[6],p[7]);
    char area[32]; snprintf(area, sizeof(area), "%u.%u.%u.%u", p[8],p[9],p[10],p[11]);
    if (ver == 2U && len >= 44) {
        uint16_t hello = ae_be16(p + 28); uint32_t dead = ae_be32(p + 32);
        ae_set(r, "ospf", 0, "v2 hello router_id=%s area=%s hello=%u dead=%u options=0x%02x",
               rid, area, hello, dead, p[30]);
    } else {
        ae_set(r, "ospf", 0, "v%u hello router_id=%s area=%s", ver, rid, area);
    }
    return 1;
}

#endif /* ARGOS_ENTERPRISE_H */
