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
        ae_set(r, "smb2", 1, "command=session-setup auth=spnego");
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
    ae_set(r, "smb2-ntlm", 1,
           "message=%u windows=%u.%u build=%u domain=%s workstation=%s",
           mt, maj, min, build, domain[0] ? domain : "-", workstation[0] ? workstation : "-");
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

static inline int ae_rdp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 11 || p[0] != 0x03U || p[1] != 0x00U) return 0; /* TPKT */
    if (p[5] != 0xe0U && p[5] != 0xd0U) return 0;             /* X.224 CR/CC */
    char cookie[128] = {0};
    const unsigned char *c = ae_find_ci(p, len, "Cookie: mstshash=");
    if (c) {
        c += 16; const unsigned char *e = ae_find(c, (int)((p + len) - c), (const unsigned char *)"\r\n", 2);
        int n = e ? (int)(e - c) : 0; if (n > 120) n = 120; ae_clean(c, n, cookie, sizeof(cookie));
    }
    ae_set(r, "rdp", 1, "x224=%s cookie=%s", p[5] == 0xe0U ? "connection-request" : "connection-confirm",
           cookie[0] ? cookie : "-");
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
        case 631: return ae_ipp(p, len, r);
        case 1433: return ae_tds(p, len, r);
        case 1521: return ae_tns(p, len, r);
        case 2000: return ae_sccp(p, len, r);
        case 3260: return ae_iscsi(p, len, r);
        case 3306: return ae_mysql(p, len, r);
        case 3389: return ae_rdp(p, len, r);
        case 5060: return ae_sip(p, len, r);
        case 5432: return ae_postgres(p, len, r);
        case 9100: return ae_pjl(p, len, r);
        case 44818: return ae_cip(p, len, r);
        default: return 0;
    }
}

static inline int ae_snmp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    static const unsigned char sysdescr[] = {0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00};
    static const unsigned char sysobj[]   = {0x2b,0x06,0x01,0x02,0x01,0x01,0x02,0x00};
    const unsigned char *q = ae_find(p, len, sysdescr, (int)sizeof(sysdescr));
    const char *label = "sysDescr";
    if (!q) { q = ae_find(p, len, sysobj, (int)sizeof(sysobj)); label = "sysObjectID"; }
    if (!q) return 0;
    q += 8;
    int remain = (int)((p + len) - q);
    if (remain < 2) return 0;
    /* Skip the value TLV tag and short-form length. Long-form values are left generic. */
    uint8_t tag = q[0], vl = q[1];
    if ((vl & 0x80U) || 2 + vl > remain) {
        ae_set(r, "snmp", 0, "%s-present", label);
        return 1;
    }
    char value[256];
    if (tag == 0x04U) ae_clean(q + 2, vl, value, sizeof(value));
    else {
        size_t used = 0; value[0] = '\0';
        for (int i = 0; i < vl && used + 3U < sizeof(value); ++i) {
            int w = snprintf(value + used, sizeof(value) - used, "%s%02x", i ? ":" : "", q[2+i]);
            if (w < 0 || (size_t)w >= sizeof(value) - used) break;
            used += (size_t)w;
        }
    }
    ae_set(r, "snmp", 0, "%s=%s", label, value[0] ? value : "-");
    return 1;
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
    ae_set(r, "kerberos", 0, "request=%s realm=%s", kind, realm[0] ? realm : "-");
    return 1;
}

static inline int ae_cldap(const unsigned char *p, int len, argos_enterprise_result_t *r) {
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
        case 161: case 162: return ae_snmp(p, len, r);
        case 389: return ae_cldap(p, len, r);
        case 427: return ae_slp(p, len, r);
        case 623: return ae_ipmi(p, len, r);
        case 1812: case 1813: return ae_radius(p, len, port, r);
        case 5060: return ae_sip(p, len, r);
        case 5678: return ae_mndp(p, len, r);
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
