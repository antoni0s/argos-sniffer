#ifndef ARGOS_IDENTITY_H
#define ARGOS_IDENTITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Optional identity evidence derived only from handshake/control fields that
 * Argos already inspects for protocol fingerprinting. This is not a generic
 * payload scanner. "Observed identity" is evidence, never device ownership.
 */
typedef struct {
    char protocol[24];
    char type[24];
    char value[192];
    uint32_t hash;
    uint16_t value_len;
    uint8_t present;
} argos_identity_result_t;

static inline uint32_t argos_identity_hash32(const unsigned char *p, size_t len) {
    uint32_t h = 2166136261U;
    if (!p) return 0U;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619U;
    }
    return h;
}

static inline size_t argos_identity_clean(const unsigned char *src, size_t len,
                                          char *dst, size_t cap) {
    size_t o = 0U;
    if (!dst || cap == 0U) return 0U;
    if (!src) { dst[0] = '\0'; return 0U; }
    for (size_t i = 0; i < len && o + 1U < cap; ++i) {
        unsigned char c = src[i];
        if (c >= 32U && c <= 126U) {
            dst[o++] = (c == '|' || c == '\\') ? '/' : (char)c;
        } else if (o > 0U && dst[o - 1U] != ' ') {
            dst[o++] = ' ';
        }
    }
    while (o > 0U && dst[o - 1U] == ' ') --o;
    dst[o] = '\0';
    return o;
}

static inline int argos_identity_build(argos_identity_result_t *r,
                                       const char *protocol, const char *type,
                                       const unsigned char *value, size_t len,
                                       int raw_mode) {
    if (!r) return 0;
    memset(r, 0, sizeof(*r));
    if (!protocol || !type || !value || len == 0U) return 0;
    if (len > 160U) len = 160U;
    snprintf(r->protocol, sizeof(r->protocol), "%s", protocol);
    snprintf(r->type, sizeof(r->type), "%s", type);
    r->hash = argos_identity_hash32(value, len);
    r->value_len = (uint16_t)len;
    r->present = 1U;
    if (raw_mode)
        argos_identity_clean(value, len, r->value, sizeof(r->value));
    else
        snprintf(r->value, sizeof(r->value), "hash=%08x,len=%u",
                 r->hash, (unsigned)r->value_len);
    return 1;
}


/* RDP identity evidence is limited to the mstshash cookie carried in the
 * initial X.224 Connection Request. It is a user/login hint, not proof of an
 * authenticated principal and never device ownership. No stream scan occurs:
 * only the already-inspected initial RDP handshake payload is considered. */
static inline int argos_identity_rdp_mstshash(const unsigned char *p, size_t len,
                                              int raw_mode,
                                              argos_identity_result_t *r) {
    static const unsigned char prefix[] = "Cookie: mstshash=";
    if (!p || !r || len < 11U || p[0] != 0x03U || p[1] != 0x00U || p[5] != 0xe0U)
        return 0;

    const size_t prefix_len = sizeof(prefix) - 1U;
    const unsigned char *c = NULL;
    for (size_t i = 0; i + prefix_len <= len; ++i) {
        int match = 1;
        for (size_t j = 0; j < prefix_len; ++j) {
            unsigned char a = p[i + j], b = prefix[j];
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b) { match = 0; break; }
        }
        if (match) { c = p + i + prefix_len; break; }
    }
    if (!c || c >= p + len) return 0;

    const unsigned char *end = NULL;
    for (const unsigned char *q = c; q + 1 < p + len; ++q) {
        if (q[0] == '\r' && q[1] == '\n') { end = q; break; }
    }
    if (!end || end <= c) return 0;
    size_t n = (size_t)(end - c);
    if (n > 120U) n = 120U;
    return argos_identity_build(r, "rdp", "mstshash", c, n, raw_mode);
}


/* NTLM Type 3 observed identity extraction. Only DomainName, UserName and
 * Workstation security buffers are consulted. LM/NT responses, session keys,
 * MICs and authentication blobs are deliberately never read or copied. */
static inline uint16_t argos_identity_le16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

static inline uint32_t argos_identity_le32(const unsigned char *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static inline int argos_identity_ntlm_utf16_field(const unsigned char *ntlm,
                                                   size_t remain,
                                                   size_t secbuf_off,
                                                   const char *type,
                                                   int raw_mode,
                                                   argos_identity_result_t *r) {
    if (!ntlm || !type || !r || secbuf_off + 8U > remain) return 0;
    uint16_t bytes = argos_identity_le16(ntlm + secbuf_off);
    uint32_t off = argos_identity_le32(ntlm + secbuf_off + 4U);
    if (bytes == 0U) return 0;
    if ((bytes & 1U) != 0U || off >= remain || (size_t)bytes > remain - (size_t)off)
        return 0;

    size_t chars = (size_t)bytes / 2U;
    if (chars > 160U) chars = 160U;
    unsigned char decoded[161];
    size_t out = 0U;
    for (size_t i = 0; i < chars; ++i) {
        unsigned char lo = ntlm[(size_t)off + i * 2U];
        unsigned char hi = ntlm[(size_t)off + i * 2U + 1U];
        unsigned char c = (hi == 0U && lo >= 32U && lo <= 126U) ? lo : (unsigned char)'?';
        decoded[out++] = c;
    }
    if (out == 0U) return 0;
    return argos_identity_build(r, "ntlm", type, decoded, out, raw_mode);
}

static inline size_t argos_identity_ntlm_type3(const unsigned char *p, size_t len,
                                                int raw_mode,
                                                argos_identity_result_t out[3]) {
    static const unsigned char smb2[] = {0xfeU,'S','M','B'};
    static const unsigned char sig[] = {'N','T','L','M','S','S','P',0};
    if (!p || !out || len < 64U || memcmp(p, smb2, sizeof(smb2)) != 0) return 0U;
    if (argos_identity_le16(p + 12U) != 0x0001U) return 0U; /* SESSION_SETUP */

    const unsigned char *n = NULL;
    for (size_t i = 64U; i + sizeof(sig) <= len; ++i) {
        if (memcmp(p + i, sig, sizeof(sig)) == 0) { n = p + i; break; }
    }
    if (!n) return 0U;
    size_t remain = len - (size_t)(n - p);
    if (remain < 52U || argos_identity_le32(n + 8U) != 3U) return 0U;

    memset(out, 0, sizeof(argos_identity_result_t) * 3U);
    size_t count = 0U;
    argos_identity_result_t r;
    if (argos_identity_ntlm_utf16_field(n, remain, 28U, "domain", raw_mode, &r))
        out[count++] = r;
    if (argos_identity_ntlm_utf16_field(n, remain, 36U, "user", raw_mode, &r))
        out[count++] = r;
    if (argos_identity_ntlm_utf16_field(n, remain, 44U, "workstation", raw_mode, &r))
        out[count++] = r;
    return count;
}


/* Kerberos observed identity is intentionally limited to cname [1] from the
 * KDC-REQ-BODY of an AS-REQ. RFC 4120 defines cname there only for AS-REQ.
 * PA-DATA, tickets, authenticators, encrypted data and TGS-REQ identity are
 * deliberately outside this parser. */
static inline int argos_identity_der_tlv(const unsigned char *p, size_t n, size_t pos,
                                         uint8_t *tag, size_t *voff,
                                         size_t *vlen, size_t *next) {
    if (!p || !tag || !voff || !vlen || !next || pos >= n) return 0;
    uint8_t t = p[pos++];
    if ((t & 0x1fU) == 0x1fU || pos >= n) return 0;
    uint8_t lb = p[pos++];
    size_t len = 0U;
    if ((lb & 0x80U) == 0U) {
        len = (size_t)lb;
    } else {
        unsigned count = (unsigned)(lb & 0x7fU);
        if (count == 0U || count > 4U || (size_t)count > n - pos) return 0;
        for (unsigned i = 0U; i < count; ++i) {
            if (len > (SIZE_MAX >> 8)) return 0;
            len = (len << 8) | (size_t)p[pos++];
        }
    }
    if (len > n - pos) return 0;
    *tag = t; *voff = pos; *vlen = len; *next = pos + len;
    return 1;
}

static inline uint32_t argos_identity_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline int argos_identity_kerberos_string(const unsigned char *p,
                                                  size_t n, size_t pos,
                                                  const unsigned char **value,
                                                  size_t *value_len) {
    uint8_t tag; size_t voff, vlen, next;
    if (!value || !value_len ||
        !argos_identity_der_tlv(p, n, pos, &tag, &voff, &vlen, &next) ||
        tag != 0x1bU || vlen == 0U) return 0;
    (void)next;
    *value = p + voff; *value_len = vlen;
    return 1;
}

static inline int argos_identity_kerberos_asreq(const unsigned char *p, size_t len,
                                                int tcp_framed, int raw_mode,
                                                argos_identity_result_t *r) {
    if (!p || !r) return 0;
    size_t off = 0U, end = len;
    if (tcp_framed) {
        if (len < 5U) return 0;
        uint32_t record_len = argos_identity_be32(p);
        if (record_len == 0U || (size_t)record_len > len - 4U) return 0;
        off = 4U; end = off + (size_t)record_len;
    }

    uint8_t tag; size_t voff, vlen, next;
    if (!argos_identity_der_tlv(p, end, off, &tag, &voff, &vlen, &next) ||
        tag != 0x6aU) return 0; /* AS-REQ only; never TGS-REQ */
    (void)next;

    uint8_t seq_tag; size_t seq_voff, seq_vlen, seq_next;
    if (!argos_identity_der_tlv(p, voff + vlen, voff,
                                &seq_tag, &seq_voff, &seq_vlen, &seq_next) ||
        seq_tag != 0x30U) return 0;
    (void)seq_next;

    size_t body_voff = 0U, body_vlen = 0U;
    size_t seq_end = seq_voff + seq_vlen;
    for (size_t pos = seq_voff; pos < seq_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!argos_identity_der_tlv(p, seq_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa4U) { body_voff = cv; body_vlen = cl; break; }
        pos = cn;
    }
    if (body_vlen == 0U) return 0;

    uint8_t body_tag; size_t bvoff, bvlen, bnext;
    if (!argos_identity_der_tlv(p, body_voff + body_vlen, body_voff,
                                &body_tag, &bvoff, &bvlen, &bnext) ||
        body_tag != 0x30U) return 0;
    (void)bnext;

    size_t cname_voff = 0U, cname_vlen = 0U, realm_voff = 0U, realm_vlen = 0U;
    size_t body_end = bvoff + bvlen;
    for (size_t pos = bvoff; pos < body_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!argos_identity_der_tlv(p, body_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa1U) { cname_voff = cv; cname_vlen = cl; }
        else if (ct == 0xa2U) { realm_voff = cv; realm_vlen = cl; }
        pos = cn;
    }
    if (cname_vlen == 0U || realm_vlen == 0U) return 0;

    const unsigned char *realm = NULL; size_t realm_len = 0U;
    if (!argos_identity_kerberos_string(p, realm_voff + realm_vlen, realm_voff,
                                        &realm, &realm_len)) return 0;

    uint8_t pn_tag; size_t pn_voff, pn_vlen, pn_next;
    if (!argos_identity_der_tlv(p, cname_voff + cname_vlen, cname_voff,
                                &pn_tag, &pn_voff, &pn_vlen, &pn_next) ||
        pn_tag != 0x30U) return 0;
    (void)pn_next;

    size_t names_voff = 0U, names_vlen = 0U;
    size_t pn_end = pn_voff + pn_vlen;
    for (size_t pos = pn_voff; pos < pn_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!argos_identity_der_tlv(p, pn_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa1U) { names_voff = cv; names_vlen = cl; break; }
        pos = cn;
    }
    if (names_vlen == 0U) return 0;

    uint8_t names_tag; size_t nvoff, nvlen, nnext;
    if (!argos_identity_der_tlv(p, names_voff + names_vlen, names_voff,
                                &names_tag, &nvoff, &nvlen, &nnext) ||
        names_tag != 0x30U) return 0;
    (void)nnext;

    unsigned char principal[161]; size_t used = 0U; unsigned components = 0U;
    size_t names_end = nvoff + nvlen;
    for (size_t pos = nvoff; pos < names_end; ) {
        uint8_t st; size_t sv, sl, sn;
        if (!argos_identity_der_tlv(p, names_end, pos, &st, &sv, &sl, &sn)) return 0;
        if (st != 0x1bU || sl == 0U) return 0;
        if (components >= 8U || sl > 120U) return 0;
        size_t need = sl + (components ? 1U : 0U);
        if (need > 160U - used) return 0;
        if (components) principal[used++] = (unsigned char)'/';
        memcpy(principal + used, p + sv, sl); used += sl; components++;
        pos = sn;
    }
    if (components == 0U || realm_len > 120U || realm_len + 1U > 160U - used) return 0;
    principal[used++] = (unsigned char)'@';
    memcpy(principal + used, realm, realm_len); used += realm_len;

    return argos_identity_build(r, "kerberos", "principal", principal, used, raw_mode);
}

#endif
