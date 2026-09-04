#ifndef ARGOS_X509_LEAF_STAGING_H
#define ARGOS_X509_LEAF_STAGING_H

/*
 * Argos Sniffer v6 — bounded X.509 leaf metadata staging parser
 *
 * STAGING ONLY:
 * - not included by production code;
 * - no telemetry/state/dispatcher integration;
 * - no heap allocation;
 * - bounded DER walking only;
 * - extracts compact metadata useful for passive service fingerprinting.
 *
 * This is intentionally not a general ASN.1/X.509 library. It recognizes only
 * the certificate structures required for bounded CN/issuer/validity/SAN
 * metadata. Unsupported encodings fail closed or simply omit optional fields.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_X509_NAME_MAX 96U
#define ARGOS_X509_TIME_MAX 20U
#define ARGOS_X509_SAN_MAX  4U
#define ARGOS_X509_SAN_LEN   96U

typedef struct {
    char subject_cn[ARGOS_X509_NAME_MAX];
    char issuer_cn[ARGOS_X509_NAME_MAX];
    char not_before[ARGOS_X509_TIME_MAX];
    char not_after[ARGOS_X509_TIME_MAX];
    char san_dns[ARGOS_X509_SAN_MAX][ARGOS_X509_SAN_LEN];
    uint8_t san_count;
    uint8_t san_truncated;
    uint8_t self_signed_hint;
    uint8_t has_subject_cn;
    uint8_t has_issuer_cn;
    uint8_t has_validity;
    uint8_t has_san;
} argos_x509_leaf_staging_result_t;

typedef struct {
    const uint8_t *value;
    size_t value_len;
    uint8_t tag;
    size_t total_len;
} argos_x509_tlv_t;

static inline int argos_x509_read_len(const uint8_t *p, size_t len, size_t *hdr, size_t *value_len)
{
    if (!p || len < 2U || !hdr || !value_len) return 0;
    if ((p[1] & 0x80U) == 0U) {
        *hdr = 2U;
        *value_len = (size_t)p[1];
        return *value_len <= len - *hdr;
    }

    {
        size_t n = (size_t)(p[1] & 0x7fU);
        size_t v = 0U;
        if (n == 0U || n > sizeof(size_t) || 2U + n > len) return 0;
        if (n > 4U) return 0; /* staging bound: DER items >4 GiB are irrelevant */
        for (size_t i = 0; i < n; ++i) v = (v << 8) | (size_t)p[2U + i];
        *hdr = 2U + n;
        *value_len = v;
        return v <= len - *hdr;
    }
}

static inline int argos_x509_read_tlv(const uint8_t *p, size_t len, argos_x509_tlv_t *out)
{
    size_t hdr, vlen;
    if (!p || !out || len < 2U) return 0;
    if (!argos_x509_read_len(p, len, &hdr, &vlen)) return 0;
    out->tag = p[0];
    out->value = p + hdr;
    out->value_len = vlen;
    out->total_len = hdr + vlen;
    return 1;
}

static inline void argos_x509_copy_printable(const uint8_t *p, size_t len, char *out, size_t out_len)
{
    size_t n;
    if (!out || out_len == 0U) return;
    if (!p) { out[0] = '\0'; return; }
    n = len < out_len - 1U ? len : out_len - 1U;
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = p[i];
        out[i] = (c >= 0x20U && c <= 0x7eU && c != (uint8_t)'|') ? (char)c : '_';
    }
    out[n] = '\0';
}

static inline int argos_x509_oid_is_cn(const uint8_t *p, size_t len)
{
    static const uint8_t oid[] = {0x55,0x04,0x03}; /* 2.5.4.3 */
    return len == sizeof(oid) && memcmp(p, oid, sizeof(oid)) == 0;
}

static inline int argos_x509_oid_is_san(const uint8_t *p, size_t len)
{
    static const uint8_t oid[] = {0x55,0x1d,0x11}; /* 2.5.29.17 */
    return len == sizeof(oid) && memcmp(p, oid, sizeof(oid)) == 0;
}

static inline void argos_x509_parse_name_cn(const uint8_t *p, size_t len, char *out, size_t out_len)
{
    size_t pos = 0U;
    if (!p || !out || out_len == 0U) return;
    out[0] = '\0';

    while (pos < len) {
        argos_x509_tlv_t set;
        if (!argos_x509_read_tlv(p + pos, len - pos, &set)) return;
        pos += set.total_len;
        if (set.tag != 0x31U) continue;

        size_t spos = 0U;
        while (spos < set.value_len) {
            argos_x509_tlv_t seq;
            if (!argos_x509_read_tlv(set.value + spos, set.value_len - spos, &seq)) break;
            spos += seq.total_len;
            if (seq.tag != 0x30U) continue;

            argos_x509_tlv_t oid, value;
            if (!argos_x509_read_tlv(seq.value, seq.value_len, &oid) || oid.tag != 0x06U) continue;
            if (oid.total_len >= seq.value_len) continue;
            if (!argos_x509_oid_is_cn(oid.value, oid.value_len)) continue;
            if (!argos_x509_read_tlv(seq.value + oid.total_len, seq.value_len - oid.total_len, &value)) continue;
            if (value.tag == 0x0cU || value.tag == 0x13U || value.tag == 0x16U || value.tag == 0x14U) {
                argos_x509_copy_printable(value.value, value.value_len, out, out_len);
                return;
            }
        }
    }
}

static inline void argos_x509_parse_san_octet(const uint8_t *p, size_t len, argos_x509_leaf_staging_result_t *out)
{
    argos_x509_tlv_t seq;
    size_t pos = 0U;
    if (!p || !out || !argos_x509_read_tlv(p, len, &seq) || seq.tag != 0x30U) return;

    while (pos < seq.value_len) {
        argos_x509_tlv_t gn;
        if (!argos_x509_read_tlv(seq.value + pos, seq.value_len - pos, &gn)) return;
        pos += gn.total_len;
        if (gn.tag != 0x82U) continue; /* dNSName [2] IA5String */
        if (out->san_count < ARGOS_X509_SAN_MAX) {
            argos_x509_copy_printable(gn.value, gn.value_len,
                                      out->san_dns[out->san_count], ARGOS_X509_SAN_LEN);
            out->san_count++;
            out->has_san = 1U;
        } else {
            out->san_truncated = 1U;
        }
    }
}

static inline int argos_x509_leaf_staging_parse(const uint8_t *der, size_t len,
                                                argos_x509_leaf_staging_result_t *out)
{
    argos_x509_tlv_t cert, tbs;
    size_t pos = 0U;
    const uint8_t *issuer_ptr = NULL, *subject_ptr = NULL;
    size_t issuer_len = 0U, subject_len = 0U;

    if (!der || !out) return 0;
    memset(out, 0, sizeof(*out));

    if (!argos_x509_read_tlv(der, len, &cert) || cert.tag != 0x30U) return 0;
    if (cert.total_len > len) return 0;
    if (!argos_x509_read_tlv(cert.value, cert.value_len, &tbs) || tbs.tag != 0x30U) return 0;

    /* TBSCertificate: optional [0] version, serial, signature, issuer, validity, subject, SPKI... */
    if (pos >= tbs.value_len) return 0;
    {
        argos_x509_tlv_t item;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &item)) return 0;
        if (item.tag == 0xa0U) pos += item.total_len;
    }

    /* serialNumber */
    {
        argos_x509_tlv_t item;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &item)) return 0;
        pos += item.total_len;
    }
    /* signature */
    {
        argos_x509_tlv_t item;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &item)) return 0;
        pos += item.total_len;
    }
    /* issuer */
    {
        argos_x509_tlv_t item;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &item) || item.tag != 0x30U) return 0;
        issuer_ptr = item.value; issuer_len = item.value_len;
        argos_x509_parse_name_cn(item.value, item.value_len, out->issuer_cn, sizeof(out->issuer_cn));
        out->has_issuer_cn = out->issuer_cn[0] != '\0';
        pos += item.total_len;
    }
    /* validity */
    {
        argos_x509_tlv_t validity, nb, na;
        size_t vpos = 0U;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &validity) || validity.tag != 0x30U) return 0;
        if (argos_x509_read_tlv(validity.value + vpos, validity.value_len - vpos, &nb) &&
            (nb.tag == 0x17U || nb.tag == 0x18U)) {
            argos_x509_copy_printable(nb.value, nb.value_len, out->not_before, sizeof(out->not_before));
            vpos += nb.total_len;
            if (vpos < validity.value_len &&
                argos_x509_read_tlv(validity.value + vpos, validity.value_len - vpos, &na) &&
                (na.tag == 0x17U || na.tag == 0x18U)) {
                argos_x509_copy_printable(na.value, na.value_len, out->not_after, sizeof(out->not_after));
                out->has_validity = 1U;
            }
        }
        pos += validity.total_len;
    }
    /* subject */
    {
        argos_x509_tlv_t item;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &item) || item.tag != 0x30U) return 0;
        subject_ptr = item.value; subject_len = item.value_len;
        argos_x509_parse_name_cn(item.value, item.value_len, out->subject_cn, sizeof(out->subject_cn));
        out->has_subject_cn = out->subject_cn[0] != '\0';
        pos += item.total_len;
    }

    out->self_signed_hint = (issuer_len == subject_len && issuer_ptr && subject_ptr &&
                             memcmp(issuer_ptr, subject_ptr, issuer_len) == 0) ? 1U : 0U;

    /* Skip SPKI then search only the bounded remainder for Extensions [3]. */
    {
        argos_x509_tlv_t spki;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &spki)) return 1;
        pos += spki.total_len;
    }

    while (pos < tbs.value_len) {
        argos_x509_tlv_t item;
        if (!argos_x509_read_tlv(tbs.value + pos, tbs.value_len - pos, &item)) break;
        pos += item.total_len;
        if (item.tag != 0xa3U) continue;

        argos_x509_tlv_t extseq;
        if (!argos_x509_read_tlv(item.value, item.value_len, &extseq) || extseq.tag != 0x30U) break;
        size_t epos = 0U;
        while (epos < extseq.value_len) {
            argos_x509_tlv_t ext;
            if (!argos_x509_read_tlv(extseq.value + epos, extseq.value_len - epos, &ext) || ext.tag != 0x30U) break;
            epos += ext.total_len;

            size_t xpos = 0U;
            argos_x509_tlv_t oid;
            if (!argos_x509_read_tlv(ext.value + xpos, ext.value_len - xpos, &oid) || oid.tag != 0x06U) continue;
            xpos += oid.total_len;
            if (xpos < ext.value_len && ext.value[xpos] == 0x01U) {
                argos_x509_tlv_t critical;
                if (!argos_x509_read_tlv(ext.value + xpos, ext.value_len - xpos, &critical)) continue;
                xpos += critical.total_len;
            }
            argos_x509_tlv_t octet;
            if (!argos_x509_read_tlv(ext.value + xpos, ext.value_len - xpos, &octet) || octet.tag != 0x04U) continue;
            if (argos_x509_oid_is_san(oid.value, oid.value_len))
                argos_x509_parse_san_octet(octet.value, octet.value_len, out);
        }
        break;
    }

    return 1;
}

#endif /* ARGOS_X509_LEAF_STAGING_H */
