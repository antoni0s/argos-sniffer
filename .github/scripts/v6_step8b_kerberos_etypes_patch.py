from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

path=Path('src/argos_enterprise.h')
s=path.read_text()
old=r'''static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r) {
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
'''
new=r'''static inline int ae_der_tlv(const unsigned char *p, size_t n, size_t pos,
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
'''
s=replace_once(s,old,new,'Kerberos parser')
path.write_text(s)

Path('tests/test_kerberos_etypes.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

int main(void) {
    static const unsigned char asreq[] = {
        0x6a,0x1d, 0x30,0x1b,
        0xa1,0x03,0x02,0x01,0x05,
        0xa2,0x03,0x02,0x01,0x0a,
        0xa4,0x0f,0x30,0x0d,0xa8,0x0b,0x30,0x09,
        0x02,0x01,0x12, 0x02,0x01,0x11, 0x02,0x01,0x17
    };
    argos_enterprise_result_t r;
    assert(ae_kerberos(asreq, (int)sizeof(asreq), &r) == 1 && r.emit);
    assert(strstr(r.detail, "request=AS-REQ"));
    assert(strstr(r.detail, "etype_count=3"));
    assert(strstr(r.detail, "etypes=18,17,23"));

    unsigned char tcp[4 + sizeof(asreq)];
    unsigned n=(unsigned)sizeof(asreq);
    tcp[0]=(unsigned char)(n>>24); tcp[1]=(unsigned char)(n>>16); tcp[2]=(unsigned char)(n>>8); tcp[3]=(unsigned char)n;
    memcpy(tcp+4,asreq,sizeof(asreq)); tcp[4]=0x6c; tcp[4+10]=0x0c;
    assert(ae_kerberos(tcp, (int)sizeof(tcp), &r) == 1);
    assert(strstr(r.detail, "request=TGS-REQ") && strstr(r.detail, "etypes=18,17,23"));

    unsigned char bad[sizeof(asreq)]; memcpy(bad,asreq,sizeof(bad));
    bad[18]=0xa7; /* no [8] etype: request still recognized, no false e-types */
    assert(ae_kerberos(bad,(int)sizeof(bad),&r)==1);
    assert(strstr(r.detail,"etype_count=0") && strstr(r.detail,"etypes=-"));

    char out[32]; unsigned count=0;
    assert(ae_kerberos_etypes(asreq,sizeof(asreq),0,out,sizeof(out),&count)==1);
    assert(count==3 && strcmp(out,"18,17,23")==0);
    puts("Kerberos etype fixtures: PASS");
    return 0;
}
''')
