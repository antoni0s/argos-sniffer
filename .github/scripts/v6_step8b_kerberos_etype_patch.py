from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

ent_path = Path('src/argos_enterprise.h')
ent = ent_path.read_text()
old = r'''static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r) {
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
new = r'''typedef struct {
    uint8_t tag;
    const unsigned char *value;
    size_t len;
    size_t total;
} ae_der_tlv_t;

/* Minimal definite-length DER reader used only for the small Kerberos fields
 * Argos fingerprints. It deliberately does not implement a generic ASN.1
 * decoder and rejects indefinite/oversized lengths. */
static inline int ae_der_read(const unsigned char *p, size_t avail, ae_der_tlv_t *t) {
    if (!p || !t || avail < 2U) return 0;
    size_t hdr = 2U, n = 0U;
    uint8_t lb = p[1];
    if ((lb & 0x80U) == 0U) {
        n = lb;
    } else {
        unsigned octets = (unsigned)(lb & 0x7fU);
        if (octets == 0U || octets > 4U || 2U + octets > avail) return 0;
        hdr = 2U + octets;
        for (unsigned i = 0; i < octets; ++i) n = (n << 8) | p[2U + i];
    }
    if (n > avail - hdr) return 0;
    t->tag = p[0]; t->value = p + hdr; t->len = n; t->total = hdr + n;
    return 1;
}

static inline int ae_der_explicit_int32(const ae_der_tlv_t *outer, int32_t *out) {
    ae_der_tlv_t v;
    if (!outer || !out || !ae_der_read(outer->value, outer->len, &v) ||
        v.tag != 0x02U || v.total != outer->len || v.len == 0U || v.len > 4U) return 0;
    int32_t x = (v.value[0] & 0x80U) ? -1 : 0;
    for (size_t i = 0; i < v.len; ++i) x = (int32_t)((uint32_t)x << 8) | v.value[i];
    *out = x;
    return 1;
}

static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (!p || !r || len < 8) return 0;
    size_t off = 0U;
    uint8_t app_tag = p[0];
    if (app_tag != 0x6aU && app_tag != 0x6cU) {
        if (len < 5) return 0;
        uint32_t record = ae_be32(p);
        if (record == 0U || record > (uint32_t)(len - 4)) return 0;
        off = 4U; app_tag = p[off];
    }
    const char *kind = app_tag == 0x6aU ? "AS-REQ" : app_tag == 0x6cU ? "TGS-REQ" : NULL;
    if (!kind) return 0;

    ae_der_tlv_t app, root;
    if (!ae_der_read(p + off, (size_t)len - off, &app) || app.tag != app_tag) return 0;
    if (!ae_der_read(app.value, app.len, &root) || root.tag != 0x30U || root.total != app.len) return 0;

    int pvno_ok = 0, msg_ok = 0;
    const unsigned char *body_p = NULL; size_t body_n = 0U;
    size_t pos = 0U;
    while (pos < root.len) {
        ae_der_tlv_t f;
        if (!ae_der_read(root.value + pos, root.len - pos, &f)) return 0;
        if (f.tag == 0xa1U) {
            int32_t v = 0; if (ae_der_explicit_int32(&f, &v) && v == 5) pvno_ok = 1;
        } else if (f.tag == 0xa2U) {
            int32_t v = 0;
            if (ae_der_explicit_int32(&f, &v) &&
                ((app_tag == 0x6aU && v == 10) || (app_tag == 0x6cU && v == 12))) msg_ok = 1;
        } else if (f.tag == 0xa4U) {
            ae_der_tlv_t body;
            if (!ae_der_read(f.value, f.len, &body) || body.tag != 0x30U || body.total != f.len) return 0;
            body_p = body.value; body_n = body.len;
        }
        pos += f.total;
    }
    if (!pvno_ok || !msg_ok || !body_p) return 0;

    char realm[128] = {0}, etypes[192] = {0}; size_t used = 0U;
    unsigned etype_count = 0U;
    pos = 0U;
    while (pos < body_n) {
        ae_der_tlv_t f;
        if (!ae_der_read(body_p + pos, body_n - pos, &f)) return 0;
        if (f.tag == 0xa2U && !realm[0]) {
            ae_der_tlv_t s;
            if (ae_der_read(f.value, f.len, &s) && s.tag == 0x1bU && s.total == f.len && s.len > 0U)
                ae_clean(s.value, (int)s.len, realm, sizeof(realm));
        } else if (f.tag == 0xa8U && etype_count == 0U) {
            ae_der_tlv_t seq;
            if (!ae_der_read(f.value, f.len, &seq) || seq.tag != 0x30U || seq.total != f.len) return 0;
            size_t q = 0U;
            while (q < seq.len && etype_count < 16U) {
                ae_der_tlv_t iv;
                if (!ae_der_read(seq.value + q, seq.len - q, &iv) || iv.tag != 0x02U || iv.len == 0U || iv.len > 4U) return 0;
                int32_t x = (iv.value[0] & 0x80U) ? -1 : 0;
                for (size_t i = 0; i < iv.len; ++i) x = (int32_t)((uint32_t)x << 8) | iv.value[i];
                int w = snprintf(etypes + used, sizeof(etypes) - used, "%s%d", used ? "," : "", (int)x);
                if (w < 0 || (size_t)w >= sizeof(etypes) - used) return 0;
                used += (size_t)w; etype_count++; q += iv.total;
            }
            if (q != seq.len || etype_count == 0U) return 0;
        }
        pos += f.total;
    }
    if (etype_count == 0U) return 0;

    /* Only the server realm and ordered encryption preference list are emitted.
     * cname/sname, PA-DATA, tickets and encrypted material remain opaque. */
    ae_set(r, "kerberos", 0, "request=%s realm=%s etypes=%s etype_count=%u",
           kind, realm[0] ? realm : "-", etypes, etype_count);
    return 1;
}
'''
ent = replace_once(ent, old, new, 'Kerberos parser')
ent_path.write_text(ent)

Path('tests/test_kerberos_etype.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static size_t tlv(unsigned char *o, unsigned char tag, const unsigned char *v, size_t n) {
    assert(n < 128U); o[0]=tag; o[1]=(unsigned char)n; memcpy(o+2,v,n); return n+2U;
}
static size_t eint(unsigned char *o, unsigned char ctag, int v) {
    unsigned char iv[3]={0x02,0x01,(unsigned char)v}; return tlv(o,ctag,iv,3U);
}
static size_t make_req(unsigned char *out, unsigned char app, int msg, const char *realm) {
    unsigned char et_inner[32], et_seq[40], et_outer[48]; size_t e=0;
    const int vals[]={18,17,23};
    for(size_t i=0;i<3;i++){ unsigned char iv[3]={0x02,0x01,(unsigned char)vals[i]}; memcpy(et_inner+e,iv,3); e+=3; }
    size_t es=tlv(et_seq,0x30,et_inner,e); size_t eo=tlv(et_outer,0xa8,et_seq,es);

    unsigned char rs[96], ro[104]; size_t rsl=tlv(rs,0x1b,(const unsigned char*)realm,strlen(realm));
    size_t rol=tlv(ro,0xa2,rs,rsl);

    /* Deliberately include a principal-looking token in [1]; parser must ignore it. */
    unsigned char cname_s[32], cname_o[40]; const char *user="alice";
    size_t csl=tlv(cname_s,0x1b,(const unsigned char*)user,strlen(user)); size_t col=tlv(cname_o,0xa1,cname_s,csl);

    unsigned char body_inner[256], body_seq[264], body_outer[272]; size_t b=0;
    memcpy(body_inner+b,cname_o,col); b+=col; memcpy(body_inner+b,ro,rol); b+=rol; memcpy(body_inner+b,et_outer,eo); b+=eo;
    size_t bs=tlv(body_seq,0x30,body_inner,b); size_t bo=tlv(body_outer,0xa4,body_seq,bs);

    unsigned char root_inner[384], root_seq[392]; size_t q=0;
    q += eint(root_inner+q,0xa1,5); q += eint(root_inner+q,0xa2,msg);
    memcpy(root_inner+q,body_outer,bo); q+=bo;
    size_t rsq=tlv(root_seq,0x30,root_inner,q); return tlv(out,app,root_seq,rsq);
}

int main(void) {
    unsigned char p[512]; argos_enterprise_result_t r;
    size_t n=make_req(p,0x6a,10,"EXAMPLE.COM");
    assert(ae_kerberos(p,(int)n,&r)==1 && r.emit);
    assert(strstr(r.detail,"request=AS-REQ") && strstr(r.detail,"realm=EXAMPLE.COM"));
    assert(strstr(r.detail,"etypes=18,17,23") && strstr(r.detail,"etype_count=3"));
    assert(strstr(r.detail,"alice")==NULL);

    unsigned char tcp[520]={0}; tcp[3]=(unsigned char)n; memcpy(tcp+4,p,n);
    assert(ae_kerberos(tcp,(int)n+4,&r)==1 && strstr(r.detail,"AS-REQ"));

    n=make_req(p,0x6c,12,"CORP.LOCAL");
    assert(ae_kerberos(p,(int)n,&r)==1 && strstr(r.detail,"request=TGS-REQ") && strstr(r.detail,"etypes=18,17,23"));

    p[0]=0x6b; assert(ae_kerberos(p,(int)n,&r)==0);
    puts("Kerberos e-type fixtures: PASS");
    return 0;
}
''')
