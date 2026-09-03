from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

path=Path('src/argos_enterprise.h')
s=path.read_text()
old=r'''static inline int ae_cldap(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    const unsigned char *d = ae_find_ci(p, len, "DnsDomain");
    const unsigned char *n = ae_find_ci(p, len, "NtVer");
    if (!d && !n) return 0;
    ae_set(r, "cldap-netlogon", 0, "locator-query dns-domain=%s ntver=%s",
           d ? "present" : "-", n ? "present" : "-");
    return 1;
}
'''
new=r'''static inline int ae_ascii_equal_ci(const unsigned char *p, size_t n, const char *s) {
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
                           (strcasecmp(names[6], names[7]) == 0 ? "same" : "different");
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
'''
s=replace_once(s,old,new,'CLDAP parser')
# strcasecmp is POSIX; avoid a new dependency by use hash equality for site relation.
s=s.replace('(strcasecmp(names[6], names[7]) == 0 ? "same" : "different")',
            '(ae_hash_ci32(names[6]) == ae_hash_ci32(names[7]) ? "same" : "different")')
path.write_text(s)

Path('tests/test_cldap_netlogon.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void le16(unsigned char *p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);}
static void le32(unsigned char *p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);}
static size_t dns(unsigned char *p,size_t pos,const char *s){
    const char *q=s;
    while(*q){const char *dot=strchr(q,'.');size_t l=dot?(size_t)(dot-q):strlen(q);assert(l<=63);p[pos++]=(unsigned char)l;memcpy(p+pos,q,l);pos+=l;if(!dot)break;q=dot+1;}
    p[pos++]=0;return pos;
}
static size_t putlen(unsigned char *p,size_t pos,size_t n){if(n<128){p[pos++]=(unsigned char)n;}else{assert(n<256);p[pos++]=0x81;p[pos++]=(unsigned char)n;}return pos;}
static size_t tlv(unsigned char *out,size_t pos,unsigned tag,const unsigned char *v,size_t n){out[pos++]=(unsigned char)tag;pos=putlen(out,pos,n);memcpy(out+pos,v,n);return pos+n;}

int main(void){
    unsigned char nl[512]={0}; size_t np=24;
    le16(nl,23); le16(nl+2,0); le32(nl+4,0x000003fdU);
    np=dns(nl,np,"forest.example"); np=dns(nl,np,"corp.example"); np=dns(nl,np,"dc01.corp.example");
    np=dns(nl,np,"CORP"); np=dns(nl,np,"DC01"); np=dns(nl,np,"alice");
    np=dns(nl,np,"Site-A"); np=dns(nl,np,"Branch-1");
    le32(nl+np,0x00000005U); np+=4; le16(nl+np,0xffff);np+=2;le16(nl+np,0xffff);np+=2;

    argos_enterprise_result_t r;
    assert(ae_cldap_netlogon_ex(nl,np,&r)==1 && r.emit);
    assert(strstr(r.detail,"response_ex opcode=23"));
    assert(strstr(r.detail,"flags=0x000003fd") && strstr(r.detail,"ntver=0x00000005"));
    assert(strstr(r.detail,"site_relation=different"));
    assert(strstr(r.detail,"Site-A")==NULL && strstr(r.detail,"Branch-1")==NULL);
    assert(strstr(r.detail,"alice")==NULL && strstr(r.detail,"dc01")==NULL && strstr(r.detail,"corp.example")==NULL);

    unsigned char valset[640], pa[700], attrs[740], entry[800], outer[900]; size_t n;
    n=0; n=tlv(valset,n,0x04,nl,np);
    size_t ppos=0; ppos=tlv(pa,ppos,0x04,(const unsigned char*)"netlogon",8); ppos=tlv(pa,ppos,0x31,valset,n);
    size_t alen=0; alen=tlv(attrs,alen,0x30,pa,ppos);
    size_t elen=0; elen=tlv(entry,elen,0x04,(const unsigned char*)"",0); elen=tlv(entry,elen,0x30,attrs,alen);
    unsigned char body[850]; size_t blen=0; unsigned char mid[3]={0x02,0x01,0x01}; memcpy(body+blen,mid,3);blen+=3; blen=tlv(body,blen,0x64,entry,elen);
    size_t olen=0; olen=tlv(outer,olen,0x30,body,blen);
    assert(ae_cldap(outer,(int)olen,&r)==1);
    assert(strstr(r.detail,"response_ex opcode=23") && strstr(r.detail,"dc_site_hash="));

    nl[np-1]=0; nl[np-2]=0; assert(ae_cldap_netlogon_ex(nl,np,&r)==0);
    puts("CLDAP Netlogon fixtures: PASS");
    return 0;
}
''')
