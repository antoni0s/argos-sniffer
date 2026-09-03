from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

path=Path('src/argos_enterprise.h')
s=path.read_text()
old=r'''static inline int ae_snmp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
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

'''
s=replace_once(s,old,'','remove old SNMP parser')
marker=r'''static inline int ae_der_int32(const unsigned char *p, size_t n, int32_t *out) {
    if (!p || !out || n == 0U || n > 4U) return 0;
    int32_t v = (p[0] & 0x80U) ? -1 : 0;
    for (size_t i = 0; i < n; ++i) v = (int32_t)((uint32_t)v << 8 | p[i]);
    *out = v;
    return 1;
}

'''
new=marker+r'''static inline uint32_t ae_hash_bytes32(const unsigned char *p, size_t n) {
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
    if (security_model != 3) return 0; pos=hn;

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
            if (w<0 || (size_t)w>=sizeof(value)-used) break; used+=(size_t)w;
        }
    }
    ae_set(r,"snmp",0,"%s=%s",label,value[0]?value:"-");
    return 1;
}

'''
s=replace_once(s,marker,new,'insert SNMPv3 parser')
path.write_text(s)

Path('tests/test_snmpv3_engineid.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static size_t tlv(unsigned char *o,size_t p,unsigned t,const unsigned char *v,size_t n){assert(n<128);o[p++]=(unsigned char)t;o[p++]=(unsigned char)n;memcpy(o+p,v,n);return p+n;}
static size_t integer(unsigned char *o,size_t p,unsigned v){unsigned char b[4];size_t n=1;if(v>0xffffff)n=4;else if(v>0xffff)n=3;else if(v>0xff)n=2;for(size_t i=0;i<n;i++)b[n-1-i]=(unsigned char)(v>>(8*i));if(b[0]&0x80){unsigned char z[5]={0};memcpy(z+1,b,n);return tlv(o,p,0x02,z,n+1);}return tlv(o,p,0x02,b,n);}

int main(void){
    unsigned char usm_body[128]={0};size_t u=0;
    unsigned char engine[]={0x80,0x00,0x02,0xb8,0x03,0x00,0x11,0x22,0x33,0x44,0x55};
    u=tlv(usm_body,u,0x04,engine,sizeof(engine));u=integer(usm_body,u,7);u=integer(usm_body,u,321);
    u=tlv(usm_body,u,0x04,(const unsigned char*)"private-user",12);
    unsigned char auth[12]={1,2,3};u=tlv(usm_body,u,0x04,auth,sizeof(auth));
    unsigned char priv[8]={4,5,6};u=tlv(usm_body,u,0x04,priv,sizeof(priv));
    unsigned char usm_seq[160];size_t us=tlv(usm_seq,0,0x30,usm_body,u);

    unsigned char hdr_body[64]={0};size_t h=0;h=integer(hdr_body,h,123);h=integer(hdr_body,h,65535);
    unsigned char flags=0x07;h=tlv(hdr_body,h,0x04,&flags,1);h=integer(hdr_body,h,3);
    unsigned char hdr[80];size_t hs=tlv(hdr,0,0x30,hdr_body,h);

    unsigned char body[320]={0};size_t b=0;b=integer(body,b,3);memcpy(body+b,hdr,hs);b+=hs;b=tlv(body,b,0x04,usm_seq,us);
    unsigned char msg[360];size_t m=tlv(msg,0,0x30,body,b);

    argos_enterprise_result_t r;
    assert(ae_snmp(msg,(int)m,&r)==1 && r.emit);
    assert(strcmp(r.proto,"snmpv3-usm")==0);
    assert(strstr(r.detail,"engine_len=11") && strstr(r.detail,"enterprise=696") && strstr(r.detail,"format=3"));
    assert(strstr(r.detail,"boots=7") && strstr(r.detail,"time=321"));
    assert(strstr(r.detail,"auth=1") && strstr(r.detail,"priv=1") && strstr(r.detail,"reportable=1"));
    assert(strstr(r.detail,"user_present=1"));
    assert(strstr(r.detail,"private-user")==NULL);
    assert(strstr(r.detail,"800002b8")==NULL);

    unsigned char discovery[360];memcpy(discovery,msg,m);
    /* standalone USM parser must reject an empty EngineID discovery request */
    unsigned char empty_usm[64]={0};size_t e=0;e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);e=integer(empty_usm,e,0);e=integer(empty_usm,e,0);e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);e=tlv(empty_usm,e,0x04,(const unsigned char*)"",0);
    unsigned char empty_seq[80];size_t es=tlv(empty_seq,0,0x30,empty_usm,e);
    unsigned char body2[160]={0};size_t b2=0;b2=integer(body2,b2,3);memcpy(body2+b2,hdr,hs);b2+=hs;b2=tlv(body2,b2,0x04,empty_seq,es);unsigned char msg2[200];size_t m2=tlv(msg2,0,0x30,body2,b2);
    assert(ae_snmp_v3_usm(msg2,m2,&r)==0);
    puts("SNMPv3 EngineID fixtures: PASS");
    return 0;
}
''')
