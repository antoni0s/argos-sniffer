from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

pp=Path('src/argos_enterprise_ports.h'); p=pp.read_text()
p=replace_once(p,
'''    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 3478, 5060, 5678, 47808, 44818\n''',
'''    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 3478, 5060, 5678, 5683, 47808, 44818\n''','CoAP UDP 5683 admission')
pp.write_text(p)

ep=Path('src/argos_enterprise.h'); e=ep.read_text()
marker='''static inline int argos_enterprise_parse_udp(uint16_t sport, uint16_t dport,\n'''
parser=r'''static inline const char *ae_coap_type(unsigned t) {
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

'''
e=replace_once(e,marker,parser+marker,'CoAP parser insertion')
e=replace_once(e,
'''        case 5678: return ae_mndp(p, len, r);\n        case 47808: return ae_bacnet(p, len, r);\n''',
'''        case 5678: return ae_mndp(p, len, r);\n        case 5683: return ae_coap(p, len, r);\n        case 47808: return ae_bacnet(p, len, r);\n''','CoAP UDP dispatch')
ep.write_text(e)

Path('tests/test_coap.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

int main(void){
    argos_enterprise_result_t r;
    /* CON GET, TKL=2, token opaque, Uri-Path "sensors"/"temp", Content-Format=50, payload. */
    unsigned char p[]={0x42,0x01,0x12,0x34,0xaa,0xbb,
                       0xb7,'s','e','n','s','o','r','s',
                       0x04,'t','e','m','p',
                       0x11,50,
                       0xff,'S','E','C','R','E','T'};
    assert(ae_coap(p,(int)sizeof(p),&r)==1 && r.emit);
    assert(strcmp(r.proto,"coap")==0);
    assert(strstr(r.detail,"type=CON") && strstr(r.detail,"code=0.01") && strstr(r.detail,"method=GET"));
    assert(strstr(r.detail,"token_len=2") && strstr(r.detail,"uri_path_segments=2"));
    assert(strstr(r.detail,"content_format=50") && strstr(r.detail,"payload=1"));
    assert(strstr(r.detail,"sensors")==NULL && strstr(r.detail,"temp")==NULL && strstr(r.detail,"SECRET")==NULL);

    unsigned char q[]={0x50,0x45,0x00,0x01}; /* NON 2.05 response */
    assert(ae_coap(q,(int)sizeof(q),&r)==1 && strstr(r.detail,"type=NON") && strstr(r.detail,"code=2.05"));
    assert(strstr(r.detail,"content_format=-") && strstr(r.detail,"accept=-"));

    p[0]=0x02; assert(ae_coap(p,(int)sizeof(p),&r)==0); /* wrong version */
    p[0]=0x49; assert(ae_coap(p,(int)sizeof(p),&r)==0); /* reserved TKL */
    puts("CoAP fixtures: PASS"); return 0;
}
''')

bp=Path('tests/test_dynamic_bpf.c'); b=bp.read_text()
b=replace_once(b,
'''    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");\n''',
'''    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");\n    expect(pass(&p, pkt, udp4(pkt, 50000, 5683, 20)), "CoAP UDP/5683 passes");\n    expect(!pass(&p, pkt, udp4(pkt, 50000, 5684, 20)), "CoAPS UDP/5684 stays out of plaintext enterprise parser");\n''','CoAP BPF matrix')
bp.write_text(b)
