from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

ports_path=Path('src/argos_enterprise_ports.h')
ports=ports_path.read_text()
ports=replace_once(ports,
'''    88, 111, 161, 162, 389, 427, 623, 1985, 2049, 5060, 5678, 47808, 44818\n''',
'''    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 5060, 5678, 47808, 44818\n''',
'enterprise UDP ports')
ports_path.write_text(ports)

ent_path=Path('src/argos_enterprise.h')
ent=ent_path.read_text()
ent=replace_once(ent,
'''#include "argos_enterprise_ports.h"\n''',
'''#include "argos_enterprise_ports.h"\n\n#include <ctype.h>\n#include <stdarg.h>\n#include <stdio.h>\n#include <string.h>\n''',
'enterprise header dependencies')
marker='''static inline int argos_enterprise_parse_udp(uint16_t sport, uint16_t dport,\n'''
radius=r'''static inline const char *ae_radius_code(uint8_t code) {
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

'''
ent=replace_once(ent,marker,radius+marker,'RADIUS insertion')
ent=replace_once(ent,
'''        case 623: return ae_ipmi(p, len, r);\n        case 5060: return ae_sip(p, len, r);\n''',
'''        case 623: return ae_ipmi(p, len, r);\n        case 1812: case 1813: return ae_radius(p, len, port, r);\n        case 5060: return ae_sip(p, len, r);\n''','RADIUS dispatch')
ent_path.write_text(ent)

Path('tests/test_radius.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void put16(unsigned char *p, unsigned v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p, unsigned v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static int attr(unsigned char *p,int pos,unsigned type,const unsigned char *v,unsigned n){p[pos]=(unsigned char)type;p[pos+1]=(unsigned char)(n+2);memcpy(p+pos+2,v,n);return pos+(int)n+2;}

int main(void){
    unsigned char p[256]={0}; int pos=20;
    p[0]=1; p[1]=7;
    const unsigned char user[]="alice@example.org"; pos=attr(p,pos,1,user,sizeof(user)-1);
    unsigned char svc[4]; put32(svc,2); pos=attr(p,pos,6,svc,4);
    unsigned char npt[4]; put32(npt,19); pos=attr(p,pos,61,npt,4);
    const unsigned char call[]="AA-BB-CC-DD-EE-FF"; pos=attr(p,pos,31,call,sizeof(call)-1);
    unsigned char eap[2]={2,1}; pos=attr(p,pos,79,eap,2);
    unsigned char ma[16]={0}; pos=attr(p,pos,80,ma,16);
    unsigned char vsa[4]; put32(vsa,9); pos=attr(p,pos,26,vsa,4);
    put16(p+2,(unsigned)pos);

    argos_enterprise_result_t r;
    assert(ae_radius(p,pos,1812,&r)==1 && r.emit);
    assert(strcmp(r.proto,"radius")==0);
    assert(strstr(r.detail,"plane=auth") && strstr(r.detail,"Access-Request"));
    assert(strstr(r.detail,"service_type=2") && strstr(r.detail,"nas_port_type=19"));
    assert(strstr(r.detail,"eap=1") && strstr(r.detail,"message_auth=1") && strstr(r.detail,"vendor_id=9"));
    assert(strstr(r.detail,"alice")==NULL && strstr(r.detail,"AA-BB")==NULL);

    memset(p,0,sizeof(p)); pos=20; p[0]=4; p[1]=9;
    unsigned char ast[4]; put32(ast,1); pos=attr(p,pos,40,ast,4); put16(p+2,(unsigned)pos);
    assert(ae_radius(p,pos,1813,&r)==1 && strstr(r.detail,"plane=accounting") && strstr(r.detail,"acct_status=1"));

    p[20]=1; p[21]=1; assert(ae_radius(p,pos,1813,&r)==0);
    puts("RADIUS fixtures: PASS");
    return 0;
}
''')
