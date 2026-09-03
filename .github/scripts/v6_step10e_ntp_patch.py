from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

pp=Path('src/argos_enterprise_ports.h'); p=pp.read_text()
p=replace_once(p,
'''    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 3478, 5060, 5678, 5683, 47808, 44818\n''',
'''    88, 111, 123, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 3478, 5060, 5678, 5683, 47808, 44818\n''','NTP UDP 123 admission')
pp.write_text(p)

ep=Path('src/argos_enterprise.h'); e=ep.read_text()
marker='''static inline int argos_enterprise_parse_udp(uint16_t sport, uint16_t dport,\n'''
parser=r'''static inline const char *ae_ntp_mode(unsigned mode) {
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

'''
e=replace_once(e,marker,parser+marker,'NTP parser insertion')
e=replace_once(e,
'''        case 111: case 2049: return ae_rpc(p, len, 0, r);\n        case 161: case 162: return ae_snmp(p, len, r);\n''',
'''        case 111: case 2049: return ae_rpc(p, len, 0, r);\n        case 123: return ae_ntp(p, len, r);\n        case 161: case 162: return ae_snmp(p, len, r);\n''','NTP UDP dispatch')
ep.write_text(e)

Path('tests/test_ntp.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

int main(void) {
    argos_enterprise_result_t r;
    unsigned char client[48]={0};
    client[0]=(4U<<3)|3U; /* v4 client */
    assert(ae_ntp(client,sizeof(client),&r)==1 && r.emit);
    assert(strcmp(r.proto,"ntp")==0);
    assert(strstr(r.detail,"version=4") && strstr(r.detail,"mode=client"));
    assert(strstr(r.detail,"stratum=0") && strstr(r.detail,"extra_bytes=0"));

    unsigned char server[68]={0};
    server[0]=(3U<<6)|(4U<<3)|4U; /* alarm, v4 server */
    server[1]=2; server[2]=6; server[3]=(unsigned char)-20;
    memcpy(server+12,"PRIV",4);                 /* Reference ID: must stay opaque */
    memcpy(server+16,"REF-TIME",8);             /* timestamps: must stay opaque */
    assert(ae_ntp(server,sizeof(server),&r)==1);
    assert(strstr(r.detail,"mode=server") && strstr(r.detail,"li=3"));
    assert(strstr(r.detail,"stratum=2") && strstr(r.detail,"poll=6"));
    assert(strstr(r.detail,"precision=-20") && strstr(r.detail,"extra_bytes=20"));
    assert(strstr(r.detail,"PRIV")==NULL && strstr(r.detail,"REF-TIME")==NULL);

    client[0]=(4U<<3)|6U; assert(ae_ntp(client,sizeof(client),&r)==0); /* control mode */
    client[0]=(5U<<3)|3U; assert(ae_ntp(client,sizeof(client),&r)==0); /* unsupported version */
    assert(ae_ntp(server,47,&r)==0);
    puts("NTP fixtures: PASS");
    return 0;
}
''')

bp=Path('tests/test_dynamic_bpf.c'); b=bp.read_text()
b=replace_once(b,
'''    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");\n''',
'''    expect(pass(&p, pkt, udp4(pkt, 50000, 123, 48)), "NTP UDP/123 passes");\n    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");\n''','NTP BPF fixture')
bp.write_text(b)
