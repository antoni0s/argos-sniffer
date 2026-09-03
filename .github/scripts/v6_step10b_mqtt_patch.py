from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

# Shared enterprise and TLS port policies -----------------------------------
pp=Path('src/argos_enterprise_ports.h'); p=pp.read_text()
p=replace_once(p,
'''    22, 88, 111, 179, 445, 502, 631, 1433, 1521, 2000, 2049,\n    3260, 3306, 3389, 5060, 5432, 9100, 44818\n''',
'''    22, 88, 111, 179, 445, 502, 631, 1433, 1521, 1883, 2000, 2049,\n    3260, 3306, 3389, 5060, 5432, 9100, 44818\n''','MQTT TCP 1883 admission')
pp.write_text(p)

tp=Path('src/argos_tls_ports.h'); t=tp.read_text()
t=replace_once(t,
'''    995U,   /* POP3S */\n    8443U   /* common alternate HTTPS */\n''',
'''    995U,   /* POP3S */\n    8443U,  /* common alternate HTTPS */\n    8883U   /* MQTT over implicit TLS */\n''','MQTTS TLS 8883 policy')
tp.write_text(t)

# MQTT CONNECT parser --------------------------------------------------------
ep=Path('src/argos_enterprise.h'); e=ep.read_text()
marker='''static inline int ae_rdp(const unsigned char *p, int len, argos_enterprise_result_t *r) {\n'''
parser=r'''static inline int ae_mqtt_varint(const unsigned char *p, int len, int *pos, uint32_t *out) {
    if (!p || !pos || !out || *pos < 0 || *pos >= len) return 0;
    uint32_t value = 0U, mult = 1U;
    for (unsigned i = 0; i < 4U; ++i) {
        if (*pos >= len) return 0;
        uint8_t b = p[(*pos)++];
        value += (uint32_t)(b & 0x7fU) * mult;
        if ((b & 0x80U) == 0U) { *out = value; return 1; }
        mult *= 128U;
    }
    return 0;
}

static inline int ae_mqtt_utf8_span(const unsigned char *p, int end, int *pos,
                                    const unsigned char **s, uint16_t *n) {
    if (!p || !pos || !s || !n || *pos < 0 || *pos + 2 > end) return 0;
    uint16_t l = ae_be16(p + *pos); *pos += 2;
    if (*pos + (int)l > end) return 0;
    *s = p + *pos; *n = l; *pos += (int)l;
    return 1;
}

/* MQTT CONNECT-only fingerprinting. The client identifier can be a stable
 * device/application identifier, so Argos emits only its length and FNV-1a
 * hash. Username, password and Will topic/payload are represented only by
 * presence/flags and are never copied into telemetry. A successful CONNECT
 * parse is marked complete so the existing app-flow DONE path suppresses all
 * later PUBLISH/SUBSCRIBE traffic for that TCP flow. */
static inline int ae_mqtt(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (!p || !r || len < 10 || p[0] != 0x10U) return 0; /* CONNECT, flags=0 */
    int pos = 1; uint32_t rem = 0U;
    if (!ae_mqtt_varint(p, len, &pos, &rem) || rem > (uint32_t)(len - pos)) return 0;
    int end = pos + (int)rem;

    const unsigned char *proto = NULL; uint16_t proto_len = 0U;
    if (!ae_mqtt_utf8_span(p, end, &pos, &proto, &proto_len)) return 0;
    if (!((proto_len == 4U && memcmp(proto,"MQTT",4U)==0) ||
          (proto_len == 6U && memcmp(proto,"MQIsdp",6U)==0))) return 0;
    if (pos + 4 > end) return 0;
    uint8_t level=p[pos++], flags=p[pos++]; uint16_t keepalive=ae_be16(p+pos); pos+=2;
    if (!((proto_len==4U && (level==4U || level==5U)) || (proto_len==6U && level==3U))) return 0;
    if ((flags & 0x01U) != 0U) return 0;
    unsigned clean=(flags & 0x02U)?1U:0U, will=(flags & 0x04U)?1U:0U;
    unsigned will_qos=(flags >> 3) & 0x03U, will_retain=(flags & 0x20U)?1U:0U;
    unsigned password=(flags & 0x40U)?1U:0U, username=(flags & 0x80U)?1U:0U;
    if (will_qos == 3U || (!will && (will_qos || will_retain))) return 0;

    uint32_t property_len=0U;
    if (level == 5U) {
        if (!ae_mqtt_varint(p,end,&pos,&property_len) || property_len > (uint32_t)(end-pos)) return 0;
        pos += (int)property_len;
    }

    const unsigned char *cid=NULL; uint16_t cid_len=0U;
    if (!ae_mqtt_utf8_span(p,end,&pos,&cid,&cid_len)) return 0;
    uint32_t cid_hash=ae_hash_bytes32(cid,cid_len);

    /* Remaining CONNECT payload may contain Will, username and password. We
     * deliberately do not walk/copy those private fields; flags are enough for
     * fingerprinting and the fixed-header Remaining Length already bounded it. */
    const char *version = level==5U ? "5.0" : level==4U ? "3.1.1" : "3.1";
    ae_set(r,"mqtt",1,
           "connect version=%s clean=%u keepalive=%u will=%u will_qos=%u will_retain=%u username_present=%u password_present=%u properties_len=%u client_id_len=%u client_id_hash=%08x",
           version,clean,(unsigned)keepalive,will,will_qos,will_retain,username,password,
           (unsigned)property_len,(unsigned)cid_len,(unsigned)cid_hash);
    return 1;
}

'''
e=replace_once(e,marker,parser+marker,'MQTT parser insertion')
e=replace_once(e,
'''        case 1521: return ae_tns(p, len, r);\n        case 2000: return ae_sccp(p, len, r);\n''',
'''        case 1521: return ae_tns(p, len, r);\n        case 1883: return ae_mqtt(p, len, r);\n        case 2000: return ae_sccp(p, len, r);\n''','MQTT dispatch')
ep.write_text(e)

# Tests ---------------------------------------------------------------------
Path('tests/test_mqtt.c').write_text(r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static size_t putstr(unsigned char *p,size_t pos,const char *s){size_t n=strlen(s);p[pos++]=(unsigned char)(n>>8);p[pos++]=(unsigned char)n;memcpy(p+pos,s,n);return pos+n;}

int main(void){
    unsigned char p[256]={0}; size_t pos=2;
    pos=putstr(p,pos,"MQTT"); p[pos++]=4; p[pos++]=0xc2; p[pos++]=0; p[pos++]=60;
    pos=putstr(p,pos,"device-secret-123");
    /* username/password bytes are private and parser should not inspect them */
    pos=putstr(p,pos,"alice@example.org"); pos=putstr(p,pos,"super-secret");
    p[0]=0x10; p[1]=(unsigned char)(pos-2);
    argos_enterprise_result_t r;
    assert(ae_mqtt(p,(int)pos,&r)==1 && r.emit && r.complete);
    assert(strcmp(r.proto,"mqtt")==0);
    assert(strstr(r.detail,"version=3.1.1") && strstr(r.detail,"clean=1") && strstr(r.detail,"keepalive=60"));
    assert(strstr(r.detail,"username_present=1") && strstr(r.detail,"password_present=1"));
    assert(strstr(r.detail,"client_id_len=17") && strstr(r.detail,"client_id_hash="));
    assert(strstr(r.detail,"device-secret")==NULL && strstr(r.detail,"alice")==NULL && strstr(r.detail,"super-secret")==NULL);

    memset(p,0,sizeof(p)); pos=2; pos=putstr(p,pos,"MQTT"); p[pos++]=5; p[pos++]=0x02; p[pos++]=0; p[pos++]=30;
    p[pos++]=0; /* v5 property length */ pos=putstr(p,pos,"sensor-01"); p[0]=0x10; p[1]=(unsigned char)(pos-2);
    assert(ae_mqtt(p,(int)pos,&r)==1 && strstr(r.detail,"version=5.0") && strstr(r.detail,"properties_len=0"));
    assert(strstr(r.detail,"sensor-01")==NULL);

    p[0]=0x30; assert(ae_mqtt(p,(int)pos,&r)==0); /* PUBLISH ignored */
    p[0]=0x10; p[1]=0xff; assert(ae_mqtt(p,(int)pos,&r)==0); /* truncated varint/remaining length */
    puts("MQTT CONNECT fixtures: PASS");
    return 0;
}
''')

# Add BPF cases: enterprise 1883 payload and TLS-only 8883 payload.
bp=Path('tests/test_dynamic_bpf.c'); b=bp.read_text()
b=replace_once(b,
'''    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 1, 40)), "TCP/44818 destination passes");\n''',
'''    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 1, 40)), "TCP/44818 destination passes");\n    expect(pass(&p, pkt, tcp4(pkt, 50000, 1883, 1, 40)), "MQTT TCP/1883 destination passes");\n''','MQTT enterprise BPF case')
b=replace_once(b,
'''    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 1, 40)), "TCP/8443 payload passes");\n''',
'''    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 1, 40)), "TCP/8443 payload passes");\n    expect(pass(&p, pkt, tcp4(pkt, 50000, 8883, 1, 40)), "MQTTS TCP/8883 payload passes");\n''','MQTTS BPF case')
bp.write_text(b)
