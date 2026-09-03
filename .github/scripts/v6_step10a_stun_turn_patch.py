from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

# Shared port policy ---------------------------------------------------------
pp = Path('src/argos_enterprise_ports.h')
p = pp.read_text()
p = replace_once(p,
'''#include <stdint.h>\n\n/* Single source of truth''',
'''#include <stdint.h>\n\n#define ARGOS_STUN_TURN_UDP_PORT 3478U\n\n/* Single source of truth''',
'STUN/TURN port constant')
p = replace_once(p,
'''    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 5060, 5678, 47808, 44818\n''',
'''    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 3478, 5060, 5678, 47808, 44818\n''',
'STUN/TURN UDP admission')
pp.write_text(p)

# Bounded STUN/TURN parser ---------------------------------------------------
ep = Path('src/argos_enterprise.h')
e = ep.read_text()
marker = '''static inline int argos_enterprise_parse_udp(uint16_t sport, uint16_t dport,\n'''
parser = r'''static inline const char *ae_stun_class(unsigned c) {
    return c == 0U ? "request" : c == 1U ? "indication" :
           c == 2U ? "success" : c == 3U ? "error" : "other";
}

static inline const char *ae_stun_method(unsigned m) {
    switch (m) {
        case 0x001U: return "Binding";
        case 0x003U: return "Allocate";
        case 0x004U: return "Refresh";
        case 0x006U: return "Send";
        case 0x007U: return "Data";
        case 0x008U: return "CreatePermission";
        case 0x009U: return "ChannelBind";
        default: return "Other";
    }
}

/* Privacy/performance-minimized RFC 8489 / RFC 8656 control fingerprint.
 * Transaction IDs and address attributes are never emitted. USERNAME, REALM,
 * NONCE, USERHASH and authentication values remain opaque. TURN Send/Data and
 * DATA attributes carry application payload and are rejected here; Ethernet
 * capture additionally fast-drops Send/Data and ChannelData in classic BPF. */
static inline int ae_stun_turn(const unsigned char *p, int len,
                               argos_enterprise_result_t *r) {
    if (!p || !r || len < 20 || (p[0] & 0xc0U) != 0U) return 0;
    uint16_t type = ae_be16(p);
    uint16_t mlen = ae_be16(p + 2);
    if ((mlen & 3U) != 0U || 20U + (uint32_t)mlen > (uint32_t)len) return 0;
    if (ae_be32(p + 4) != 0x2112a442U) return 0;

    unsigned method = (unsigned)(type & 0x000fU) |
                      (unsigned)((type & 0x00e0U) >> 1) |
                      (unsigned)((type & 0x3e00U) >> 2);
    unsigned cls = (unsigned)((type & 0x0010U) >> 4) |
                   (unsigned)((type & 0x0100U) >> 7);
    /* TURN Send/Data indications are relay payload, not fingerprints. */
    if (method == 0x006U || method == 0x007U) return 0;

    char software[128] = {0};
    uint32_t priority = 0U, lifetime = 0U;
    unsigned use_candidate = 0U, ice_controlled = 0U, ice_controlling = 0U;
    unsigned integrity = 0U, integrity256 = 0U, fingerprint = 0U;
    unsigned requested_transport = 0U, address_family = 0U, channel_present = 0U;

    size_t pos = 20U, end = 20U + (size_t)mlen;
    while (pos < end) {
        if (pos + 4U > end) return 0;
        uint16_t at = ae_be16(p + pos), alen = ae_be16(p + pos + 2U);
        size_t value = pos + 4U;
        size_t padded = ((size_t)alen + 3U) & ~(size_t)3U;
        if (value + padded > end || value + (size_t)alen > end) return 0;
        const unsigned char *v = p + value;
        switch (at) {
            case 0x0008U: integrity = 1U; break;                 /* MESSAGE-INTEGRITY */
            case 0x000cU: if (alen == 4U) channel_present = 1U; break;
            case 0x000dU: if (alen == 4U) lifetime = ae_be32(v); break;
            case 0x0013U: return 0;                             /* DATA: relay payload */
            case 0x0017U: if (alen == 4U) address_family = v[0]; break;
            case 0x0019U: if (alen == 4U) requested_transport = v[0]; break;
            case 0x001cU: integrity256 = 1U; break;              /* MESSAGE-INTEGRITY-SHA256 */
            case 0x0024U: if (alen == 4U) priority = ae_be32(v); break;
            case 0x0025U: if (alen == 0U) use_candidate = 1U; break;
            case 0x8022U:
                if (alen > 0U) {
                    int n = alen > 120U ? 120 : (int)alen;
                    ae_clean(v, n, software, sizeof(software));
                }
                break;
            case 0x8028U: if (alen == 4U) fingerprint = 1U; break;
            case 0x8029U: if (alen == 8U) ice_controlled = 1U; break;
            case 0x802aU: if (alen == 8U) ice_controlling = 1U; break;
            default: break; /* includes all identity/address/auth values */
        }
        pos = value + padded;
    }
    if (pos != end) return 0;

    const char *proto = (method == 0x003U || method == 0x004U ||
                         method == 0x008U || method == 0x009U) ? "turn" : "stun";
    const char *ice = ice_controlled && ice_controlling ? "both" :
                      ice_controlled ? "controlled" : ice_controlling ? "controlling" : "-";
    ae_set(r, proto, 0,
           "method=%s class=%s software=%s priority=%u use_candidate=%u ice=%s integrity=%u integrity_sha256=%u fingerprint=%u requested_transport=%u lifetime=%u address_family=%u channel_present=%u",
           ae_stun_method(method), ae_stun_class(cls), software[0] ? software : "-",
           (unsigned)priority, use_candidate, ice, integrity, integrity256, fingerprint,
           requested_transport, (unsigned)lifetime, address_family, channel_present);
    return 1;
}

'''
e = replace_once(e, marker, parser + marker, 'STUN/TURN parser insertion')
e = replace_once(e,
'''        case 1812: case 1813: return ae_radius(p, len, port, r);\n        case 5060: return ae_sip(p, len, r);\n''',
'''        case 1812: case 1813: return ae_radius(p, len, port, r);\n        case 3478: return ae_stun_turn(p, len, r);\n        case 5060: return ae_sip(p, len, r);\n''',
'STUN/TURN UDP dispatch')
ep.write_text(e)

# Kernel BPF: admit STUN control only, drop TURN relay data ------------------
bp = Path('src/argos_bpf.h')
b = bp.read_text()
b = replace_once(b,
'''        for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i) {\n            ADD(ud, ud_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n            ADD(us, us_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n        }\n''',
'''        for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i) {\n            if (ARGOS_ENTERPRISE_UDP_PORTS[i] == ARGOS_STUN_TURN_UDP_PORT) continue;\n            ADD(ud, ud_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n            ADD(us, us_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);\n        }\n''',
'STUN generic enterprise BPF exclusion')

old_udp = '''        EMIT(abpf_stmt(p, BPF_LDX | BPF_B | BPF_MSH, 14));\n        if (ud_n) {\n'''
new_udp = '''        EMIT(abpf_stmt(p, BPF_LDX | BPF_B | BPF_MSH, 14));\n        size_t stun_dport_ja = (size_t)-1, stun_sport_ja = (size_t)-1;\n        if (cfg->enterprise) {\n            /* UDP/3478 is special: TURN relay data can be an elephant flow.\n             * Jump matched 3478 packets to a small STUN-only admission block\n             * after the generic UDP port checks. */\n            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 16));\n            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ARGOS_STUN_TURN_UDP_PORT, 0, 1));\n            stun_dport_ja = p->len; EMIT(abpf_stmt(p, BPF_JMP | BPF_JA, 0));\n            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 14));\n            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ARGOS_STUN_TURN_UDP_PORT, 0, 1));\n            stun_sport_ja = p->len; EMIT(abpf_stmt(p, BPF_JMP | BPF_JA, 0));\n        }\n        if (ud_n) {\n'''
b = replace_once(b, old_udp, new_udp, 'STUN UDP BPF entry')
old_end = '''        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));\n    }\n\n#undef ADD\n'''
new_end = '''        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));\n        if (cfg->enterprise) {\n            size_t stun_start = p->len;\n            p->code[stun_dport_ja].k = (uint32_t)(stun_start - stun_dport_ja - 1U);\n            p->code[stun_sport_ja].k = (uint32_t)(stun_start - stun_sport_ja - 1U);\n            /* Minimum STUN datagram: 8-byte UDP + 20-byte STUN header. */\n            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 18));\n            EMIT(abpf_jump(p, BPF_JMP | BPF_JGT | BPF_K, 27, 1, 0));\n            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));\n            /* STUN has top two bits 00; ChannelData starts 01 and is dropped. */\n            EMIT(abpf_stmt(p, BPF_LD | BPF_B | BPF_IND, 22));\n            EMIT(abpf_stmt(p, BPF_ALU | BPF_AND | BPF_K, 0xc0));\n            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));\n            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));\n            /* TURN Send/Data indications (0x0016/0x0017) carry relay payload. */\n            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 22));\n            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0x0016, 0, 1));\n            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));\n            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0x0017, 0, 1));\n            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));\n            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));\n        }\n    }\n\n#undef ADD\n'''
b = replace_once(b, old_end, new_end, 'STUN UDP BPF control block')
bp.write_text(b)

# Dynamic BPF regression -----------------------------------------------------
tp = Path('tests/test_dynamic_bpf.c')
t = tp.read_text()
needle = '''    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");\n'''
insert = needle + '''    size_t stun_n = udp4(pkt, 50000, 3478, 32); pkt[42]=0x00; pkt[43]=0x01;\n    expect(pass(&p, pkt, stun_n), "STUN Binding control on UDP/3478 passes");\n    stun_n = udp4(pkt, 3478, 50000, 32); pkt[42]=0x01; pkt[43]=0x01;\n    expect(pass(&p, pkt, stun_n), "STUN response from UDP/3478 passes");\n    stun_n = udp4(pkt, 50000, 3478, 32); pkt[42]=0x40; pkt[43]=0x01;\n    expect(!pass(&p, pkt, stun_n), "TURN ChannelData fast-drops in kernel BPF");\n    stun_n = udp4(pkt, 50000, 3478, 32); pkt[42]=0x00; pkt[43]=0x16;\n    expect(!pass(&p, pkt, stun_n), "TURN Send indication fast-drops in kernel BPF");\n    stun_n = udp4(pkt, 3478, 50000, 32); pkt[42]=0x00; pkt[43]=0x17;\n    expect(!pass(&p, pkt, stun_n), "TURN Data indication fast-drops in kernel BPF");\n    expect(!pass(&p, pkt, udp4(pkt, 50000, 3478, 0)), "short UDP/3478 packet drops");\n'''
t = replace_once(t, needle, insert, 'dynamic BPF STUN matrix')
tp.write_text(t)

# Parser fixtures ------------------------------------------------------------
Path('tests/test_stun_turn.c').write_text(r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void put16(unsigned char *p, uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p, uint32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static size_t attr(unsigned char *p,size_t pos,uint16_t type,const unsigned char *v,size_t n){
    put16(p+pos,type); put16(p+pos+2,(uint16_t)n); if(n) memcpy(p+pos+4,v,n);
    size_t pad=(n+3U)&~3U; if(pad>n) memset(p+pos+4+n,0,pad-n); return pos+4U+pad;
}
static void header(unsigned char *p,uint16_t type,size_t end){
    put16(p,type); put16(p+2,(uint16_t)(end-20U)); put32(p+4,0x2112a442U);
    for(int i=8;i<20;i++) p[i]=(unsigned char)(0xa0+i); /* transaction ID: must stay opaque */
}

int main(void){
    unsigned char p[512]={0}; size_t pos=20; argos_enterprise_result_t r;
    const unsigned char sw[]="libwebrtc/126"; pos=attr(p,pos,0x8022,sw,sizeof(sw)-1);
    unsigned char pr[4]; put32(pr,0x6e0001ffU); pos=attr(p,pos,0x0024,pr,4);
    pos=attr(p,pos,0x0025,NULL,0);
    unsigned char role[8]={1,2,3,4,5,6,7,8}; pos=attr(p,pos,0x802a,role,8);
    unsigned char mi[20]={0}; pos=attr(p,pos,0x0008,mi,20);
    unsigned char fp[4]={0}; pos=attr(p,pos,0x8028,fp,4);
    header(p,0x0001,(size_t)pos);
    assert(ae_stun_turn(p,(int)pos,&r)==1 && r.emit && strcmp(r.proto,"stun")==0);
    assert(strstr(r.detail,"method=Binding class=request"));
    assert(strstr(r.detail,"software=libwebrtc/126"));
    assert(strstr(r.detail,"priority=1845494271") && strstr(r.detail,"use_candidate=1"));
    assert(strstr(r.detail,"ice=controlling") && strstr(r.detail,"integrity=1") && strstr(r.detail,"fingerprint=1"));
    assert(strstr(r.detail,"a8a9aa")==NULL);

    memset(p,0,sizeof(p)); pos=20;
    unsigned char rt[4]={17,0,0,0}; pos=attr(p,pos,0x0019,rt,4);
    unsigned char life[4]; put32(life,600); pos=attr(p,pos,0x000d,life,4);
    unsigned char fam[4]={1,0,0,0}; pos=attr(p,pos,0x0017,fam,4);
    const unsigned char user[]="secret-user"; pos=attr(p,pos,0x0006,user,sizeof(user)-1);
    const unsigned char realm[]="internal.example"; pos=attr(p,pos,0x0014,realm,sizeof(realm)-1);
    const unsigned char nonce[]="private-nonce"; pos=attr(p,pos,0x0015,nonce,sizeof(nonce)-1);
    header(p,0x0003,pos);
    assert(ae_stun_turn(p,(int)pos,&r)==1 && strcmp(r.proto,"turn")==0);
    assert(strstr(r.detail,"method=Allocate class=request"));
    assert(strstr(r.detail,"requested_transport=17") && strstr(r.detail,"lifetime=600") && strstr(r.detail,"address_family=1"));
    assert(strstr(r.detail,"secret-user")==NULL && strstr(r.detail,"internal.example")==NULL && strstr(r.detail,"private-nonce")==NULL);

    /* Relay-data forms are intentionally not fingerprints. */
    memset(p,0,sizeof(p)); header(p,0x0016,20); assert(ae_stun_turn(p,20,&r)==0);
    memset(p,0,sizeof(p)); header(p,0x0017,20); assert(ae_stun_turn(p,20,&r)==0);
    memset(p,0,sizeof(p)); p[0]=0x40; assert(ae_stun_turn(p,20,&r)==0);

    /* Malformed attribute length must fail closed. */
    memset(p,0,sizeof(p)); pos=20; unsigned char x[4]={0}; pos=attr(p,pos,0x0024,x,4); header(p,0x0001,pos);
    p[22]=0xff; p[23]=0xff; assert(ae_stun_turn(p,(int)pos,&r)==0);
    puts("STUN/TURN control fixtures: PASS");
    return 0;
}
''')
