from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


hdr = r'''#ifndef ARGOS_LLDP_MED_H
#define ARGOS_LLDP_MED_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int have_capabilities;
    uint16_t capabilities;
    uint8_t device_class;
    int have_policy;
    uint8_t app_type;
    uint8_t policy_unknown;
    uint8_t policy_tagged;
    uint16_t vlan;
    uint8_t priority;
    uint8_t dscp;
    char hardware[64];
    char firmware[64];
    char software[64];
    char serial[64];
    char manufacturer[96];
    char model[96];
    char asset[64];
    char detail[640];
} argos_lldp_med_result_t;

static inline uint16_t alm_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t alm_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void alm_text(const unsigned char *p, size_t n, char *out, size_t cap) {
    if (!out || cap == 0U) return;
    size_t take = n < cap - 1U ? n : cap - 1U;
    for (size_t i = 0; i < take; ++i) {
        unsigned char c = p[i];
        out[i] = (char)((c >= 0x20U && c <= 0x7eU && c != '|' && c != ';') ? c : ' ');
    }
    while (take > 0U && out[take - 1U] == ' ') --take;
    out[take] = '\0';
}
static inline const char *alm_class(uint8_t v) {
    switch (v) {
        case 1: return "endpoint1";
        case 2: return "endpoint2";
        case 3: return "endpoint3";
        case 4: return "network";
        default: return "unknown";
    }
}
static inline const char *alm_app(uint8_t v) {
    switch (v) {
        case 1: return "voice";
        case 2: return "voice-signaling";
        case 3: return "guest-voice";
        case 4: return "guest-voice-signaling";
        case 5: return "softphone-voice";
        case 6: return "video-conferencing";
        case 7: return "streaming-video";
        case 8: return "video-signaling";
        default: return "reserved";
    }
}
static inline void alm_append(char *out, size_t cap, const char *key, const char *value) {
    if (!out || !key || !value || !value[0] || cap == 0U) return;
    size_t used = strlen(out);
    if (used >= cap - 1U) return;
    (void)snprintf(out + used, cap - used, "%s%s=%s", used ? ";" : "", key, value);
}

/* ANSI/TIA-1057 LLDP-MED organizational TLVs use OUI 00-12-BB. Location
 * Identification (subtype 3) is deliberately ignored: Argos fingerprints
 * equipment and policy, not physical/civic location. Power TLV subtype 4 is
 * likewise left for a later PoE-specific vector. */
static inline int argos_lldp_med_parse(const unsigned char *p, size_t n,
                                       argos_lldp_med_result_t *r) {
    if (!p || !r) return 0;
    memset(r, 0, sizeof(*r));
    size_t pos = 0U;
    while (pos + 2U <= n) {
        uint16_t h = alm_be16(p + pos); pos += 2U;
        unsigned type = h >> 9;
        size_t len = h & 0x01ffU;
        if (type == 0U) break;
        if (len > n - pos) return 0;
        if (type == 127U && len >= 4U &&
            p[pos] == 0x00U && p[pos + 1U] == 0x12U && p[pos + 2U] == 0xbbU) {
            uint8_t subtype = p[pos + 3U];
            const unsigned char *v = p + pos + 4U;
            size_t vlen = len - 4U;
            if (subtype == 1U && vlen >= 3U) {
                r->seen = 1; r->have_capabilities = 1;
                r->capabilities = alm_be16(v);
                r->device_class = v[2];
            } else if (subtype == 2U && vlen == 4U && !r->have_policy) {
                uint32_t w = alm_be32(v);
                r->seen = 1; r->have_policy = 1;
                r->app_type = (uint8_t)(w >> 24);
                r->policy_unknown = (uint8_t)((w >> 23) & 1U);
                r->policy_tagged = (uint8_t)((w >> 22) & 1U);
                r->vlan = (uint16_t)((w >> 9) & 0x0fffU);
                r->priority = (uint8_t)((w >> 6) & 0x07U);
                r->dscp = (uint8_t)(w & 0x3fU);
            } else if (subtype >= 5U && subtype <= 11U && vlen > 0U) {
                r->seen = 1;
                char *dst = subtype == 5U ? r->hardware : subtype == 6U ? r->firmware :
                            subtype == 7U ? r->software : subtype == 8U ? r->serial :
                            subtype == 9U ? r->manufacturer : subtype == 10U ? r->model : r->asset;
                size_t cap = subtype == 9U || subtype == 10U ? 96U : 64U;
                if (!dst[0]) alm_text(v, vlen, dst, cap);
            }
        }
        pos += len;
    }
    if (!r->seen) return 0;

    char tmp[160];
    if (r->have_capabilities) {
        snprintf(tmp, sizeof(tmp), "%s", alm_class(r->device_class));
        alm_append(r->detail, sizeof(r->detail), "class", tmp);
        snprintf(tmp, sizeof(tmp), "0x%04x", (unsigned)r->capabilities);
        alm_append(r->detail, sizeof(r->detail), "caps", tmp);
    }
    if (r->have_policy) {
        snprintf(tmp, sizeof(tmp), "%s,%s,%s,vlan=%u,prio=%u,dscp=%u",
                 alm_app(r->app_type), r->policy_unknown ? "unknown" : "defined",
                 r->policy_tagged ? "tagged" : "untagged", (unsigned)r->vlan,
                 (unsigned)r->priority, (unsigned)r->dscp);
        alm_append(r->detail, sizeof(r->detail), "policy", tmp);
    }
    alm_append(r->detail, sizeof(r->detail), "manufacturer", r->manufacturer);
    alm_append(r->detail, sizeof(r->detail), "model", r->model);
    alm_append(r->detail, sizeof(r->detail), "hardware", r->hardware);
    alm_append(r->detail, sizeof(r->detail), "firmware", r->firmware);
    alm_append(r->detail, sizeof(r->detail), "software", r->software);
    alm_append(r->detail, sizeof(r->detail), "serial", r->serial);
    alm_append(r->detail, sizeof(r->detail), "asset", r->asset);
    return r->detail[0] != '\0';
}

#endif /* ARGOS_LLDP_MED_H */
'''
Path('src/argos_lldp_med.h').write_text(hdr)

p = Path('src/argos_bpf.h')
s = p.read_text()
s = replace_once(s,
    '    if (cfg->enterprise) {\n        EMIT(abpf_pass_ethertype(p, 0x888e)); /* EAPoL */\n',
    '    if (cfg->enterprise) {\n        EMIT(abpf_pass_ethertype(p, 0x88cc)); /* LLDP / LLDP-MED */\n        EMIT(abpf_pass_ethertype(p, 0x888e)); /* EAPoL */\n',
    'enterprise LLDP BPF')
p.write_text(s)

p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_tls_server.h"\n#include "argos_enterprise.h"\n',
    '#include "argos_tls_server.h"\n#include "argos_lldp_med.h"\n#include "argos_enterprise.h"\n',
    'LLDP-MED include')

s = replace_once(s,
    '            if (opt_l2 && l3_proto == 0x88cc) {\n'
    '                parse_lldp(buffer + l3_offset, (int)len - l3_offset, mac_str, routed_str, opt_l2_rl);\n'
    '                continue;\n'
    '            }\n',
    '            if (l3_proto == 0x88cc) {\n'
    '                if (opt_l2)\n'
    '                    parse_lldp(buffer + l3_offset, (int)len - l3_offset, mac_str, routed_str, opt_l2_rl);\n'
    '                if (opt_enterprise) {\n'
    '                    argos_lldp_med_result_t med;\n'
    '                    if (argos_lldp_med_parse(buffer + l3_offset, (size_t)((int)len - l3_offset), &med)) {\n'
    '                        if (!dedup_should_suppress(mac_str, "ENT", med.detail, opt_enterprise_rl))\n'
    '                            emit_telemetry("ENT|%s|-|-|LLDP-MED|%s\\n", mac_str, med.detail);\n'
    '                    }\n'
    '                }\n'
    '                continue;\n'
    '            }\n',
    'LLDP-MED dispatch')
p.write_text(s)

# Functional BPF: enterprise-alone must admit LLDP, while legacy l2 behavior remains.
p = Path('tests/test_dynamic_bpf.c')
s = p.read_text()
anchor = '    puts("dynamic BPF functional matrix: PASS");\n'
insert = r'''    memset(&cfg, 0, sizeof(cfg)); cfg.enterprise = 1;
    expect(argos_bpf_build(&cfg, &p), "enterprise-only BPF builds");
    memset(pkt, 0, sizeof(pkt)); put16(pkt + 12, 0x88cc);
    expect(pass(&p, pkt, 64), "enterprise-only admits LLDP-MED EtherType");

'''
s = replace_once(s, anchor, insert + anchor, 'LLDP-MED BPF fixture')
p.write_text(s)

# Pure parser fixture with Capabilities, Voice policy and inventory. Location TLV
# contains a marker that must not surface in the fingerprint detail.
test = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_lldp_med.h"

static void put16(unsigned char *p, uint16_t v) { p[0]=(unsigned char)(v>>8); p[1]=(unsigned char)v; }
static void put32(unsigned char *p, uint32_t v) { p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v; }
static size_t tlv(unsigned char *p, unsigned type, const unsigned char *v, size_t n) { put16(p,(uint16_t)((type<<9)|n)); memcpy(p+2,v,n); return n+2; }
static size_t med(unsigned char *p, uint8_t subtype, const unsigned char *v, size_t n) { unsigned char b[128]={0x00,0x12,0xbb,0}; b[3]=subtype; memcpy(b+4,v,n); return tlv(p,127,b,n+4); }
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
  unsigned char p[512]={0}; size_t n=0; unsigned char caps[3]={0x00,0x23,0x03};
  n+=med(p+n,1,caps,sizeof(caps));
  unsigned char pol[4]; uint32_t w=(1U<<24)|(1U<<22)|(200U<<9)|(5U<<6)|46U; put32(pol,w); n+=med(p+n,2,pol,4);
  const unsigned char loc[]="SECRET-ROOM-42"; n+=med(p+n,3,loc,sizeof(loc)-1);
  const unsigned char vendor[]="Cisco"; n+=med(p+n,9,vendor,sizeof(vendor)-1);
  const unsigned char model[]="CP-8841"; n+=med(p+n,10,model,sizeof(model)-1);
  const unsigned char fw[]="14.2.1"; n+=med(p+n,6,fw,sizeof(fw)-1);
  put16(p+n,0); n+=2;
  argos_lldp_med_result_t r; expect(argos_lldp_med_parse(p,n,&r),"parse");
  expect(r.device_class==3,"endpoint class III"); expect(r.capabilities==0x0023,"capabilities bitmap");
  expect(r.have_policy && r.app_type==1 && r.policy_tagged && r.vlan==200 && r.priority==5 && r.dscp==46,"voice policy fields");
  expect(strcmp(r.manufacturer,"Cisco")==0 && strcmp(r.model,"CP-8841")==0,"inventory");
  expect(strstr(r.detail,"class=endpoint3")!=NULL,"class detail");
  expect(strstr(r.detail,"policy=voice,defined,tagged,vlan=200,prio=5,dscp=46")!=NULL,"policy detail");
  expect(strstr(r.detail,"SECRET-ROOM-42")==NULL,"location privacy");
  unsigned char bad[8]={0}; put16(bad,(uint16_t)((127U<<9)|6U)); bad[2]=0;bad[3]=0x12;bad[4]=0xbb;bad[5]=2;bad[6]=1;bad[7]=2;
  expect(!argos_lldp_med_parse(bad,sizeof(bad),&r),"truncated MED rejected");
  puts("LLDP-MED fingerprint fixtures: PASS"); return 0;
}
'''
Path('tests/test_lldp_med.c').write_text(test)
print('step7a LLDP-MED patch applied')
