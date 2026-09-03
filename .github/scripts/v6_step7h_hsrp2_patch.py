from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

hdr_path = Path('src/argos_hsrp.h')
hdr = hdr_path.read_text()
old_end = '\n#endif /* ARGOS_HSRP_H */\n'
addition = r'''

typedef struct {
    uint8_t wire_version;
    uint8_t opcode;
    uint8_t state;
    uint8_t ip_version;
    uint16_t group;
    uint32_t priority;
    uint32_t hello_ms;
    uint32_t hold_ms;
    uint8_t identifier[6];
    uint8_t extra_tlvs;
    char detail[320];
} argos_hsrp2_result_t;

static inline uint16_t ahsrp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t ahsrp_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* HSRPv2 uses a TLV payload on UDP/1985. The Group State TLV is type 1,
 * length 40 and carries version/opcode/state/IP-version/group, a six-byte
 * sender identifier, 32-bit priority and millisecond timers. Virtual IP and
 * any following authentication TLVs are intentionally never emitted. */
static inline int argos_hsrp2_parse(const unsigned char *p, size_t n,
                                    argos_hsrp2_result_t *r) {
    if (!p || !r || n < 42U) return 0;
    memset(r, 0, sizeof(*r));

    size_t pos = 0U;
    while (pos + 2U <= n) {
        uint8_t type = p[pos];
        uint8_t len = p[pos + 1U];
        size_t end = pos + 2U + (size_t)len;
        if (end > n) return 0;

        if (type == 1U && len == 40U) {
            const unsigned char *v = p + pos + 2U;
            if (v[0] != 2U || v[1] > 2U) return 0;
            if (v[3] != 4U && v[3] != 6U) return 0;
            uint16_t group = ahsrp_be16(v + 4U);
            if (group > 4095U) return 0;

            r->wire_version = v[0];
            r->opcode = v[1];
            r->state = v[2];
            r->ip_version = v[3];
            r->group = group;
            memcpy(r->identifier, v + 6U, 6U);
            r->priority = ahsrp_be32(v + 12U);
            r->hello_ms = ahsrp_be32(v + 16U);
            r->hold_ms = ahsrp_be32(v + 20U);

            size_t scan = end;
            while (scan + 2U <= n) {
                uint8_t slen = p[scan + 1U];
                size_t send = scan + 2U + (size_t)slen;
                if (send > n) return 0;
                if (r->extra_tlvs != 255U) r->extra_tlvs++;
                scan = send;
            }
            if (scan != n) return 0;

            (void)snprintf(r->detail, sizeof(r->detail),
                "version=2;opcode=%s;state=%s;ip_version=%u;group=%u;priority=%u;hello_ms=%u;hold_ms=%u;id=%02x%02x%02x%02x%02x%02x;extra_tlvs=%u",
                ahsrp_opcode(r->opcode), ahsrp_state(r->state), (unsigned)r->ip_version,
                (unsigned)r->group, (unsigned)r->priority, (unsigned)r->hello_ms,
                (unsigned)r->hold_ms, r->identifier[0], r->identifier[1],
                r->identifier[2], r->identifier[3], r->identifier[4], r->identifier[5],
                (unsigned)r->extra_tlvs);
            return 1;
        }
        pos = end;
    }
    return 0;
}
'''
hdr = replace_once(hdr, old_end, addition + old_end, 'argos_hsrp.h end')
hdr_path.write_text(hdr)

src_path = Path('src/argos-sniffer.c')
src = src_path.read_text()
old = '''                if (opt_enterprise && ttl == 1U && (sport == 1985U || dport == 1985U)) {
                    argos_hsrp1_result_t hsrp;
                    if (argos_hsrp1_parse(payload, (size_t)payload_len, &hsrp)) {
                        char ent_mac[18], ent_sig[384];
                        if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);
                        else format_mac(src_mac, ent_mac);
                        snprintf(ent_sig, sizeof(ent_sig), "%s|HSRP|%s", src_ip_str, hsrp.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))
                            emit_telemetry("ENT|%s|%s|%s|HSRP|%s%s\\n",
                                           ent_mac, src_ip_str, dst_ip_str, hsrp.detail, routed_str);
                    }
                }
'''
new = '''                if (opt_enterprise && ttl == 1U && (sport == 1985U || dport == 1985U)) {
                    char ent_mac[18], ent_sig[512];
                    if (pkt_type == LINK_RAW_IP) snprintf(ent_mac, sizeof(ent_mac), "%s", current_iface->name);
                    else format_mac(src_mac, ent_mac);

                    argos_hsrp2_result_t hsrp2;
                    if (argos_hsrp2_parse(payload, (size_t)payload_len, &hsrp2)) {
                        snprintf(ent_sig, sizeof(ent_sig), "%s|HSRP2|%s", src_ip_str, hsrp2.detail);
                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))
                            emit_telemetry("ENT|%s|%s|%s|HSRP2|%s%s\\n",
                                           ent_mac, src_ip_str, dst_ip_str, hsrp2.detail, routed_str);
                    } else {
                        argos_hsrp1_result_t hsrp1;
                        if (argos_hsrp1_parse(payload, (size_t)payload_len, &hsrp1)) {
                            snprintf(ent_sig, sizeof(ent_sig), "%s|HSRP|%s", src_ip_str, hsrp1.detail);
                            if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))
                                emit_telemetry("ENT|%s|%s|%s|HSRP|%s%s\\n",
                                               ent_mac, src_ip_str, dst_ip_str, hsrp1.detail, routed_str);
                        }
                    }
                }
'''
src = replace_once(src, old, new, 'HSRP integration block')
src_path.write_text(src)

Path('tests/test_hsrp2.c').write_text(r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_hsrp.h"

static void put32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16);
    p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v;
}

int main(void) {
    unsigned char p[46] = {0};
    p[0]=1; p[1]=40;              /* Group State TLV */
    p[2]=2; p[3]=0; p[4]=16; p[5]=4; /* v2, hello, active, IPv4 */
    p[6]=0x0f; p[7]=0xff;         /* group 4095 */
    p[8]=0x00; p[9]=0x11; p[10]=0x22; p[11]=0x33; p[12]=0x44; p[13]=0x55;
    put32(p+14, 150); put32(p+18, 3000); put32(p+22, 10000);
    p[26]=192; p[27]=0; p[28]=2; p[29]=254; /* virtual IP: must never be emitted */
    p[42]=4; p[43]=2; p[44]=0xde; p[45]=0xad; /* opaque/auth-like extra TLV */

    argos_hsrp2_result_t r;
    assert(argos_hsrp2_parse(p, sizeof(p), &r) == 1);
    assert(r.wire_version == 2 && r.opcode == 0 && r.state == 16 && r.ip_version == 4);
    assert(r.group == 4095 && r.priority == 150 && r.hello_ms == 3000 && r.hold_ms == 10000);
    assert(r.extra_tlvs == 1);
    assert(strstr(r.detail, "version=2") && strstr(r.detail, "state=active"));
    assert(strstr(r.detail, "group=4095") && strstr(r.detail, "hello_ms=3000"));
    assert(strstr(r.detail, "001122334455"));
    assert(strstr(r.detail, "192.0.2.254") == NULL);
    assert(strstr(r.detail, "dead") == NULL);

    p[2]=1; assert(argos_hsrp2_parse(p, sizeof(p), &r) == 0); p[2]=2;
    p[5]=5; assert(argos_hsrp2_parse(p, sizeof(p), &r) == 0); p[5]=4;
    p[6]=0x10; p[7]=0x00; assert(argos_hsrp2_parse(p, sizeof(p), &r) == 0);
    assert(argos_hsrp2_parse(p, 41, &r) == 0);
    puts("HSRPv2 fixtures: PASS");
    return 0;
}
''')
