from pathlib import Path


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)

Path('src/argos_udp_suppress.h').write_text(r'''#ifndef ARGOS_UDP_SUPPRESS_H
#define ARGOS_UDP_SUPPRESS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_UDP_SUPPRESS_SLOTS 256U
#define ARGOS_UDP_SUPPRESS_PROBES 2U
#define ARGOS_UDP_SUPPRESS_TTL_SECS 5U

typedef struct {
    uint64_t key;
    uint64_t last_seen_sec;
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t sport;
    uint16_t dport;
    uint8_t ip_version;
    uint8_t msg_class;
    uint8_t valid;
} argos_udp_suppress_entry_t;

static inline uint64_t argos_udp_suppress_hash_update(uint64_t h, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static inline uint64_t argos_udp_suppress_key(uint8_t ip_version,
                                               const uint8_t *src, const uint8_t *dst,
                                               uint16_t sport, uint16_t dport,
                                               uint8_t msg_class) {
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = 1469598103934665603ULL;
    h = argos_udp_suppress_hash_update(h, &ip_version, sizeof(ip_version));
    h = argos_udp_suppress_hash_update(h, src, addr_len);
    h = argos_udp_suppress_hash_update(h, dst, addr_len);
    h = argos_udp_suppress_hash_update(h, &sport, sizeof(sport));
    h = argos_udp_suppress_hash_update(h, &dport, sizeof(dport));
    h = argos_udp_suppress_hash_update(h, &msg_class, sizeof(msg_class));
    return h;
}

/* Returns 1 only for an exact class+5-tuple hit still inside the short TTL.
 * Suppressed hits deliberately do NOT refresh last_seen_sec: a continuous
 * elephant flow is therefore revalidated periodically instead of becoming
 * permanently invisible. First/expired packets return 0 and seed a new epoch. */
static inline int argos_udp_suppress_recent(argos_udp_suppress_entry_t table[ARGOS_UDP_SUPPRESS_SLOTS],
                                            uint8_t ip_version,
                                            const uint8_t *src, const uint8_t *dst,
                                            uint16_t sport, uint16_t dport,
                                            uint8_t msg_class, uint64_t now_sec) {
    if (!table || !src || !dst || (ip_version != 4U && ip_version != 6U)) return 0;
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    const uint64_t key = argos_udp_suppress_key(ip_version, src, dst, sport, dport, msg_class);
    const size_t base = (size_t)(key & (ARGOS_UDP_SUPPRESS_SLOTS - 1U));
    size_t replace = base;
    uint64_t oldest = UINT64_MAX;

    for (size_t probe = 0; probe < ARGOS_UDP_SUPPRESS_PROBES; ++probe) {
        const size_t slot = (base + probe) & (ARGOS_UDP_SUPPRESS_SLOTS - 1U);
        argos_udp_suppress_entry_t *e = &table[slot];
        if (e->valid && e->key == key && e->ip_version == ip_version &&
            e->sport == sport && e->dport == dport && e->msg_class == msg_class &&
            memcmp(e->src, src, addr_len) == 0 && memcmp(e->dst, dst, addr_len) == 0) {
            if (now_sec >= e->last_seen_sec &&
                now_sec - e->last_seen_sec <= ARGOS_UDP_SUPPRESS_TTL_SECS) return 1;
            e->valid = 0;
            replace = slot;
            break;
        }
        if (!e->valid) { replace = slot; oldest = 0; break; }
        if (e->last_seen_sec < oldest) { oldest = e->last_seen_sec; replace = slot; }
    }

    argos_udp_suppress_entry_t *e = &table[replace];
    memset(e, 0, sizeof(*e));
    e->key = key;
    e->last_seen_sec = now_sec;
    memcpy(e->src, src, addr_len);
    memcpy(e->dst, dst, addr_len);
    e->sport = sport;
    e->dport = dport;
    e->ip_version = ip_version;
    e->msg_class = msg_class;
    e->valid = 1U;
    return 0;
}

#endif
''')

wp=Path('src/argos_wireguard.h'); w=wp.read_text()
old='''typedef struct {\n    int emit;\n    char detail[96];\n} argos_wireguard_result_t;\n\n'''
new='''typedef struct {\n    int emit;\n    char detail[96];\n} argos_wireguard_result_t;\n\n/* Shared structural classifier used by both the full parser and the optional\n * pre-parser suppression path. 0=not valid type-4, 1=keepalive, 2=data. */\nstatic inline int argos_wireguard_transport_kind(const unsigned char *p, size_t len) {\n    if (!p || len < 4U || p[0] != 4U || p[1] != 0U || p[2] != 0U || p[3] != 0U) return 0;\n    if (len < 32U || (len & 15U) != 0U) return 0;\n    return len == 32U ? 1 : 2;\n}\n\n'''
w=replace_once(w,old,new,'WireGuard transport classifier')
old='''    } else if (type == 4U) {\n        /* 16-byte transport header + AEAD ciphertext/tag. Empty keepalive is\n         * 32 bytes; encrypted transport packets remain 16-byte aligned. */\n        if (len < 32U || (len & 15U) != 0U) return 0;\n        kind = len == 32U ? "transport-keepalive" : "transport-data";\n'''
new='''    } else if (type == 4U) {\n        /* 16-byte transport header + AEAD ciphertext/tag. Empty keepalive is\n         * 32 bytes; encrypted transport packets remain 16-byte aligned. */\n        int transport_kind = argos_wireguard_transport_kind(p, len);\n        if (transport_kind == 0) return 0;\n        kind = transport_kind == 1 ? "transport-keepalive" : "transport-data";\n'''
w=replace_once(w,old,new,'WireGuard parser shared classifier')
wp.write_text(w)

sp=Path('src/argos-sniffer.c'); s=sp.read_text()
s=replace_once(s,
'''#include "argos_wireguard.h"\n#include "argos_dns_track.h"\n''',
'''#include "argos_wireguard.h"\n#include "argos_udp_suppress.h"\n#include "argos_dns_track.h"\n''','UDP suppression include')

anchor='''static app_flow_entry_t app_flow_table[APP_FLOW_SLOTS];\n\n'''
s=replace_once(s,anchor,anchor+'''/* UDP suppression is intentionally separate from TCP DONE state. It is used\n * only for protocol/message classes proven safe to skip briefly. */\nstatic argos_udp_suppress_entry_t udp_suppress_table[ARGOS_UDP_SUPPRESS_SLOTS];\n\n''','UDP suppression table')

old='''                if (opt_enterprise && (sport == opt_wireguard_port || dport == opt_wireguard_port)) {\n                    argos_wireguard_result_t wg;\n                    if (argos_wireguard_parse(payload, (size_t)payload_len, &wg) && wg.emit) {\n                        char ent_mac[18], ent_sig[384];\n                        format_mac(src_mac, ent_mac);\n                        snprintf(ent_sig, sizeof(ent_sig), "%s|WireGuard|%s", src_ip_str, wg.detail);\n                        if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                            emit_telemetry("ENT|%s|%s|%s|WireGuard|%s%s\\n",\n                                           ent_mac, src_ip_str, dst_ip_str, wg.detail, routed_str);\n                    }\n                }\n'''
new='''                if (opt_enterprise && (sport == opt_wireguard_port || dport == opt_wireguard_port)) {\n                    /* Type-4 transport packets can be an elephant UDP flow. Validate the\n                     * exact WireGuard framing cheaply, then bypass the full parser for\n                     * repeated transport-data in a short epoch. Handshake/cookie types\n                     * and keepalives are always parsed. DNS/DHCP/QUIC/STUN/CoAP/NTP are\n                     * deliberately outside this suppression table. */\n                    int wg_transport = argos_wireguard_transport_kind(payload, (size_t)payload_len);\n                    int wg_suppressed = wg_transport == 2 &&\n                        argos_udp_suppress_recent(udp_suppress_table, flow_ip_version,\n                                                  flow_src_addr, flow_dst_addr, sport, dport,\n                                                  4U, (uint64_t)time(NULL));\n                    if (!wg_suppressed) {\n                        argos_wireguard_result_t wg;\n                        if (argos_wireguard_parse(payload, (size_t)payload_len, &wg) && wg.emit) {\n                            char ent_mac[18], ent_sig[384];\n                            format_mac(src_mac, ent_mac);\n                            snprintf(ent_sig, sizeof(ent_sig), "%s|WireGuard|%s", src_ip_str, wg.detail);\n                            if (!dedup_should_suppress(ent_mac, "ENT", ent_sig, opt_enterprise_rl))\n                                emit_telemetry("ENT|%s|%s|%s|WireGuard|%s%s\\n",\n                                               ent_mac, src_ip_str, dst_ip_str, wg.detail, routed_str);\n                        }\n                    }\n                }\n'''
s=replace_once(s,old,new,'WireGuard UDP class suppression integration')
sp.write_text(s)

Path('tests/test_udp_suppress.c').write_text(r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_udp_suppress.h"
#include "../src/argos_wireguard.h"

int main(void) {
    argos_udp_suppress_entry_t tab[ARGOS_UDP_SUPPRESS_SLOTS];
    memset(tab,0,sizeof(tab));
    uint8_t a[16]={10,0,0,1}, b[16]={10,0,0,2};

    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,100)==0);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,101)==1);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,105)==1);
    /* Suppressed hits do not refresh the epoch: revalidate after 5 seconds. */
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,106)==0);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,4,107)==1);

    /* Reverse direction and a different message class are independent. */
    assert(argos_udp_suppress_recent(tab,4,b,a,51820,50000,4,107)==0);
    assert(argos_udp_suppress_recent(tab,4,a,b,50000,51820,3,107)==0);

    uint8_t a6[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t b6[16]={0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2};
    assert(argos_udp_suppress_recent(tab,6,a6,b6,50001,51820,4,200)==0);
    assert(argos_udp_suppress_recent(tab,6,a6,b6,50001,51820,4,201)==1);

    unsigned char keepalive[32]={4,0,0,0};
    unsigned char data[48]={4,0,0,0};
    unsigned char bad[48]={4,1,0,0};
    assert(argos_wireguard_transport_kind(keepalive,sizeof(keepalive))==1);
    assert(argos_wireguard_transport_kind(data,sizeof(data))==2);
    assert(argos_wireguard_transport_kind(bad,sizeof(bad))==0);
    assert(argos_wireguard_transport_kind(data,47)==0);

    puts("Bounded UDP class suppression fixtures: PASS");
    return 0;
}
''')
