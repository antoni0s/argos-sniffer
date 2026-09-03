from pathlib import Path


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

Path('src/argos_dns_track.h').write_text(r'''#ifndef ARGOS_DNS_TRACK_H
#define ARGOS_DNS_TRACK_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ARGOS_DNS_TRACK_PROBES 8U
#define ARGOS_DNS_TRACK_TTL_USEC 5000000ULL

typedef struct {
    uint64_t key;
    uint64_t qname_hash;
    uint64_t ts_usec;
    uint8_t client_addr[16];
    uint8_t server_addr[16];
    char domain[128];
    uint8_t mac[6];
    uint16_t client_port;
    uint16_t server_port;
    uint16_t txid;
    uint16_t qtype;
    uint8_t ip_version;
    uint8_t routed;
    uint8_t valid;
} argos_dns_track_t;

static inline uint64_t argos_dns_hash_update(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static inline uint64_t argos_dns_name_hash(const char *name) {
    uint64_t h = 1469598103934665603ULL;
    return argos_dns_hash_update(h, name ? name : "", name ? strlen(name) : 0U);
}

static inline uint64_t argos_dns_track_key(uint8_t ip_version,
                                           const uint8_t *client_addr,
                                           const uint8_t *server_addr,
                                           uint16_t client_port,
                                           uint16_t server_port,
                                           uint16_t txid,
                                           uint16_t qtype,
                                           uint64_t qname_hash) {
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    uint64_t h = 1469598103934665603ULL;
    h = argos_dns_hash_update(h, &ip_version, sizeof(ip_version));
    h = argos_dns_hash_update(h, client_addr, addr_len);
    h = argos_dns_hash_update(h, server_addr, addr_len);
    h = argos_dns_hash_update(h, &client_port, sizeof(client_port));
    h = argos_dns_hash_update(h, &server_port, sizeof(server_port));
    h = argos_dns_hash_update(h, &txid, sizeof(txid));
    h = argos_dns_hash_update(h, &qtype, sizeof(qtype));
    h = argos_dns_hash_update(h, &qname_hash, sizeof(qname_hash));
    return h;
}

static inline int argos_dns_track_match(const argos_dns_track_t *e,
                                        uint8_t ip_version,
                                        const uint8_t *client_addr,
                                        const uint8_t *server_addr,
                                        uint16_t client_port,
                                        uint16_t server_port,
                                        uint16_t txid,
                                        uint16_t qtype,
                                        uint64_t qname_hash,
                                        uint64_t key) {
    if (!e || !e->valid || e->key != key || e->ip_version != ip_version ||
        e->client_port != client_port || e->server_port != server_port ||
        e->txid != txid || e->qtype != qtype || e->qname_hash != qname_hash) return 0;
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    return memcmp(e->client_addr, client_addr, addr_len) == 0 &&
           memcmp(e->server_addr, server_addr, addr_len) == 0;
}

static inline int argos_dns_track_expired(argos_dns_track_t *e, uint64_t now_usec) {
    if (!e || !e->valid) return 1;
    if (now_usec < e->ts_usec || now_usec - e->ts_usec >= ARGOS_DNS_TRACK_TTL_USEC) {
        e->valid = 0;
        return 1;
    }
    return 0;
}

static inline argos_dns_track_t *argos_dns_track_put(argos_dns_track_t *table, size_t slots,
                                                      uint8_t ip_version,
                                                      const uint8_t *client_addr,
                                                      const uint8_t *server_addr,
                                                      uint16_t client_port,
                                                      uint16_t server_port,
                                                      uint16_t txid,
                                                      uint16_t qtype,
                                                      const char *qname,
                                                      uint64_t now_usec,
                                                      const uint8_t mac[6],
                                                      uint8_t routed) {
    if (!table || !slots || (slots & (slots - 1U)) != 0U ||
        (ip_version != 4U && ip_version != 6U) || !client_addr || !server_addr || !qname || !qname[0]) return NULL;
    uint64_t qhash = argos_dns_name_hash(qname);
    uint64_t key = argos_dns_track_key(ip_version, client_addr, server_addr,
                                       client_port, server_port, txid, qtype, qhash);
    size_t base = (size_t)(key & (slots - 1U));
    argos_dns_track_t *empty = NULL, *oldest = NULL;
    uint64_t oldest_ts = UINT64_MAX;
    size_t probes = slots < ARGOS_DNS_TRACK_PROBES ? slots : ARGOS_DNS_TRACK_PROBES;

    for (size_t p = 0; p < probes; ++p) {
        argos_dns_track_t *e = &table[(base + p) & (slots - 1U)];
        (void)argos_dns_track_expired(e, now_usec);
        if (argos_dns_track_match(e, ip_version, client_addr, server_addr,
                                  client_port, server_port, txid, qtype, qhash, key)) {
            empty = e;
            break;
        }
        if (!e->valid) {
            if (!empty) empty = e;
        } else if (e->ts_usec < oldest_ts) {
            oldest_ts = e->ts_usec;
            oldest = e;
        }
    }
    argos_dns_track_t *e = empty ? empty : oldest;
    if (!e) return NULL;
    memset(e, 0, sizeof(*e));
    e->key = key; e->qname_hash = qhash; e->ts_usec = now_usec;
    e->client_port = client_port; e->server_port = server_port;
    e->txid = txid; e->qtype = qtype; e->ip_version = ip_version; e->routed = routed; e->valid = 1;
    const size_t addr_len = ip_version == 6U ? 16U : 4U;
    memcpy(e->client_addr, client_addr, addr_len);
    memcpy(e->server_addr, server_addr, addr_len);
    if (mac) memcpy(e->mac, mac, 6U);
    size_t n = strlen(qname); if (n >= sizeof(e->domain)) n = sizeof(e->domain) - 1U;
    memcpy(e->domain, qname, n); e->domain[n] = '\0';
    return e;
}

static inline argos_dns_track_t *argos_dns_track_find_response(argos_dns_track_t *table, size_t slots,
                                                                uint8_t ip_version,
                                                                const uint8_t *client_addr,
                                                                const uint8_t *server_addr,
                                                                uint16_t client_port,
                                                                uint16_t server_port,
                                                                uint16_t txid,
                                                                uint16_t qtype,
                                                                const char *qname,
                                                                uint64_t now_usec) {
    if (!table || !slots || (slots & (slots - 1U)) != 0U ||
        (ip_version != 4U && ip_version != 6U) || !client_addr || !server_addr || !qname || !qname[0]) return NULL;
    uint64_t qhash = argos_dns_name_hash(qname);
    uint64_t key = argos_dns_track_key(ip_version, client_addr, server_addr,
                                       client_port, server_port, txid, qtype, qhash);
    size_t base = (size_t)(key & (slots - 1U));
    size_t probes = slots < ARGOS_DNS_TRACK_PROBES ? slots : ARGOS_DNS_TRACK_PROBES;
    for (size_t p = 0; p < probes; ++p) {
        argos_dns_track_t *e = &table[(base + p) & (slots - 1U)];
        if (argos_dns_track_expired(e, now_usec)) continue;
        if (argos_dns_track_match(e, ip_version, client_addr, server_addr,
                                  client_port, server_port, txid, qtype, qhash, key)) return e;
    }
    return NULL;
}

#endif
''')

sp=Path('src/argos-sniffer.c'); s=sp.read_text()
s=replace_once(s,
'''#include "argos_multicast_membership.h"\n#include "argos_wireguard.h"\n#include "argos_enterprise.h"\n''',
'''#include "argos_multicast_membership.h"\n#include "argos_wireguard.h"\n#include "argos_dns_track.h"\n#include "argos_enterprise.h"\n''','DNS tracker include')

old_struct='''typedef struct {\n    uint16_t txid;\n    uint16_t qtype;\n    uint32_t src_ip;\n    uint64_t ts_usec;\n    char domain[128];\n    uint8_t mac[6];\n    uint8_t routed;\n} dns_track_t;\nstatic dns_track_t *dns_table = NULL;\n'''
s=replace_once(s,old_struct,'''static argos_dns_track_t *dns_table = NULL;\n''','old DNS tracker')

old_addr6='''static uint32_t addr6_key(const struct in6_addr *a) {\n    uint32_t k = (uint32_t)hash_bytes(a->s6_addr, 16);\n    return k ? k : 1u; /* never collide with "no address" */\n}\n\n'''
s=replace_once(s,old_addr6,'','obsolete IPv6 DNS key helper')

s=replace_once(s,
'''        dns_table = (dns_track_t *)calloc(TRACK_SLOTS, sizeof(*dns_table));\n''',
'''        dns_table = (argos_dns_track_t *)calloc(TRACK_SLOTS, sizeof(*dns_table));\n''','DNS tracker allocation')

s=replace_once(s,
'''            uint32_t flow_src_key = is_ipv6_packet ? addr6_key(&src_ip6_addr) : src_ip_num;\n            uint32_t flow_dst_key = is_ipv6_packet ? addr6_key(&dst_ip6_addr) : dst_ip_num;\n            uint8_t flow_ip_version = is_ipv6_packet ? 6U : 4U;\n''',
'''            uint8_t flow_ip_version = is_ipv6_packet ? 6U : 4U;\n''','obsolete DNS address keys')

old_query='''                                if (opt_ext_metrics) {\n                                    uint32_t slot = (txid ^ flow_src_key) & (TRACK_SLOTS - 1);\n                                    dns_table[slot].txid = txid;\n                                    dns_table[slot].qtype = qtype;\n                                    dns_table[slot].src_ip = flow_src_key;\n                                    dns_table[slot].ts_usec = pkt_usec;\n                                    dns_table[slot].routed = (uint8_t)(routed_evidence ? 1 : 0);\n                                    memcpy(dns_table[slot].mac, src_mac, 6);\n                                    size_t domain_len = strlen(qname);\n                                    if (domain_len >= sizeof(dns_table[slot].domain)) domain_len = sizeof(dns_table[slot].domain) - 1U;\n                                    memcpy(dns_table[slot].domain, qname, domain_len);\n                                    dns_table[slot].domain[domain_len] = '\\0';\n                                }\n'''
new_query='''                                if (opt_ext_metrics && qtype != 0U) {\n                                    (void)argos_dns_track_put(dns_table, TRACK_SLOTS,\n                                                              flow_ip_version, flow_src_addr, flow_dst_addr,\n                                                              sport, dport, txid, qtype, qname, pkt_usec,\n                                                              src_mac, (uint8_t)(routed_evidence ? 1 : 0));\n                                }\n'''
s=replace_once(s,old_query,new_query,'DNSEXT query insertion')

old_response='''                            if (opt_ext_metrics) {\n                                uint32_t slot = (txid ^ flow_dst_key) & (TRACK_SLOTS - 1);\n                                if (dns_table[slot].txid == txid && dns_table[slot].src_ip == flow_dst_key\n                                    && pkt_usec >= dns_table[slot].ts_usec\n                                    && (pkt_usec - dns_table[slot].ts_usec) < 5000000ULL) {\n                                    uint8_t rcode = flags & 0x000F;\n                                    uint64_t latency_us = pkt_usec - dns_table[slot].ts_usec;\n                                    float ent = calculate_entropy(dns_table[slot].domain);\n\n                                    char client_mac_str[18];\n                                    snprintf(client_mac_str, sizeof(client_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",\n                                             dns_table[slot].mac[0], dns_table[slot].mac[1], dns_table[slot].mac[2],\n                                             dns_table[slot].mac[3], dns_table[slot].mac[4], dns_table[slot].mac[5]);\n\n                                    char dnsext_sig[384];\n                                    source_dedup_signature(dnsext_sig, sizeof(dnsext_sig), dst_ip_str,\n                                                           dns_table[slot].domain,\n                                                           dns_table[slot].routed ? "|routed" : "");\n                                    if (!dedup_should_suppress(client_mac_str, "DNSEXT", dnsext_sig, opt_dns_rl)) {\n                                        emit_telemetry("DNSEXT|%s|%s|%s|%s|%u|%u|%.2f|%.2f%s\\n",\n                                            client_mac_str, dst_ip_str, src_ip_str, dns_table[slot].domain,\n                                            (unsigned)dns_table[slot].qtype, (unsigned)rcode,\n                                            (float)latency_us / 1000.0f, ent,\n                                            dns_table[slot].routed ? "|routed" : "");\n                                    }\n                                    char alert_sig[192];\n                                    source_dedup_signature(alert_sig, sizeof(alert_sig), dst_ip_str,\n                                                           "HIGH_DNS_ENTROPY",\n                                                           dns_table[slot].routed ? "|routed" : "");\n                                    if (ent >= 4.2f &&\n                                        !dedup_should_suppress(client_mac_str, "ALERT", alert_sig, opt_dns_rl)) {\n                                        emit_telemetry("ALERT|%s|%s|HIGH_DNS_ENTROPY|%s|%.2f%s\\n",\n                                                       client_mac_str, dst_ip_str, dns_table[slot].domain, ent,\n                                                       dns_table[slot].routed ? "|routed" : "");\n                                    }\n                                    dns_table[slot].txid = 0;\n                                }\n                            }\n'''
new_response='''                            if (opt_ext_metrics && read_be16(payload + 4) > 0U) {\n                                char response_qname[256];\n                                uint16_t response_qtype = 0U;\n                                if (decode_dns_name(payload, payload_len, 12, response_qname, sizeof(response_qname)) > 0 &&\n                                    response_qname[0] && dns_question_qtype(payload, payload_len, 12, &response_qtype)) {\n                                    argos_dns_track_t *tracked = argos_dns_track_find_response(\n                                        dns_table, TRACK_SLOTS, flow_ip_version, flow_dst_addr, flow_src_addr,\n                                        dport, sport, txid, response_qtype, response_qname, pkt_usec);\n                                    if (tracked) {\n                                        uint8_t rcode = flags & 0x000F;\n                                        uint64_t latency_us = pkt_usec - tracked->ts_usec;\n                                        float ent = calculate_entropy(tracked->domain);\n\n                                        char client_mac_str[18];\n                                        format_mac(tracked->mac, client_mac_str);\n\n                                        char dnsext_sig[384];\n                                        source_dedup_signature(dnsext_sig, sizeof(dnsext_sig), dst_ip_str,\n                                                               tracked->domain, tracked->routed ? "|routed" : "");\n                                        if (!dedup_should_suppress(client_mac_str, "DNSEXT", dnsext_sig, opt_dns_rl)) {\n                                            emit_telemetry("DNSEXT|%s|%s|%s|%s|%u|%u|%.2f|%.2f%s\\n",\n                                                client_mac_str, dst_ip_str, src_ip_str, tracked->domain,\n                                                (unsigned)tracked->qtype, (unsigned)rcode,\n                                                (float)latency_us / 1000.0f, ent, tracked->routed ? "|routed" : "");\n                                        }\n                                        char alert_sig[192];\n                                        source_dedup_signature(alert_sig, sizeof(alert_sig), dst_ip_str,\n                                                               "HIGH_DNS_ENTROPY", tracked->routed ? "|routed" : "");\n                                        if (ent >= 4.2f &&\n                                            !dedup_should_suppress(client_mac_str, "ALERT", alert_sig, opt_dns_rl)) {\n                                            emit_telemetry("ALERT|%s|%s|HIGH_DNS_ENTROPY|%s|%.2f%s\\n",\n                                                           client_mac_str, dst_ip_str, tracked->domain, ent,\n                                                           tracked->routed ? "|routed" : "");\n                                        }\n                                        tracked->valid = 0;\n                                    }\n                                }\n                            }\n'''
s=replace_once(s,old_response,new_response,'DNSEXT response lookup')

if 'flow_src_key' in s or 'flow_dst_key' in s or 'addr6_key(' in s:
    raise SystemExit('obsolete DNS keying remains after patch')
sp.write_text(s)

Path('tests/test_dns_track.c').write_text(r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_dns_track.h"

static void v4(uint8_t out[16], unsigned a, unsigned b, unsigned c, unsigned d) {
    memset(out,0,16); out[0]=(uint8_t)a; out[1]=(uint8_t)b; out[2]=(uint8_t)c; out[3]=(uint8_t)d;
}

int main(void) {
    argos_dns_track_t t[32]; memset(t,0,sizeof(t));
    uint8_t c1[16],c2[16],s1[16],s2[16],m1[6]={0,1,2,3,4,5},m2[6]={6,7,8,9,10,11};
    v4(c1,10,0,0,10); v4(c2,10,0,0,11); v4(s1,1,1,1,1); v4(s2,8,8,8,8);
    const uint64_t now=10000000ULL;

    assert(argos_dns_track_put(t,32,4,c1,s1,53000,53,0x1234,1,"example.com",now,m1,0));
    argos_dns_track_t *e=argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,1,"example.com",now+1000);
    assert(e && strcmp(e->domain,"example.com")==0 && memcmp(e->mac,m1,6)==0);

    /* Same TXID must not cross client, server, client port, qtype or qname. */
    assert(!argos_dns_track_find_response(t,32,4,c2,s1,53000,53,0x1234,1,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s2,53000,53,0x1234,1,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53001,53,0x1234,1,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,28,"example.com",now+1000));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,1,"other.example",now+1000));

    /* Two simultaneous same-TXID requests coexist instead of overwriting one slot. */
    assert(argos_dns_track_put(t,32,4,c2,s1,53000,53,0x1234,1,"example.com",now+10,m2,1));
    assert(argos_dns_track_put(t,32,4,c1,s2,53000,53,0x1234,1,"example.net",now+20,m1,0));
    assert(argos_dns_track_find_response(t,32,4,c2,s1,53000,53,0x1234,1,"example.com",now+1000));
    assert(argos_dns_track_find_response(t,32,4,c1,s2,53000,53,0x1234,1,"example.net",now+1000));

    /* Stale and clock-regressed replies cannot match. */
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53000,53,0x1234,1,"example.com",now+ARGOS_DNS_TRACK_TTL_USEC));
    assert(argos_dns_track_put(t,32,4,c1,s1,53002,53,0x2222,1,"clock.test",now,m1,0));
    assert(!argos_dns_track_find_response(t,32,4,c1,s1,53002,53,0x2222,1,"clock.test",now-1));

    /* Full IPv6 addresses, not a 32-bit address hint, establish identity. */
    uint8_t v61[16]={0x20,0x01,0x0d,0xb8}, v62[16]={0x20,0x01,0x0d,0xb8}, v6s[16]={0x26,0x06,0x47,0x00};
    v61[15]=1; v62[15]=2; v6s[15]=53;
    assert(argos_dns_track_put(t,32,6,v61,v6s,54000,53,0xabcd,28,"ipv6.example",now,m1,0));
    assert(argos_dns_track_find_response(t,32,6,v61,v6s,54000,53,0xabcd,28,"ipv6.example",now+500));
    assert(!argos_dns_track_find_response(t,32,6,v62,v6s,54000,53,0xabcd,28,"ipv6.example",now+500));

    /* Collision handling: find two distinct tuples sharing the same base slot. */
    argos_dns_track_t small[8]; memset(small,0,sizeof(small));
    char n1[32],n2[32]; uint64_t first_key=0; int found=0;
    snprintf(n1,sizeof(n1),"collision-%d.test",0);
    first_key=argos_dns_track_key(4,c1,s1,55000,53,0x4444,1,argos_dns_name_hash(n1));
    for(int i=1;i<10000;i++) {
        snprintf(n2,sizeof(n2),"collision-%d.test",i);
        uint64_t k=argos_dns_track_key(4,c1,s1,55000,53,0x4444,1,argos_dns_name_hash(n2));
        if ((k & 7U)==(first_key & 7U) && k!=first_key) { found=1; break; }
    }
    assert(found);
    assert(argos_dns_track_put(small,8,4,c1,s1,55000,53,0x4444,1,n1,now,m1,0));
    assert(argos_dns_track_put(small,8,4,c1,s1,55000,53,0x4444,1,n2,now+1,m1,0));
    assert(argos_dns_track_find_response(small,8,4,c1,s1,55000,53,0x4444,1,n1,now+100));
    assert(argos_dns_track_find_response(small,8,4,c1,s1,55000,53,0x4444,1,n2,now+100));

    puts("DNSEXT correlation fixtures: PASS");
    return 0;
}
''')
