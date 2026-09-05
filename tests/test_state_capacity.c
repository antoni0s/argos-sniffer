#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../src/argos_flow_state.h"
#include "../src/argos_network.h"
#include "../src/argos_quic.h"

static argos_syn_track_t syn_table[ARGOS_SYN_TRACK_SLOTS];
static argos_dns_track_t dns_table[8];
static argos_network_owner4_entry_t owner4[ARGOS_NETWORK_OWNER4_SLOTS];
static argos_network_owner6_entry_t owner6[ARGOS_NETWORK_OWNER6_SLOTS];

_Static_assert(sizeof(argos_flow_entry_t) == 56U, "flow entry budget changed");
_Static_assert(sizeof(argos_flow_state_t) == 57344U, "flow table budget changed");
_Static_assert(sizeof(argos_udp_suppress_entry_t) == 56U, "UDP suppression entry budget changed");
_Static_assert(sizeof(argos_syn_track_t) == 64U, "SYN entry budget changed");
_Static_assert(sizeof(argos_dns_track_t) == 208U, "DNS entry budget changed");
_Static_assert(sizeof(argos_dedup_entry_t) == 24U, "dedup entry budget changed");
_Static_assert(sizeof(argos_network_owner4_entry_t) == 32U, "IPv4 owner entry budget changed");
_Static_assert(sizeof(argos_network_owner6_entry_t) == 40U, "IPv6 owner entry budget changed");
_Static_assert(sizeof(quic_session_t) == 9272U, "QUIC session budget changed");

static void collision_ports(uint16_t *ports, size_t count, size_t mask,
                            const uint8_t src[16], const uint8_t dst[16]) {
    size_t found = 0, target = 0;
    for (unsigned port = 1024; port <= 65535U && found < count; ++port) {
        size_t base = (size_t)(argos_flow_key(4, src, dst, (uint16_t)port, 443) & mask);
        if (!found) target = base;
        if (base == target) ports[found++] = (uint16_t)port;
    }
    assert(found == count);
}

static void application_capacity(void) {
    argos_flow_state_t state = {0};
    const uint8_t src[16] = {10,0,0,1}, dst[16] = {10,0,0,2};
    uint16_t ports[ARGOS_FLOW_PROBES + 1U];
    collision_ports(ports, ARGOS_FLOW_PROBES + 1U, ARGOS_FLOW_SLOTS - 1U, src, dst);
    for (size_t i = 0; i < ARGOS_FLOW_PROBES; ++i)
        assert(argos_flow_find_at(&state, 4, src, dst, ports[i], 443, 1,
                                  (time_t)(100 + i)));
    assert(argos_flow_find_at(&state, 4, src, dst, ports[ARGOS_FLOW_PROBES], 443,
                              1, 200));
    assert(!argos_flow_find_at(&state, 4, src, dst, ports[0], 443, 0, 200));
    assert(argos_flow_find_at(&state, 4, src, dst, ports[ARGOS_FLOW_PROBES],
                              443, 0, 200));
}

static void syn_capacity(void) {
    argos_runtime_state_t state = {0};
    state.syn_track = syn_table;
    const uint8_t src[16] = {10,0,0,3}, dst[16] = {10,0,0,4};
    const uint8_t mac[6] = {0x02,1,2,3,4,5};
    uint16_t ports[ARGOS_SYN_TRACK_PROBES + 1U];
    size_t found = 0, target = 0;
    for (unsigned port = 1024; port <= 65535U && found < ARGOS_SYN_TRACK_PROBES + 1U; ++port) {
        size_t base = argos_syn_track_key(mac, (uint16_t)port, 443, 4, src, dst) &
                      (ARGOS_SYN_TRACK_SLOTS - 1U);
        if (!found) target = base;
        if (base == target) ports[found++] = (uint16_t)port;
    }
    assert(found == ARGOS_SYN_TRACK_PROBES + 1U);
    for (size_t i = 0; i < ARGOS_SYN_TRACK_PROBES; ++i) {
        argos_syn_track_t *e = argos_syn_track_find(&state, mac, ports[i], 443,
                                                     4, src, dst, 100 + i, 1);
        assert(e); e->ts_usec = 100 + i;
    }
    argos_syn_track_t *newest = argos_syn_track_find(
        &state, mac, ports[ARGOS_SYN_TRACK_PROBES], 443, 4, src, dst, 200, 1);
    assert(newest); newest->ts_usec = 200;
    assert(!argos_syn_track_find(&state, mac, ports[0], 443, 4, src, dst, 200, 0));
    memset(syn_table, 0, sizeof(syn_table));
    state.syn_track = NULL;
}

static void udp_capacity(void) {
    argos_udp_suppress_entry_t table[ARGOS_UDP_SUPPRESS_SLOTS] = {0};
    const uint8_t src[16] = {10,0,0,5}, dst[16] = {10,0,0,6};
    uint16_t ports[ARGOS_UDP_SUPPRESS_PROBES + 1U];
    size_t found = 0, target = 0;
    for (unsigned port = 1024; port <= 65535U && found < ARGOS_UDP_SUPPRESS_PROBES + 1U; ++port) {
        uint64_t key = argos_udp_suppress_key(4, src, dst, (uint16_t)port, 51820, 4);
        size_t base = (size_t)(key & (ARGOS_UDP_SUPPRESS_SLOTS - 1U));
        if (!found) target = base;
        if (base == target) ports[found++] = (uint16_t)port;
    }
    assert(found == ARGOS_UDP_SUPPRESS_PROBES + 1U);
    for (size_t i = 0; i < ARGOS_UDP_SUPPRESS_PROBES + 1U; ++i)
        assert(!argos_udp_suppress_recent(table, 4, src, dst, ports[i], 51820,
                                          4, 100 + i));
    uint64_t first = argos_udp_suppress_key(4, src, dst, ports[0], 51820, 4);
    int retained = 0;
    for (size_t i = 0; i < ARGOS_UDP_SUPPRESS_SLOTS; ++i)
        if (table[i].valid && table[i].key == first) retained = 1;
    assert(!retained);
}

static void dns_capacity(void) {
    const uint8_t client[16] = {10,0,0,7}, server[16] = {1,1,1,1};
    const uint8_t mac[6] = {0x02,6,7,8,9,10};
    char names[9][32];
    size_t found = 0, target = 0;
    for (unsigned i = 0; i < 100000U && found < 9U; ++i) {
        char candidate[32];
        snprintf(candidate, sizeof(candidate), "capacity-%u.test", i);
        uint64_t qhash = argos_dns_name_hash(candidate);
        uint64_t key = argos_dns_track_key(4, client, server, 53000, 53, 1, 1, qhash);
        size_t base = (size_t)(key & 7U);
        if (!found) target = base;
        if (base == target) snprintf(names[found++], sizeof(names[0]), "%s", candidate);
    }
    assert(found == 9U);
    for (size_t i = 0; i < 9U; ++i)
        assert(argos_dns_track_put(dns_table, 8, 4, client, server, 53000, 53,
                                   1, 1, names[i], 100 + i, mac, 0));
    assert(!argos_dns_track_find_response(dns_table, 8, 4, client, server,
                                           53000, 53, 1, 1, names[0], 109));
    assert(argos_dns_track_find_response(dns_table, 8, 4, client, server,
                                          53000, 53, 1, 1, names[8], 109));
    memset(dns_table, 0, sizeof(dns_table));
}

static uint64_t dedup_key(const char *mac, const char *event, const char *payload) {
    static const char separator = '|';
    uint64_t h = 1469598103934665603ULL;
    h = argos_dedup_hash_update(h, mac, strlen(mac));
    h = argos_dedup_hash_update(h, &separator, 1U);
    h = argos_dedup_hash_update(h, event, strlen(event));
    h = argos_dedup_hash_update(h, &separator, 1U);
    return argos_dedup_hash_update(h, payload, strlen(payload));
}

static void dedup_capacity(void) {
    argos_dedup_state_t state = {0};
    assert(argos_dedup_prepare(&state));
    char payloads[ARGOS_DEDUP_PROBES + 1U][32];
    size_t found = 0, target = 0;
    for (unsigned i = 0; i < 100000U && found < ARGOS_DEDUP_PROBES + 1U; ++i) {
        char candidate[32];
        snprintf(candidate, sizeof(candidate), "capacity-%u", i);
        size_t base = (size_t)(dedup_key("aa", "TEST", candidate) &
                               (ARGOS_DEDUP_SLOTS - 1U));
        if (!found) target = base;
        if (base == target)
            snprintf(payloads[found++], sizeof(payloads[0]), "%s", candidate);
    }
    assert(found == ARGOS_DEDUP_PROBES + 1U);
    for (size_t i = 0; i < ARGOS_DEDUP_PROBES + 1U; ++i)
        assert(!argos_dedup_should_suppress_at(&state, "aa", "TEST", payloads[i],
                                                1, 1000, 0, (time_t)(100 + i)));
    assert(argos_dedup_should_suppress_at(&state, "aa", "TEST",
                                           payloads[ARGOS_DEDUP_PROBES],
                                           1, 1000, 0, 200));
    assert(!argos_dedup_should_suppress_at(&state, "aa", "TEST", payloads[0],
                                            1, 1000, 0, 200));
    argos_dedup_destroy(&state);
}

static void network4_capacity(void) {
    argos_network_state_t state = {0};
    state.owner4 = owner4;
    const uint8_t mac[6] = {0x02,11,12,13,14,15};
    uint32_t ips[ARGOS_NETWORK_OWNER_PROBES + 1U];
    size_t found = 0, target = 0;
    for (uint32_t host = 1; host < 100000U && found < ARGOS_NETWORK_OWNER_PROBES + 1U; ++host) {
        uint32_t ip = htonl(0x0a000000U | host);
        size_t base = (size_t)(argos_network_hash(&ip, sizeof(ip)) &
                               (ARGOS_NETWORK_OWNER4_SLOTS - 1U));
        if (!found) target = base;
        if (base == target) ips[found++] = ip;
    }
    assert(found == ARGOS_NETWORK_OWNER_PROBES + 1U);
    time_t now = time(NULL);
    for (size_t i = 0; i < ARGOS_NETWORK_OWNER_PROBES; ++i) {
        argos_network_owner4_note(&state, ips[i], mac);
        for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
            argos_network_owner4_entry_t *e = &owner4[(target + p) &
                                                       (ARGOS_NETWORK_OWNER4_SLOTS - 1U)];
            if (e->valid && e->ip == ips[i]) e->last_seen = now - (time_t)(10 - i);
        }
    }
    argos_network_owner4_note(&state, ips[ARGOS_NETWORK_OWNER_PROBES], mac);
    int first_retained = 0, newest_retained = 0;
    for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
        argos_network_owner4_entry_t *e = &owner4[(target + p) &
                                                   (ARGOS_NETWORK_OWNER4_SLOTS - 1U)];
        first_retained |= e->valid && e->ip == ips[0];
        newest_retained |= e->valid && e->ip == ips[ARGOS_NETWORK_OWNER_PROBES];
    }
    assert(!first_retained && newest_retained);
    memset(owner4, 0, sizeof(owner4));
}

static void network6_capacity(void) {
    argos_network_state_t state = {0};
    state.owner6 = owner6;
    const uint8_t mac[6] = {0x02,16,17,18,19,20};
    struct in6_addr ips[ARGOS_NETWORK_OWNER_PROBES + 1U];
    size_t found = 0, target = 0;
    for (uint32_t host = 1; host < 100000U &&
         found < ARGOS_NETWORK_OWNER_PROBES + 1U; ++host) {
        struct in6_addr ip = IN6ADDR_LOOPBACK_INIT;
        uint32_t wire = htonl(host);
        memcpy(&ip.s6_addr[12], &wire, sizeof(wire));
        size_t base = (size_t)(argos_network_hash(ip.s6_addr, 16) &
                               (ARGOS_NETWORK_OWNER6_SLOTS - 1U));
        if (!found) target = base;
        if (base == target) ips[found++] = ip;
    }
    assert(found == ARGOS_NETWORK_OWNER_PROBES + 1U);
    time_t now = time(NULL);
    for (size_t i = 0; i < ARGOS_NETWORK_OWNER_PROBES; ++i) {
        argos_network_owner6_note(&state, &ips[i], mac);
        for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
            argos_network_owner6_entry_t *e = &owner6[(target + p) &
                                                       (ARGOS_NETWORK_OWNER6_SLOTS - 1U)];
            if (e->valid && IN6_ARE_ADDR_EQUAL(&e->ip, &ips[i]))
                e->last_seen = now - (time_t)(10 - i);
        }
    }
    argos_network_owner6_note(&state, &ips[ARGOS_NETWORK_OWNER_PROBES], mac);
    int first_retained = 0, newest_retained = 0;
    for (size_t p = 0; p < ARGOS_NETWORK_OWNER_PROBES; ++p) {
        argos_network_owner6_entry_t *e = &owner6[(target + p) &
                                                   (ARGOS_NETWORK_OWNER6_SLOTS - 1U)];
        first_retained |= e->valid && IN6_ARE_ADDR_EQUAL(&e->ip, &ips[0]);
        newest_retained |= e->valid &&
                           IN6_ARE_ADDR_EQUAL(&e->ip, &ips[ARGOS_NETWORK_OWNER_PROBES]);
    }
    assert(!first_retained && newest_retained);
    memset(owner6, 0, sizeof(owner6));
}

static void quic_capacity(void) {
    argos_quic_state_t state = {0};
    quic_session_t sessions[QUIC_STATE_SLOTS] = {0};
    state.sessions = sessions;
    for (unsigned i = 0; i < QUIC_STATE_SLOTS; ++i) {
        uint8_t dcid[2] = {(uint8_t)i, (uint8_t)(i ^ 0xa5U)};
        int slot = quic_heavy_get_or_create_session(&state, ARGOS_QUIC_VERSION_V1,
                                                    dcid, sizeof(dcid));
        assert(slot >= 0); sessions[slot].last_seen = 100;
    }
    const uint8_t overflow[2] = {0xff,0xee};
    assert(quic_heavy_get_or_create_session(&state, ARGOS_QUIC_VERSION_V1,
                                            overflow, sizeof(overflow)) == -1);
    quic_heavy_gc_at(&state, 100 + QUIC_STATE_TTL + 1);
    assert(quic_heavy_get_or_create_session(&state, ARGOS_QUIC_VERSION_V1,
                                            overflow, sizeof(overflow)) >= 0);
}

int main(void) {
    application_capacity();
    syn_capacity();
    udp_capacity();
    dns_capacity();
    dedup_capacity();
    network4_capacity();
    network6_capacity();
    quic_capacity();
    printf("State saturation/eviction contracts: PASS; runtime_inline=%zu "
           "flow=%zu udp=%zu syn=%zu dns=%zu dedup=%zu network_inline=%zu "
           "owner4=%zu owner6=%zu quic_inline=%zu quic_workspace=%u quic_heavy=%zu\n",
           sizeof(argos_runtime_state_t), sizeof(argos_flow_state_t),
           sizeof(((argos_runtime_state_t *)0)->udp_suppress),
           ARGOS_SYN_TRACK_SLOTS * sizeof(argos_syn_track_t),
           ARGOS_RUNTIME_DNS_SLOTS * sizeof(argos_dns_track_t),
           ARGOS_DEDUP_SLOTS * sizeof(argos_dedup_entry_t),
           sizeof(argos_network_state_t), sizeof(owner4),
           ARGOS_NETWORK_OWNER6_SLOTS * sizeof(argos_network_owner6_entry_t),
           sizeof(argos_quic_state_t), (unsigned)ARGOS_QUIC_WORKSPACE_BYTES,
           QUIC_STATE_SLOTS * sizeof(quic_session_t));
    return 0;
}
