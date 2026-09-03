#ifndef ARGOS_DNS_TRACK_H
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
