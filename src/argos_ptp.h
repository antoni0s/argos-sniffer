#ifndef ARGOS_PTP_H
#define ARGOS_PTP_H

/* Argos-Sniffer v6 staging engine: IEEE 1588 PTPv2.
 *
 * Standalone parser only. This header is intentionally not wired into the
 * v6 dispatcher, CLI flags, telemetry, deduplication or capture path yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t transport_specific;
    uint8_t message_type;
    uint8_t version;
    uint16_t message_length;
    uint8_t domain_number;
    uint16_t flags;
    int64_t correction_field;
    unsigned char source_clock_identity[8];
    uint16_t source_port_number;
    uint16_t sequence_id;
    uint8_t control_field;
    int8_t log_message_interval;
    char detail[512];
} argos_ptp_result_t;

static inline uint16_t aptp_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint64_t aptp_be64(const unsigned char *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline const char *aptp_message_name(uint8_t t) {
    switch (t) {
        case 0x0U: return "sync";
        case 0x1U: return "delay-req";
        case 0x2U: return "pdelay-req";
        case 0x3U: return "pdelay-resp";
        case 0x8U: return "follow-up";
        case 0x9U: return "delay-resp";
        case 0xaU: return "pdelay-resp-follow-up";
        case 0xbU: return "announce";
        case 0xcU: return "signaling";
        case 0xdU: return "management";
        default: return "reserved";
    }
}

static inline void aptp_clock_id(char out[24], const unsigned char id[8]) {
    (void)snprintf(out, 24,
        "%02x%02x%02x.%02x%02x.%02x%02x%02x",
        id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]);
}

/* IEEE 1588-2008 / PTPv2 common message header.
 *
 * This parser intentionally fingerprints only the fixed 34-byte common
 * header. Message-specific payloads and TLVs are left for later vectors.
 * It therefore works for both UDP transport (319/320) and native Ethernet
 * transport once the caller supplies the PTP payload itself.
 */
static inline int argos_ptp_parse(const unsigned char *p, size_t n,
                                  argos_ptp_result_t *r) {
    if (!p || !r || n < 34U) return 0;
    memset(r, 0, sizeof(*r));

    r->transport_specific = (uint8_t)((p[0] >> 4) & 0x0fU);
    r->message_type = (uint8_t)(p[0] & 0x0fU);
    r->version = (uint8_t)(p[1] & 0x0fU);
    if (r->version != 2U) return 0;

    r->message_length = aptp_be16(p + 2);
    if (r->message_length < 34U || r->message_length > n) return 0;

    r->domain_number = p[4];
    r->flags = aptp_be16(p + 6);
    r->correction_field = (int64_t)aptp_be64(p + 8);
    memcpy(r->source_clock_identity, p + 20, 8);
    r->source_port_number = aptp_be16(p + 28);
    r->sequence_id = aptp_be16(p + 30);
    r->control_field = p[32];
    r->log_message_interval = (int8_t)p[33];

    char clock_id[24];
    aptp_clock_id(clock_id, r->source_clock_identity);

    (void)snprintf(r->detail, sizeof(r->detail),
        "version=2;type=%s;type_id=0x%x;transport=%u;domain=%u;len=%u;flags=0x%04x;"
        "clock=%s;port=%u;seq=%u;control=%u;log_interval=%d;correction=%lld",
        aptp_message_name(r->message_type),
        (unsigned)r->message_type,
        (unsigned)r->transport_specific,
        (unsigned)r->domain_number,
        (unsigned)r->message_length,
        (unsigned)r->flags,
        clock_id,
        (unsigned)r->source_port_number,
        (unsigned)r->sequence_id,
        (unsigned)r->control_field,
        (int)r->log_message_interval,
        (long long)r->correction_field);

    return 1;
}

#endif /* ARGOS_PTP_H */
