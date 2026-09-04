/* Test-only packet decoder snapshot at 1def2ffb (PR #18).
 * Only symbol/include-guard prefixes differ. Never included by production. */
#ifndef reference_ARGOS_PACKET_H
#define reference_ARGOS_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef enum {
    reference_LINK_UNSUPPORTED = 0,
    reference_LINK_ETHERNET = 1,
    reference_LINK_RAW_IP = 2,
    reference_LINK_COOKED = 3, /* SLL v1 compatibility input; not produced by live capture. */
    reference_LINK_PER_PACKET = 4
} reference_link_type_t;

/* Stack-only normalized view over the capture buffer. It owns no payload,
 * performs no allocation and keeps policy (LAN/routed/filtering) outside the
 * decoder. Offsets always refer to the original capture buffer. */
typedef struct {
    const unsigned char *frame;
    int captured_len;
    reference_link_type_t link_type;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t l3_proto;
    uint16_t outer_vlan;
    uint16_t inner_vlan;
    int l3_offset;
    int l4_offset;
    int packet_end;
    uint8_t is_ip;
    uint8_t ip_version;
    uint8_t ip_protocol;
    uint8_t ip_ttl;
    uint8_t nonfirst_fragment;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
} reference_argos_packet_view_t;

/* Borrowed transport slice; offsets refer to packet.frame and expire when that
 * capture buffer is reused. No payload/observation storage or protocol state.
 * Non-port IP protocols expose the whole L4 span, not invented port numbers. */
typedef struct {
    int payload_offset;
    int payload_len;
    int header_len;
    uint16_t sport;
    uint16_t dport;
    uint8_t has_ports;
} reference_argos_transport_view_t;

static inline uint16_t reference_read_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* Framing only, shared by transport dispatch and the best-effort inspector.
 * p covers available bytes; fragment admission remains the caller's policy. */
static inline int reference_argos_packet_tcp_header_length(const unsigned char *p, int available) {
    if (available < 20) return 0;
    int header = (int)(p[12] >> 4) * 4;
    return header >= 20 && header <= available ? header : 0;
}

/* Invoke only when a transport view is needed, not for every disabled engine.
 * Success validates framing/bounds, not checksums or application semantics.
 * First fragments retain legacy behavior if a complete transport header fits;
 * non-first fragments cannot expose transport. IPv6 AH traversal is unchanged:
 * this API describes the final normalized L4 span, not skipped AH headers. */
/* Internal fast entry: v must retain successful decoder framing fields with
 * is_ip && !nonfirst_fragment; out must be non-NULL. The dispatcher has already
 * checked these conditions; protocol must equal v->ip_protocol (the known
 * dispatch constant permits compile-time specialization). On failure out is
 * unspecified and must not be used.
 * Both entries share the same transport parser; do not repeat IP validation. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline int reference_argos_packet_transport_normalized(const reference_argos_packet_view_t *v,
                                                     uint8_t protocol,
                                                     reference_argos_transport_view_t *out) {
    int available = v->packet_end - v->l4_offset;
    int header = 0, length = available;
    const unsigned char *p = v->frame + v->l4_offset;
    if (protocol == 6U) {
        header = reference_argos_packet_tcp_header_length(p, available);
        if (!header) return 0;
    } else if (protocol == 17U) {
        if (available < 8) return 0;
        length = (int)reference_read_be16(p + 4);
        if (length < 8 || length > available) return 0;
        header = 8;
    }
    out->sport = header ? reference_read_be16(p) : 0U;
    out->dport = header ? reference_read_be16(p + 2) : 0U;
    out->has_ports = (uint8_t)(header != 0);
    out->header_len = header;
    out->payload_offset = v->l4_offset + header;
    out->payload_len = length - header;
    return 1;
}

/* Defensive entry for callers that have not established the normalized-view
 * preconditions. Failure clears the result, preserving the public API contract. */
static inline int reference_argos_packet_transport(const reference_argos_packet_view_t *v,
                                          reference_argos_transport_view_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!v || !v->frame || !v->is_ip || v->nonfirst_fragment ||
        v->l3_offset < 0 || v->l4_offset < v->l3_offset ||
        v->packet_end < v->l4_offset || v->packet_end > v->captured_len) return 0;
    return reference_argos_packet_transport_normalized(v, v->ip_protocol, out);
}

static inline int reference_ipv4_header_info(const unsigned char *buffer, int available,
                                   uint16_t *total_len_out, int *header_len_out) {
    if (!buffer || available < 20) return 0;
    uint8_t version = (uint8_t)(buffer[0] >> 4);
    uint8_t ihl = (uint8_t)(buffer[0] & 0x0fU);
    if (version != 4U || ihl < 5U) return 0;
    int header_len = (int)ihl * 4;
    if (header_len > available) return 0;
    uint16_t total_len = reference_read_be16(buffer + 2);
    if (total_len < (uint16_t)header_len || total_len > (uint16_t)available) return 0;
    if (total_len_out) *total_len_out = total_len;
    if (header_len_out) *header_len_out = header_len;
    return 1;
}

static inline int reference_ipv6_packet_info(const unsigned char *buffer, int available,
                                   int *packet_len_out) {
    if (!buffer || available < 40 || (buffer[0] >> 4) != 6U) return 0;
    uint32_t packet_len = 40U + (uint32_t)reference_read_be16(buffer + 4);
    if (packet_len > (uint32_t)available) return 0;
    if (packet_len_out) *packet_len_out = (int)packet_len;
    return 1;
}

static inline int reference_argos_packet_strip_l2(reference_argos_packet_view_t *v) {
    const unsigned char *buffer = v->frame;
    int len = v->captured_len;

    if (v->link_type == reference_LINK_ETHERNET) {
        if (len < 14) return 0;
        memcpy(v->dst_mac, buffer, 6U);
        memcpy(v->src_mac, buffer + 6, 6U);
        uint16_t eth_type = reference_read_be16(buffer + 12);
        int offset = 14;

        if (eth_type == 0x8100U || eth_type == 0x88a8U) {
            if (len < 18) return 0;
            v->outer_vlan = (uint16_t)(reference_read_be16(buffer + 14) & 0x0fffU);
            eth_type = reference_read_be16(buffer + 16);
            offset = 18;
            if (eth_type == 0x8100U || eth_type == 0x88a8U) {
                if (len < 22) return 0;
                v->inner_vlan = (uint16_t)(reference_read_be16(buffer + 18) & 0x0fffU);
                eth_type = reference_read_be16(buffer + 20);
                offset = 22;
            }
        }

        /* Preserve the existing LLC/SNAP protocol discriminators. */
        if (eth_type <= 1500U) {
            if ((int)eth_type > len - offset) return 0;
            len = offset + (int)eth_type;
            v->packet_end = len;
            /* STP-family parsers consume the LLC prefix themselves. Retain it,
             * and exclude Ethernet padding using the declared 802.3 length.
             * Unknown LLC formats remain rejected; this is not generic DPI. */
            if (len >= offset + 3 && buffer[offset] == 0x42U &&
                buffer[offset + 1] == 0x42U && buffer[offset + 2] == 0x03U) {
                v->l3_proto = eth_type;
                v->l3_offset = offset;
                return 1;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0xe0U && buffer[offset + 5] == 0x2bU &&
                reference_read_be16(buffer + offset + 6) == 0x00bbU) {
                v->l3_proto = 0x00bbU;
                v->l3_offset = offset + 8;
                return 1;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0xe0U && buffer[offset + 5] == 0x52U &&
                reference_read_be16(buffer + offset + 6) == 0x2000U) {
                v->l3_proto = 0xf200U;
                v->l3_offset = offset + 8;
                return 1;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0x00U && buffer[offset + 5] == 0x0cU &&
                reference_read_be16(buffer + offset + 6) == 0x2000U) {
                v->l3_proto = 0x2000U;
                v->l3_offset = offset + 8;
                return 1;
            }
            if (len >= offset + 3 && buffer[offset] == 0xfeU &&
                buffer[offset + 1] == 0xfeU && buffer[offset + 2] == 0x03U) {
                v->l3_proto = 0x00feU;
                v->l3_offset = offset + 3;
                return 1;
            }
            return 0;
        }

        if (eth_type == 0x8864U) {
            if (len < offset + 8) return 0;
            /* RFC 2516: payload length includes the PPP protocol field,
             * not the six-byte PPPoE header or Ethernet padding. */
            int payload_len = (int)reference_read_be16(buffer + offset + 4);
            if (payload_len < 2 || payload_len > len - offset - 6) return 0;
            v->packet_end = offset + 6 + payload_len;
            uint16_t ppp_proto = reference_read_be16(buffer + offset + 6);
            offset += 8;
            if (ppp_proto == 0x0021U) eth_type = 0x0800U;
            else if (ppp_proto == 0x0057U) eth_type = 0x86ddU;
            else return 0;
        }
        v->l3_proto = eth_type;
        v->l3_offset = offset;
        return 1;
    }

    if (v->link_type == reference_LINK_COOKED) {
        if (len < 16) return 0;
        /* SLL v1 has a BE16 address length. Do not invent a six-byte MAC
         * from a shorter address or a truncated longer address. No dst MAC. */
        if (reference_read_be16(buffer + 4) == 6U) memcpy(v->src_mac, buffer + 6, 6U);
        v->l3_proto = reference_read_be16(buffer + 14);
        v->l3_offset = 16;
        return 1;
    }

    if (v->link_type == reference_LINK_RAW_IP) {
        if (len < 1) return 0;
        uint8_t version = (uint8_t)(buffer[0] >> 4);
        if (version == 4U) v->l3_proto = 0x0800U;
        else if (version == 6U) v->l3_proto = 0x86ddU;
        else return 0;
        v->l3_offset = 0;
        return 1;
    }

    return 0;
}

static inline int reference_argos_packet_ipv6_l4(reference_argos_packet_view_t *v) {
    const unsigned char *buf = v->frame;
    int end = v->packet_end;
    uint8_t next = buf[v->l3_offset + 6];
    int off = v->l3_offset + 40;

    for (int guard = 0; guard < 8; ++guard) {
        if (next == 0U || next == 43U || next == 60U) {
            if (off + 2 > end) return 0;
            int header_len = ((int)buf[off + 1] + 1) * 8;
            next = buf[off];
            off += header_len;
            if (off > end) return 0;
        } else if (next == 44U) {
            if (off + 8 > end) return 0;
            uint16_t fragment = reference_read_be16(buf + off + 2);
            if ((fragment & 0xfff8U) != 0U) return 0;
            next = buf[off];
            off += 8;
        } else if (next == 51U) {
            if (off + 2 > end) return 0;
            int header_len = ((int)buf[off + 1] + 2) * 4;
            next = buf[off];
            off += header_len;
            if (off > end) return 0;
        } else if (next == 59U) {
            return 0;
        } else {
            v->ip_protocol = next;
            v->l4_offset = off;
            return 1;
        }
    }
    return 0;
}

static inline int reference_argos_packet_decode(reference_link_type_t type,
                                      const unsigned char *frame, int length,
                                      int enable_ipv6,
                                      reference_argos_packet_view_t *v) {
    if (!frame || !v || length <= 0) return 0;
    memset(v, 0, sizeof(*v));
    v->frame = frame;
    v->captured_len = length;
    v->packet_end = length;
    v->link_type = type;
    if (!reference_argos_packet_strip_l2(v)) return 0;

    int available = v->packet_end - v->l3_offset;
    if (v->l3_proto == 0x0800U) {
        uint16_t total_len = 0U;
        int header_len = 0;
        if (!reference_ipv4_header_info(frame + v->l3_offset, available, &total_len, &header_len)) return 0;

        v->is_ip = 1U;
        v->ip_version = 4U;
        v->ip_ttl = frame[v->l3_offset + 8];
        v->ip_protocol = frame[v->l3_offset + 9];
        v->l4_offset = v->l3_offset + header_len;
        v->packet_end = v->l3_offset + (int)total_len;
        v->nonfirst_fragment = (uint8_t)((reference_read_be16(frame + v->l3_offset + 6) & 0x1fffU) != 0U);
        memcpy(v->src_addr, frame + v->l3_offset + 12, 4U);
        memcpy(v->dst_addr, frame + v->l3_offset + 16, 4U);
        return 1;
    }

    if (v->l3_proto == 0x86ddU && enable_ipv6) {
        int packet_len = 0;
        if (!reference_ipv6_packet_info(frame + v->l3_offset, available, &packet_len)) return 0;

        v->is_ip = 1U;
        v->ip_version = 6U;
        v->ip_ttl = frame[v->l3_offset + 7];
        v->packet_end = v->l3_offset + packet_len;
        memcpy(v->src_addr, frame + v->l3_offset + 8, 16U);
        memcpy(v->dst_addr, frame + v->l3_offset + 24, 16U);
        return reference_argos_packet_ipv6_l4(v);
    }

    return 1;
}

#endif /* reference_ARGOS_PACKET_H */

