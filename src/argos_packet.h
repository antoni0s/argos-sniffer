#ifndef ARGOS_PACKET_H
#define ARGOS_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef enum {
    LINK_UNSUPPORTED = 0,
    LINK_ETHERNET = 1,
    LINK_RAW_IP = 2,
    LINK_COOKED = 3,
    LINK_PER_PACKET = 4
} link_type_t;

/* Stack-only normalized view over the capture buffer. It owns no payload,
 * performs no allocation and keeps policy (LAN/routed/filtering) outside the
 * decoder. Offsets always refer to the original capture buffer. */
typedef struct {
    const unsigned char *frame;
    int captured_len;
    link_type_t link_type;
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
} argos_packet_view_t;

static inline uint16_t read_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline int ipv4_header_info(const unsigned char *buffer, int available,
                                   uint16_t *total_len_out, int *header_len_out) {
    if (!buffer || available < 20) return 0;
    uint8_t version = (uint8_t)(buffer[0] >> 4);
    uint8_t ihl = (uint8_t)(buffer[0] & 0x0fU);
    if (version != 4U || ihl < 5U) return 0;
    int header_len = (int)ihl * 4;
    if (header_len > available) return 0;
    uint16_t total_len = read_be16(buffer + 2);
    if (total_len < (uint16_t)header_len || total_len > (uint16_t)available) return 0;
    if (total_len_out) *total_len_out = total_len;
    if (header_len_out) *header_len_out = header_len;
    return 1;
}

static inline int ipv6_packet_info(const unsigned char *buffer, int available,
                                   int *packet_len_out) {
    if (!buffer || available < 40 || (buffer[0] >> 4) != 6U) return 0;
    uint32_t packet_len = 40U + (uint32_t)read_be16(buffer + 4);
    if (packet_len > (uint32_t)available) return 0;
    if (packet_len_out) *packet_len_out = (int)packet_len;
    return 1;
}

static inline int argos_packet_strip_l2(argos_packet_view_t *v) {
    const unsigned char *buffer = v->frame;
    int len = v->captured_len;

    if (v->link_type == LINK_ETHERNET) {
        if (len < 14) return 0;
        memcpy(v->dst_mac, buffer, 6U);
        memcpy(v->src_mac, buffer + 6, 6U);
        uint16_t eth_type = read_be16(buffer + 12);
        int offset = 14;

        if (eth_type == 0x8100U || eth_type == 0x88a8U) {
            if (len < 18) return 0;
            v->outer_vlan = (uint16_t)(read_be16(buffer + 14) & 0x0fffU);
            eth_type = read_be16(buffer + 16);
            offset = 18;
            if (eth_type == 0x8100U || eth_type == 0x88a8U) {
                if (len < 22) return 0;
                v->inner_vlan = (uint16_t)(read_be16(buffer + 18) & 0x0fffU);
                eth_type = read_be16(buffer + 20);
                offset = 22;
            }
        }

        /* Preserve the existing LLC/SNAP protocol discriminators. */
        if (eth_type <= 1500U) {
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0xe0U && buffer[offset + 5] == 0x2bU &&
                read_be16(buffer + offset + 6) == 0x00bbU) {
                v->l3_proto = 0x00bbU;
                v->l3_offset = offset + 8;
                return 1;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0xe0U && buffer[offset + 5] == 0x52U &&
                read_be16(buffer + offset + 6) == 0x2000U) {
                v->l3_proto = 0xf200U;
                v->l3_offset = offset + 8;
                return 1;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0x00U && buffer[offset + 5] == 0x0cU &&
                read_be16(buffer + offset + 6) == 0x2000U) {
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
            uint16_t ppp_proto = read_be16(buffer + offset + 6);
            offset += 8;
            if (ppp_proto == 0x0021U) eth_type = 0x0800U;
            else if (ppp_proto == 0x0057U) eth_type = 0x86ddU;
            else return 0;
        }
        v->l3_proto = eth_type;
        v->l3_offset = offset;
        return 1;
    }

    if (v->link_type == LINK_COOKED) {
        if (len < 16) return 0;
        /* Keep the legacy SLL address-length interpretation byte-for-byte. */
        if (buffer[4] >= 6U) memcpy(v->src_mac, buffer + 6, 6U);
        v->l3_proto = read_be16(buffer + 14);
        v->l3_offset = 16;
        return 1;
    }

    if (v->link_type == LINK_RAW_IP) {
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

static inline int argos_packet_ipv6_l4(argos_packet_view_t *v) {
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
            uint16_t fragment = read_be16(buf + off + 2);
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

static inline int argos_packet_decode(link_type_t type,
                                      const unsigned char *frame, int length,
                                      int enable_ipv6,
                                      argos_packet_view_t *v) {
    if (!frame || !v || length <= 0) return 0;
    memset(v, 0, sizeof(*v));
    v->frame = frame;
    v->captured_len = length;
    v->packet_end = length;
    v->link_type = type;
    if (!argos_packet_strip_l2(v)) return 0;

    int available = length - v->l3_offset;
    if (v->l3_proto == 0x0800U) {
        uint16_t total_len = 0U;
        int header_len = 0;
        if (!ipv4_header_info(frame + v->l3_offset, available, &total_len, &header_len)) return 0;

        v->is_ip = 1U;
        v->ip_version = 4U;
        v->ip_ttl = frame[v->l3_offset + 8];
        v->ip_protocol = frame[v->l3_offset + 9];
        v->l4_offset = v->l3_offset + header_len;
        v->packet_end = v->l3_offset + (int)total_len;
        v->nonfirst_fragment = (uint8_t)((read_be16(frame + v->l3_offset + 6) & 0x1fffU) != 0U);
        memcpy(v->src_addr, frame + v->l3_offset + 12, 4U);
        memcpy(v->dst_addr, frame + v->l3_offset + 16, 4U);
        return 1;
    }

    if (v->l3_proto == 0x86ddU && enable_ipv6) {
        int packet_len = 0;
        if (!ipv6_packet_info(frame + v->l3_offset, available, &packet_len)) return 0;

        v->is_ip = 1U;
        v->ip_version = 6U;
        v->ip_ttl = frame[v->l3_offset + 7];
        v->packet_end = v->l3_offset + packet_len;
        memcpy(v->src_addr, frame + v->l3_offset + 8, 16U);
        memcpy(v->dst_addr, frame + v->l3_offset + 24, 16U);
        return argos_packet_ipv6_l4(v);
    }

    return 1;
}

#endif /* ARGOS_PACKET_H */
