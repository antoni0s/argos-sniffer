#ifndef ARGOS_DISCOVERY_H
#define ARGOS_DISCOVERY_H

/*
 * Stateless discovery protocol decoding.
 *
 * This engine only turns bounded packet bytes into bounded result structs.
 * Routing policy, ownership learning, deduplication and telemetry stay with
 * the caller so the engine has no allocation, hidden state or I/O.
 */

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char name[17];
} argos_discovery_nbns_t;

typedef struct {
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_ip[4];
    uint16_t operation;
} argos_discovery_arp_t;

typedef struct {
    char hostname[64];
    char vendor[64];
    char parameter_request_list[256];
} argos_discovery_dhcp4_t;

typedef struct {
    const char *message_type;
    const char *duid_type;
    char vendor[128];
    char option_request[256];
    char fqdn[256];
} argos_discovery_dhcp6_t;

typedef struct {
    uint8_t identity_mac[6];
    uint8_t target[16];
    const char *kind;
    char flags[8];
    uint8_t has_target;
    uint8_t is_advertisement;
} argos_discovery_ndp_t;

typedef struct {
    uint8_t hop_limit;
    char flags[8];
    uint16_t lifetime;
    uint8_t prefix[16];
    uint8_t prefix_length;
    uint8_t has_prefix;
    uint32_t mtu;
} argos_discovery_ra_t;

typedef struct {
    char question[256];
} argos_discovery_mdns_t;

static uint16_t argos_discovery_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t argos_discovery_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int argos_discovery_mac_valid(const uint8_t mac[6]) {
    static const uint8_t zero[6] = {0};
    return mac && !(mac[0] & 1U) && memcmp(mac, zero, sizeof(zero)) != 0;
}

static void argos_discovery_sanitize(const uint8_t *src, size_t len,
                                     char *dst, size_t dst_size) {
    size_t out = 0;
    if (!dst || dst_size == 0U) return;
    if (!src) len = 0U;
    while (out < len && out + 1U < dst_size) {
        uint8_t c = src[out];
        dst[out] = (char)((c < 32U || c > 126U || c == '|') ? ' ' : c);
        ++out;
    }
    dst[out] = '\0';
}

/* NetBIOS Name Service --------------------------------------------------- */

static int argos_discovery_nbns_parse(const uint8_t *payload, size_t len,
                                      argos_discovery_nbns_t *result) {
    size_t out = 0;
    if (!payload || !result || len < 50U || payload[12] != 0x20U) return 0;
    memset(result, 0, sizeof(*result));
    for (size_t i = 0; i + 1U < 32U && out + 1U < sizeof(result->name); i += 2U) {
        uint8_t hi = payload[13U + i], lo = payload[14U + i];
        if (hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P') break;
        uint8_t c = (uint8_t)(((hi - 'A') << 4) | (lo - 'A'));
        if (c == 0U || c == 0x20U) break;
        result->name[out++] = (char)((c >= 32U && c <= 126U && c != '|') ? c : ' ');
    }
    while (out > 0U && result->name[out - 1U] == ' ') result->name[--out] = '\0';
    return result->name[0] != '\0';
}

/* Address discovery: ARP, NDP and RA ----------------------------------- */

static int argos_discovery_arp_parse(const uint8_t *payload, size_t len,
                                     argos_discovery_arp_t *result) {
    if (!payload || !result || len < 28U || argos_discovery_be16(payload) != 1U ||
        argos_discovery_be16(payload + 2) != 0x0800U || payload[4] != 6U ||
        payload[5] != 4U || !argos_discovery_mac_valid(payload + 8)) return 0;
    memcpy(result->sender_mac, payload + 8, 6);
    memcpy(result->sender_ip, payload + 14, 4);
    memcpy(result->target_ip, payload + 24, 4);
    result->operation = argos_discovery_be16(payload + 6);
    return 1;
}

static const uint8_t *argos_discovery_ndp_lladdr(const uint8_t *icmp, size_t len,
                                                 size_t offset, uint8_t wanted) {
    while (offset + 2U <= len) {
        uint8_t type = icmp[offset], units = icmp[offset + 1U];
        size_t option_len;
        if (units == 0U) break;
        option_len = (size_t)units * 8U;
        if (option_len > len - offset) break;
        if (type == wanted && option_len >= 8U) return icmp + offset + 2U;
        offset += option_len;
    }
    return NULL;
}

static int argos_discovery_ra_parse(const uint8_t *icmp, size_t len,
                                    argos_discovery_ra_t *result) {
    size_t pos, flags = 0;
    if (!icmp || !result || len < 16U || icmp[0] != 134U) return 0;
    memset(result, 0, sizeof(*result));
    result->hop_limit = icmp[4];
    result->lifetime = argos_discovery_be16(icmp + 6);
    if (icmp[5] & 0x80U) result->flags[flags++] = 'M';
    if (icmp[5] & 0x40U) result->flags[flags++] = 'O';
    if (icmp[5] & 0x20U) result->flags[flags++] = 'H';
    if (flags == 0U) result->flags[flags++] = '-';
    result->flags[flags] = '\0';
    for (pos = 16U; pos + 2U <= len;) {
        uint8_t type = icmp[pos], units = icmp[pos + 1U];
        size_t option_len;
        if (units == 0U) break;
        option_len = (size_t)units * 8U;
        if (option_len > len - pos) break;
        if (type == 3U && option_len >= 32U && !result->has_prefix) {
            result->prefix_length = icmp[pos + 2U];
            memcpy(result->prefix, icmp + pos + 16U, 16);
            result->has_prefix = 1U;
        } else if (type == 5U && option_len >= 8U) {
            result->mtu = argos_discovery_be32(icmp + pos + 4U);
        }
        pos += option_len;
    }
    return 1;
}

static int argos_discovery_ndp_parse(const uint8_t *icmp, size_t len,
                                     const uint8_t frame_src_mac[6],
                                     argos_discovery_ndp_t *result) {
    uint8_t type, wanted;
    size_t option_offset, flags = 0;
    const uint8_t *option_mac, *identity_mac;
    if (!icmp || !frame_src_mac || !result || len < 8U) return 0;
    type = icmp[0];
    if (type != 133U && type != 135U && type != 136U) return 0;
    option_offset = type == 133U ? 8U : 24U;
    if (len < option_offset) return 0;
    wanted = type == 136U ? 2U : 1U;
    option_mac = argos_discovery_ndp_lladdr(icmp, len, option_offset, wanted);
    identity_mac = option_mac && argos_discovery_mac_valid(option_mac) ? option_mac : frame_src_mac;

    memset(result, 0, sizeof(*result));
    memcpy(result->identity_mac, identity_mac, 6);
    result->kind = type == 133U ? "RS" : (type == 135U ? "NS" : "NA");
    result->flags[0] = '-'; result->flags[1] = '\0';
    if (type == 135U || type == 136U) {
        memcpy(result->target, icmp + 8, 16);
        result->has_target = 1U;
    }
    if (type == 136U) {
        result->is_advertisement = 1U;
        if (icmp[4] & 0x80U) result->flags[flags++] = 'R';
        if (icmp[4] & 0x40U) result->flags[flags++] = 'S';
        if (icmp[4] & 0x20U) result->flags[flags++] = 'O';
        if (flags == 0U) result->flags[flags++] = '-';
        result->flags[flags] = '\0';
    }
    return 1;
}

/* DHCP ------------------------------------------------------------------ */

static int argos_discovery_dhcp4_parse(const uint8_t *payload, size_t len,
                                       argos_discovery_dhcp4_t *result) {
    size_t pos = 240U;
    int found = 0;
    if (!payload || !result || len < 241U || payload[236] != 0x63U ||
        payload[237] != 0x82U || payload[238] != 0x53U || payload[239] != 0x63U) return 0;
    memset(result, 0, sizeof(*result));
    while (pos < len) {
        uint8_t code = payload[pos++], option_len;
        if (code == 0xffU) break;
        if (code == 0U) continue;
        if (pos >= len) break;
        option_len = payload[pos++];
        if ((size_t)option_len > len - pos) break;
        if (code == 12U) {
            size_t text_len = option_len < 63U ? option_len : 63U;
            while (text_len > 0U && payload[pos + text_len - 1U] == 0U) --text_len;
            for (size_t i = 0; i < text_len; ++i) {
                if (payload[pos + i] == 0U) { text_len = i; break; }
            }
            argos_discovery_sanitize(payload + pos, text_len, result->hostname, sizeof(result->hostname));
            found = 1;
        } else if (code == 60U) {
            size_t text_len = option_len < 63U ? option_len : 63U;
            while (text_len > 0U && payload[pos + text_len - 1U] == 0U) --text_len;
            for (size_t i = 0; i < text_len; ++i) {
                if (payload[pos + i] == 0U) { text_len = i; break; }
            }
            argos_discovery_sanitize(payload + pos, text_len, result->vendor, sizeof(result->vendor));
            found = 1;
        } else if (code == 55U) {
            size_t used = 0;
            for (size_t i = 0; i < option_len && used < sizeof(result->parameter_request_list) - 8U; ++i) {
                int n = snprintf(result->parameter_request_list + used,
                                 sizeof(result->parameter_request_list) - used,
                                 "%s%u", used ? "," : "", (unsigned)payload[pos + i]);
                if (n > 0) used += (size_t)n;
            }
            found = 1;
        }
        pos += option_len;
    }
    return found;
}

static const char *argos_discovery_dhcp6_message(uint8_t type) {
    switch (type) {
        case 1: return "SOLICIT";
        case 3: return "REQUEST";
        case 5: return "RENEW";
        case 6: return "REBIND";
        case 11: return "INFORMATION";
        case 4: return "CONFIRM";
        case 8: return "RELEASE";
        case 9: return "DECLINE";
        default: return "OTHER";
    }
}

static const char *argos_discovery_dhcp6_duid(uint16_t type) {
    switch (type) {
        case 1: return "LLT";
        case 2: return "EN";
        case 3: return "LL";
        case 4: return "UUID";
        default: return "UNKNOWN";
    }
}

static int argos_discovery_dhcp6_name(const uint8_t *buf, size_t len,
                                      char *out, size_t out_size) {
    size_t pos = 0, used = 0;
    if (!buf || !out || out_size == 0U) return 0;
    out[0] = '\0';
    while (pos < len) {
        uint8_t label_len = buf[pos++];
        if (label_len == 0U) break;
        if ((label_len & 0xc0U) != 0U || label_len > 63U || (size_t)label_len > len - pos) return 0;
        if (used != 0U) {
            if (used + 1U >= out_size) return 0;
            out[used++] = '.';
        }
        for (uint8_t i = 0; i < label_len; ++i) {
            uint8_t c;
            if (used + 1U >= out_size) return 0;
            c = buf[pos++];
            out[used++] = (char)((c >= 32U && c <= 126U && c != '|') ? c : '_');
        }
    }
    out[used] = '\0';
    return used > 0U;
}

static int argos_discovery_dhcp6_parse(const uint8_t *payload, size_t len,
                                       argos_discovery_dhcp6_t *result) {
    size_t pos = 4U;
    if (!payload || !result || len < 4U || payload[0] == 12U || payload[0] == 13U) return 0;
    memset(result, 0, sizeof(*result));
    result->message_type = argos_discovery_dhcp6_message(payload[0]);
    result->duid_type = "UNKNOWN";
    strcpy(result->vendor, "none");
    strcpy(result->option_request, "none");
    strcpy(result->fqdn, "none");
    while (pos + 4U <= len) {
        uint16_t code = argos_discovery_be16(payload + pos);
        uint16_t option_len = argos_discovery_be16(payload + pos + 2U);
        const uint8_t *value;
        pos += 4U;
        if ((size_t)option_len > len - pos) break;
        value = payload + pos;
        if (code == 1U && option_len >= 2U) {
            result->duid_type = argos_discovery_dhcp6_duid(argos_discovery_be16(value));
        } else if (code == 6U && option_len >= 2U) {
            size_t used = 0;
            result->option_request[0] = '\0';
            for (size_t i = 0; i + 1U < option_len; i += 2U) {
                uint16_t requested = argos_discovery_be16(value + i);
                int n = snprintf(result->option_request + used, sizeof(result->option_request) - used,
                                 "%s%u", used ? "," : "", (unsigned)requested);
                if (n < 0 || (size_t)n >= sizeof(result->option_request) - used) break;
                used += (size_t)n;
            }
            if (result->option_request[0] == '\0') strcpy(result->option_request, "none");
        } else if (code == 16U && option_len >= 6U) {
            size_t value_pos = 4U;
            uint16_t vendor_len = argos_discovery_be16(value + value_pos);
            value_pos += 2U;
            if ((size_t)vendor_len <= (size_t)option_len - value_pos) {
                argos_discovery_sanitize(value + value_pos, vendor_len, result->vendor, sizeof(result->vendor));
                if (result->vendor[0] == '\0') strcpy(result->vendor, "none");
            }
        } else if (code == 39U && option_len >= 2U &&
                   !argos_discovery_dhcp6_name(value + 1U, (size_t)option_len - 1U,
                                                result->fqdn, sizeof(result->fqdn))) {
            strcpy(result->fqdn, "none");
        }
        pos += option_len;
    }
    return 1;
}

/* DNS names and mDNS ----------------------------------------------------- */

static int argos_discovery_dns_name(const uint8_t *payload, int payload_len,
                                    int start_pos, char *out, int out_max) {
    int pos = start_pos, used = 0, guard = 0, original_pos = -1;
    if (!payload || !out || payload_len <= 0 || start_pos < 0 ||
        start_pos >= payload_len || out_max <= 0) return 0;
    while (guard++ < 64) {
        uint8_t label_len;
        if (pos >= payload_len) break;
        label_len = payload[pos++];
        if (label_len == 0U) {
            if (original_pos != -1) {
                pos = original_pos;
                original_pos = -1;
                continue;
            }
            break;
        }
        if ((label_len & 0xc0U) == 0xc0U) {
            int pointer;
            if (pos >= payload_len) break;
            pointer = ((label_len & 0x3fU) << 8) | payload[pos++];
            if (original_pos == -1) original_pos = pos;
            pos = pointer;
            continue;
        }
        if (label_len > 63U || pos + label_len > payload_len) break;
        if (used > 0 && used < out_max - 1) out[used++] = '.';
        for (int i = 0; i < label_len && pos < payload_len && used < out_max - 1; ++i) {
            uint8_t c = payload[pos++];
            out[used++] = (char)((isalnum(c) || c == '-' || c == '_') ? tolower(c) : '.');
        }
    }
    out[used] = '\0';
    return used;
}

static int argos_discovery_dns_qtype(const uint8_t *payload, int payload_len,
                                     int start_pos, uint16_t *qtype) {
    int pos = start_pos, guard = 0;
    if (!payload || !qtype || start_pos < 0 || start_pos >= payload_len) return 0;
    while (pos < payload_len && guard++ < 128) {
        uint8_t label_len = payload[pos++];
        if (label_len == 0U) break;
        if ((label_len & 0xc0U) == 0xc0U) {
            if (pos >= payload_len) return 0;
            ++pos;
            break;
        }
        if (label_len > 63U || pos + label_len > payload_len) return 0;
        pos += label_len;
    }
    if (pos + 4 > payload_len) return 0;
    *qtype = argos_discovery_be16(payload + pos);
    return 1;
}

static int argos_discovery_mdns_parse(const uint8_t *payload, size_t len,
                                      argos_discovery_mdns_t *result) {
    if (!payload || !result || len < 12U || argos_discovery_be16(payload + 4) == 0U) return 0;
    memset(result, 0, sizeof(*result));
    return argos_discovery_dns_name(payload, (int)len, 12, result->question,
                                    (int)sizeof(result->question)) > 0 && result->question[0] != '\0';
}

#endif
