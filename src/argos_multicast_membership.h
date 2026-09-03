#ifndef ARGOS_MULTICAST_MEMBERSHIP_H
#define ARGOS_MULTICAST_MEMBERSHIP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int emit;
    char proto[8];
    char detail[192];
} argos_membership_result_t;

static inline uint16_t amm_be16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline int amm_zero16(const unsigned char *p) {
    unsigned char v = 0;
    for (unsigned i = 0; i < 16U; ++i) v |= p[i];
    return v == 0U;
}

static inline int argos_igmp_parse(const unsigned char *p, size_t len,
                                   argos_membership_result_t *r) {
    if (!p || !r || len < 8U) return 0;
    memset(r, 0, sizeof(*r));
    const unsigned type = p[0];
    unsigned version = 0U, records = 0U, sources = 0U, group_specific = 0U;
    const char *kind = NULL;

    if (type == 0x11U) {
        kind = "query";
        group_specific = (p[4] | p[5] | p[6] | p[7]) != 0U;
        if (len >= 12U) {
            version = 3U;
            sources = amm_be16(p + 10);
            if (12U + 4U * (size_t)sources > len) return 0;
        } else {
            version = p[1] == 0U ? 1U : 2U;
        }
    } else if (type == 0x12U) {
        version = 1U; kind = "report"; group_specific = 1U;
    } else if (type == 0x16U) {
        version = 2U; kind = "report"; group_specific = 1U;
    } else if (type == 0x17U) {
        version = 2U; kind = "leave"; group_specific = 1U;
    } else if (type == 0x22U) {
        version = 3U; kind = "report";
        records = amm_be16(p + 6);
        if (records > 64U) return 0;
        size_t pos = 8U;
        for (unsigned i = 0; i < records; ++i) {
            if (pos + 8U > len) return 0;
            unsigned aux_words = p[pos + 1];
            unsigned nsrc = amm_be16(p + pos + 2);
            if (nsrc > 1024U) return 0;
            size_t need = 8U + 4U * (size_t)nsrc + 4U * (size_t)aux_words;
            if (need > len - pos) return 0;
            if (sources > 65535U - nsrc) return 0;
            sources += nsrc;
            pos += need;
        }
        group_specific = records != 0U;
    } else {
        return 0;
    }

    r->emit = 1;
    snprintf(r->proto, sizeof(r->proto), "IGMP");
    snprintf(r->detail, sizeof(r->detail),
             "version=%u type=%s records=%u sources=%u group_specific=%u",
             version, kind, records, sources, group_specific);
    return 1;
}

static inline int argos_mld_parse(const unsigned char *p, size_t len,
                                  argos_membership_result_t *r) {
    if (!p || !r || len < 8U) return 0;
    memset(r, 0, sizeof(*r));
    const unsigned type = p[0];
    unsigned version = 0U, records = 0U, sources = 0U, group_specific = 0U;
    const char *kind = NULL;

    if (type == 130U) {
        if (len < 24U) return 0;
        kind = "query";
        group_specific = !amm_zero16(p + 8);
        if (len >= 28U) {
            version = 2U;
            sources = amm_be16(p + 26);
            if (28U + 16U * (size_t)sources > len) return 0;
        } else {
            version = 1U;
        }
    } else if (type == 131U) {
        if (len < 24U) return 0;
        version = 1U; kind = "report"; group_specific = 1U;
    } else if (type == 132U) {
        if (len < 24U) return 0;
        version = 1U; kind = "done"; group_specific = 1U;
    } else if (type == 143U) {
        version = 2U; kind = "report";
        records = amm_be16(p + 6);
        if (records > 64U) return 0;
        size_t pos = 8U;
        for (unsigned i = 0; i < records; ++i) {
            if (pos + 20U > len) return 0;
            unsigned aux_words = p[pos + 1];
            unsigned nsrc = amm_be16(p + pos + 2);
            if (nsrc > 1024U) return 0;
            size_t need = 20U + 16U * (size_t)nsrc + 4U * (size_t)aux_words;
            if (need > len - pos) return 0;
            if (sources > 65535U - nsrc) return 0;
            sources += nsrc;
            pos += need;
        }
        group_specific = records != 0U;
    } else {
        return 0;
    }

    r->emit = 1;
    snprintf(r->proto, sizeof(r->proto), "MLD");
    snprintf(r->detail, sizeof(r->detail),
             "version=%u type=%s records=%u sources=%u group_specific=%u",
             version, kind, records, sources, group_specific);
    return 1;
}

#endif
