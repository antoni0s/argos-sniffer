#ifndef ARGOS_MONGODB_H
#define ARGOS_MONGODB_H

/* Argos-Sniffer v6 staging engine: MongoDB wire protocol.
 * Standalone passive parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int seen;
    int32_t message_length;
    int32_t request_id;
    int32_t response_to;
    int32_t opcode;
    char opcode_name[24];
    char detail[256];
} argos_mongodb_result_t;

static inline int32_t amg_le32(const unsigned char *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static inline const char *amg_opcode_name(int32_t op) {
    switch (op) {
        case 1: return "OP_REPLY";
        case 1000: return "OP_MSG_LEGACY";
        case 2001: return "OP_UPDATE";
        case 2002: return "OP_INSERT";
        case 2004: return "OP_QUERY";
        case 2005: return "OP_GET_MORE";
        case 2006: return "OP_DELETE";
        case 2007: return "OP_KILL_CURSORS";
        case 2012: return "OP_COMPRESSED";
        case 2013: return "OP_MSG";
        default: return "unknown";
    }
}

static inline int argos_mongodb_parse(const unsigned char *p, size_t n,
                                      argos_mongodb_result_t *r) {
    if (!p || !r || n < 16U) return 0;
    memset(r, 0, sizeof(*r));

    r->message_length = amg_le32(p + 0);
    r->request_id = amg_le32(p + 4);
    r->response_to = amg_le32(p + 8);
    r->opcode = amg_le32(p + 12);

    if (r->message_length < 16 || (size_t)r->message_length > n) return 0;
    if (!strcmp(amg_opcode_name(r->opcode), "unknown")) return 0;

    r->seen = 1;
    (void)snprintf(r->opcode_name, sizeof(r->opcode_name), "%s", amg_opcode_name(r->opcode));
    (void)snprintf(r->detail, sizeof(r->detail),
                   "len=%d;request_id=%d;response_to=%d;opcode=%d(%s)",
                   r->message_length, r->request_id, r->response_to,
                   r->opcode, r->opcode_name);
    return 1;
}

#endif /* ARGOS_MONGODB_H */
