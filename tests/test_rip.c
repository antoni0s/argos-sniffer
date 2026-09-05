#include <assert.h>
#include <string.h>

#include "../src/argos_network.h"

static void put16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}

static void test_headers(void) {
    argos_network_rip_result_t r;
    unsigned char v1[4] = {1, 1, 0, 0};
    assert(argos_network_rip_parse(v1, sizeof(v1), &r));
    assert(r.kind == ARGOS_NETWORK_RIP_V1);
    assert(strcmp(r.detail,
        "version=1 command=request entries=0 auth=none next_hop_present=0") == 0);

    unsigned char ng[4] = {2, 1, 0, 0};
    assert(argos_network_ripng_parse(ng, sizeof(ng), &r));
    assert(r.kind == ARGOS_NETWORK_RIP_NG);
    assert(strcmp(r.detail,
        "version=ng command=response entries=0 auth=- next_hop_present=0") == 0);
}

static void test_ripv2_route_and_auth(void) {
    argos_network_rip_result_t r;
    unsigned char packet[44] = {2, 2, 0, 0};
    put16(packet + 4, 0xffffU); put16(packet + 6, 2U);
    memcpy(packet + 8, "private-password", 16U);
    put16(packet + 24, 2U);
    packet[36] = 192U; packet[37] = 0U; packet[38] = 2U; packet[39] = 1U;
    packet[43] = 1U;
    assert(argos_network_rip_parse(packet, sizeof(packet), &r));
    assert(r.auth == ARGOS_NETWORK_RIP_AUTH_SIMPLE);
    assert(r.entry_count == 1U && r.next_hop_present == 1U);
    assert(strcmp(r.detail,
        "version=2 command=response entries=1 auth=simple next_hop_present=1") == 0);
    assert(strstr(r.detail, "private") == NULL);

    put16(packet + 6, 3U);
    memset(packet + 8, 0xa5, 16U);
    assert(argos_network_rip_parse(packet, sizeof(packet), &r));
    assert(strcmp(r.detail,
        "version=2 command=response entries=1 auth=md5 next_hop_present=1") == 0);
    assert(strstr(r.detail, "a5") == NULL);

    put16(packet + 6, 99U);
    assert(argos_network_rip_parse(packet, sizeof(packet), &r));
    assert(strstr(r.detail, "auth=-") != NULL);
}

static void test_ripng_next_hop(void) {
    argos_network_rip_result_t r;
    unsigned char packet[44] = {2, 1, 0, 0};
    packet[4] = 0xfeU; packet[5] = 0x80U; packet[23] = 0xffU;
    packet[24] = 0x20U; packet[25] = 0x01U;
    packet[42] = 64U; packet[43] = 2U;
    assert(argos_network_ripng_parse(packet, sizeof(packet), &r));
    assert(r.entry_count == 1U && r.next_hop_present == 1U);
    assert(strcmp(r.detail,
        "version=ng command=response entries=1 auth=- next_hop_present=1") == 0);
}

static void test_rejections(void) {
    argos_network_rip_result_t r;
    unsigned char p[24] = {1, 2, 0, 0};
    assert(!argos_network_rip_parse(NULL, sizeof(p), &r));
    assert(!argos_network_rip_parse(p, sizeof(p), NULL));
    assert(!argos_network_rip_parse(p, 3U, &r));
    assert(!argos_network_rip_parse(p, 23U, &r));
    p[0] = 3U; assert(!argos_network_rip_parse(p, sizeof(p), &r));
    p[0] = 1U; p[1] = 3U; assert(!argos_network_rip_parse(p, sizeof(p), &r));
    p[1] = 2U; p[2] = 1U; assert(!argos_network_rip_parse(p, sizeof(p), &r));
    p[2] = 0U; put16(p + 4, 0xffffU); put16(p + 6, 2U); p[1] = 1U;
    assert(!argos_network_rip_parse(p, sizeof(p), &r));
    memset(p, 0, sizeof(p)); p[0] = 2U; p[1] = 2U;
    put16(p + 4, 2U); p[23] = 17U;
    assert(!argos_network_rip_parse(p, sizeof(p), &r));

    memset(p, 0, sizeof(p)); p[0] = 1U; p[1] = 1U; p[22] = 129U; p[23] = 1U;
    assert(!argos_network_ripng_parse(p, sizeof(p), &r));
    p[22] = 64U; p[23] = 17U;
    assert(!argos_network_ripng_parse(p, sizeof(p), &r));
    p[23] = 0U;
    assert(!argos_network_ripng_parse(p, sizeof(p), &r));
    p[20] = 1U; p[22] = 0U; p[23] = 0xffU;
    assert(!argos_network_ripng_parse(p, sizeof(p), &r));
    p[20] = 0U;
    p[23] = 16U; p[1] = 2U;
    assert(!argos_network_ripng_parse(p, sizeof(p), &r));

    unsigned char oversized[4104] = {1, 2, 0, 0};
    assert(!argos_network_rip_parse(oversized, sizeof(oversized), &r));
    unsigned char maximum[4084] = {1, 2, 0, 0};
    for (size_t i = 4U; i < sizeof(maximum); i += 20U) maximum[i + 19U] = 16U;
    assert(argos_network_rip_parse(maximum, sizeof(maximum), &r));
    assert(r.entry_count == 204U);
}

int main(void) {
    _Static_assert(sizeof(argos_network_rip_result_t) == 144U,
                   "RIP automatic result budget changed");
    test_headers();
    test_ripv2_route_and_auth();
    test_ripng_next_hop();
    test_rejections();
    return 0;
}
