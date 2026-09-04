/* Test-only oracle: routed predicates from version-6 b44ad286. Never runtime. */
#ifndef ARGOS_TEST_NETWORK_CONTEXT_LEGACY_H
#define ARGOS_TEST_NETWORK_CONTEXT_LEGACY_H
#include "../src/argos_network.h"
static inline int legacy_routed4(const argos_network_state_t *state, uint32_t ip_be, int ifindex) {
    if (!argos_network_iface_has_family(state, ifindex, AF_INET) ||
        argos_network_direct4(state, ip_be, ifindex)) return 0;
    uint32_t ip = ntohl(ip_be);
    return (ip & 0xFF000000U) == 0x0A000000U || (ip & 0xFFF00000U) == 0xAC100000U ||
           (ip & 0xFFFF0000U) == 0xC0A80000U || (ip & 0xFFC00000U) == 0x64400000U;
}
static inline int legacy_routed6(const argos_network_state_t *state, const struct in6_addr *addr, int ifindex) {
    if (!addr || !argos_network_iface_has_family(state, ifindex, AF_INET6) ||
        argos_network_direct6(state, addr, ifindex)) return 0;
    if ((addr->s6_addr[0] & 0xFEU) == 0xFCU) return 1;
    if ((addr->s6_addr[0] & 0xE0U) != 0x20U) return 0;
    for (int i = 0; i < state->learned_count; ++i) {
        const argos_network_prefix_t *p = &state->learned[i];
        if (p->family == AF_INET6 && p->ifindex == ifindex &&
            (p->v6.s6_addr[0] & 0xE0U) == 0x20U &&
            memcmp(addr->s6_addr, p->v6.s6_addr, 6) == 0) return 1;
    }
    return 0;
}
#endif
