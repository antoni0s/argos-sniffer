#ifndef ARGOS_DISPATCH_H
#define ARGOS_DISPATCH_H

#include <stdint.h>
#include <string.h>

#include "argos_config.h"

/* Startup-derived route demand. These flags are control-plane data compiled
 * from the canonical protocol bitmap; packet processing must never scan the
 * catalogs or selector strings. Conservative encapsulation fallback remains
 * the BPF owner's responsibility. */
enum {
    ARGOS_DISPATCH_L2_ARP      = UINT16_C(1) << 0,
    ARGOS_DISPATCH_L2_LLDP     = UINT16_C(1) << 1,
    ARGOS_DISPATCH_L2_LLC      = UINT16_C(1) << 2,
    ARGOS_DISPATCH_L2_SLOW     = UINT16_C(1) << 3,
    ARGOS_DISPATCH_L2_EAPOL    = UINT16_C(1) << 4,
    ARGOS_DISPATCH_L2_PROFINET = UINT16_C(1) << 5
};

enum {
    ARGOS_DISPATCH_L3_IPV4   = UINT16_C(1) << 0,
    ARGOS_DISPATCH_L3_IPV6   = UINT16_C(1) << 1,
    ARGOS_DISPATCH_L3_ICMPV6 = UINT16_C(1) << 2,
    ARGOS_DISPATCH_L3_IGMP   = UINT16_C(1) << 3,
    ARGOS_DISPATCH_L3_OSPF   = UINT16_C(1) << 4,
    ARGOS_DISPATCH_L3_VRRP   = UINT16_C(1) << 5
};

enum {
    ARGOS_DISPATCH_L4_TCP = UINT16_C(1) << 0,
    ARGOS_DISPATCH_L4_UDP = UINT16_C(1) << 1
};

typedef struct {
    argos_protocol_selection_t protocols;
    argos_feature_selection_t features;
    uint16_t l2_routes;
    uint16_t l3_routes;
    uint16_t l4_routes;
    uint16_t reserved;
} argos_dispatch_plan_t;

static inline int argos_dispatch_protocol_enabled(
    const argos_dispatch_plan_t *plan, argos_protocol_id_t protocol)
{
    return plan && argos_protocol_set_has(&plan->protocols.enabled, protocol);
}

static inline int argos_dispatch_l2_enabled(const argos_dispatch_plan_t *plan,
                                            uint16_t routes)
{
    return plan && (plan->l2_routes & routes) != 0U;
}

static inline int argos_dispatch_l3_enabled(const argos_dispatch_plan_t *plan,
                                            uint16_t routes)
{
    return plan && (plan->l3_routes & routes) != 0U;
}

static inline int argos_dispatch_l4_enabled(const argos_dispatch_plan_t *plan,
                                            uint16_t routes)
{
    return plan && (plan->l4_routes & routes) != 0U;
}

static inline int argos_dispatch_legacy_enabled(
    const argos_dispatch_plan_t *plan, argos_legacy_category_id_t category)
{
    argos_cli_selection_t view;
    if (!plan) return 0;
    memset(&view, 0, sizeof(view));
    view.protocols = plan->protocols;
    view.features = plan->features;
    return argos_cli_legacy_category_enabled(&view, category);
}

static inline int argos_dispatch_legacy_rate_limited(
    const argos_dispatch_plan_t *plan, argos_legacy_category_id_t category)
{
    argos_cli_selection_t view;
    if (!plan) return 0;
    memset(&view, 0, sizeof(view));
    view.protocols = plan->protocols;
    view.features = plan->features;
    return argos_cli_legacy_category_rate_limited(&view, category);
}

static inline void argos_dispatch_plan_compile(
    argos_dispatch_plan_t *plan, const argos_cli_selection_t *selection)
{
    if (!plan) return;
    memset(plan, 0, sizeof(*plan));
    if (!selection) return;
    plan->protocols = selection->protocols;
    plan->features = selection->features;

#define ARGOS_DISPATCH_HAS(protocol) \
    argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_##protocol)
    if (ARGOS_DISPATCH_HAS(ARP)) plan->l2_routes |= ARGOS_DISPATCH_L2_ARP;
    if (ARGOS_DISPATCH_HAS(LLDP) || ARGOS_DISPATCH_HAS(LLDP_MED))
        plan->l2_routes |= ARGOS_DISPATCH_L2_LLDP;
    if (ARGOS_DISPATCH_HAS(CDP) || ARGOS_DISPATCH_HAS(EDP) ||
        ARGOS_DISPATCH_HAS(FDP) || ARGOS_DISPATCH_HAS(ISIS) ||
        ARGOS_DISPATCH_HAS(STP))
        plan->l2_routes |= ARGOS_DISPATCH_L2_LLC;
    if (ARGOS_DISPATCH_HAS(LACP)) plan->l2_routes |= ARGOS_DISPATCH_L2_SLOW;
    if (ARGOS_DISPATCH_HAS(EAPOL)) plan->l2_routes |= ARGOS_DISPATCH_L2_EAPOL;
    if (ARGOS_DISPATCH_HAS(PROFINET)) plan->l2_routes |= ARGOS_DISPATCH_L2_PROFINET;

    if (ARGOS_DISPATCH_HAS(NDP) || ARGOS_DISPATCH_HAS(RA) || ARGOS_DISPATCH_HAS(MLD))
        plan->l3_routes |= ARGOS_DISPATCH_L3_ICMPV6;
    if (ARGOS_DISPATCH_HAS(IGMP)) plan->l3_routes |= ARGOS_DISPATCH_L3_IGMP;
    if (ARGOS_DISPATCH_HAS(OSPF)) plan->l3_routes |= ARGOS_DISPATCH_L3_OSPF;
    if (ARGOS_DISPATCH_HAS(VRRP)) plan->l3_routes |= ARGOS_DISPATCH_L3_VRRP;

    if (argos_feature_selection_has(&plan->features, ARGOS_FEATURE_TCP_SYN) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_HTTP) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_TLS) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_ENTERPRISE))
        plan->l4_routes |= ARGOS_DISPATCH_L4_TCP;
    if (argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_MULTI) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_DHCP) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_NETBIOS) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_DNS) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_TLS) ||
        argos_dispatch_legacy_enabled(plan, ARGOS_LEGACY_CATEGORY_ENTERPRISE))
        plan->l4_routes |= ARGOS_DISPATCH_L4_UDP;
    if (plan->l4_routes != 0U ||
        (plan->l3_routes & (ARGOS_DISPATCH_L3_IGMP | ARGOS_DISPATCH_L3_OSPF |
                            ARGOS_DISPATCH_L3_VRRP)) != 0U)
        plan->l3_routes |= ARGOS_DISPATCH_L3_IPV4;
    if (argos_feature_selection_has(&plan->features, ARGOS_FEATURE_IPV6) &&
        (plan->l4_routes != 0U ||
         (plan->l3_routes & ARGOS_DISPATCH_L3_ICMPV6) != 0U))
        plan->l3_routes |= ARGOS_DISPATCH_L3_IPV6;
#undef ARGOS_DISPATCH_HAS
}

#endif
