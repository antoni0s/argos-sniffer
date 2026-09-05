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
    ARGOS_DISPATCH_L2_PROFINET = UINT16_C(1) << 5,
    ARGOS_DISPATCH_L2_PTP      = UINT16_C(1) << 6
};

enum {
    ARGOS_DISPATCH_L3_IPV4   = UINT16_C(1) << 0,
    ARGOS_DISPATCH_L3_IPV6   = UINT16_C(1) << 1,
    ARGOS_DISPATCH_L3_ICMPV6 = UINT16_C(1) << 2,
    ARGOS_DISPATCH_L3_IGMP   = UINT16_C(1) << 3,
    ARGOS_DISPATCH_L3_OSPF   = UINT16_C(1) << 4,
    ARGOS_DISPATCH_L3_VRRP   = UINT16_C(1) << 5,
    ARGOS_DISPATCH_L3_ESP    = UINT16_C(1) << 6,
    ARGOS_DISPATCH_L3_AH     = UINT16_C(1) << 7
};

enum {
    ARGOS_DISPATCH_L4_TCP = UINT16_C(1) << 0,
    ARGOS_DISPATCH_L4_UDP = UINT16_C(1) << 1
};

enum {
    ARGOS_DISPATCH_TRANSPORT_TCP_OWNER = UINT16_C(1) << 0,
    ARGOS_DISPATCH_TRANSPORT_UDP_OWNER = UINT16_C(1) << 1
};

typedef struct {
    argos_protocol_selection_t protocols;
    argos_feature_selection_t features;
    uint16_t l2_routes;
    uint16_t l3_routes;
    uint16_t l4_routes;
    uint16_t transport_routes;
} argos_dispatch_plan_t;

static inline int argos_dispatch_protocol_enabled(
    const argos_dispatch_plan_t *plan, argos_protocol_id_t protocol)
{
    return plan && argos_protocol_set_has(&plan->protocols.enabled, protocol);
}

static inline int argos_dispatch_protocol_rate_limited(
    const argos_dispatch_plan_t *plan, argos_protocol_id_t protocol)
{
    return argos_dispatch_protocol_enabled(plan, protocol) &&
           !argos_protocol_set_has(&plan->protocols.unrated, protocol);
}

static inline int argos_dispatch_any_rate_limited(
    const argos_dispatch_plan_t *plan)
{
    if (!plan) return 0;
    for (size_t i = 0; i < ARGOS_PROTOCOL_WORDS; ++i)
        if ((plan->protocols.enabled.words[i] &
             ~plan->protocols.unrated.words[i]) != 0U)
            return 1;
    return (plan->features.enabled & ~plan->features.unrated &
            argos_feature_bit(ARGOS_FEATURE_TCP_SYN)) != 0U;
}

/* Packet normalization preserves these synthetic discriminators for LLC/SNAP
 * protocols. Resolve them once with a bounded switch before any parser call. */
static inline argos_protocol_id_t argos_dispatch_l2_protocol(uint16_t protocol)
{
    switch (protocol) {
        case 0x0806U: return ARGOS_PROTOCOL_ARP;
        case 0x8809U: return ARGOS_PROTOCOL_LACP;
        case 0x888eU: return ARGOS_PROTOCOL_EAPOL;
        case 0x8892U: return ARGOS_PROTOCOL_PROFINET;
        case 0x88f7U: return ARGOS_PROTOCOL_PTP;
        case 0x2000U: return ARGOS_PROTOCOL_CDP;
        case 0x00feU: return ARGOS_PROTOCOL_ISIS;
        case 0x00bbU: return ARGOS_PROTOCOL_EDP;
        case 0xf200U: return ARGOS_PROTOCOL_FDP;
        default:
            return protocol <= 1500U ? ARGOS_PROTOCOL_STP : ARGOS_PROTOCOL_COUNT;
    }
}

/* Exact no-port IP owner resolution. HOLD bits can be characterized through
 * this fixed switch without becoming selectable through the production CLI. */
static inline argos_protocol_id_t argos_dispatch_ip_protocol_engine(
    const argos_dispatch_plan_t *plan, uint8_t protocol)
{
    argos_protocol_id_t engine;
    switch (protocol) {
        case 2U: engine = ARGOS_PROTOCOL_IGMP; break;
        case 50U: engine = ARGOS_PROTOCOL_ESP; break;
        case 51U: engine = ARGOS_PROTOCOL_AH; break;
        case 89U: engine = ARGOS_PROTOCOL_OSPF; break;
        case 112U: engine = ARGOS_PROTOCOL_VRRP; break;
        default: return ARGOS_PROTOCOL_COUNT;
    }
    return argos_dispatch_protocol_enabled(plan, engine) ? engine : ARGOS_PROTOCOL_COUNT;
}

static inline int argos_dispatch_ptp_udp_enabled(
    const argos_dispatch_plan_t *plan, uint16_t sport, uint16_t dport)
{
    return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_PTP) &&
           (sport == 319U || sport == 320U || dport == 319U || dport == 320U);
}

static inline int argos_dispatch_l2_frame_enabled(
    const argos_dispatch_plan_t *plan, uint16_t protocol)
{
    argos_protocol_id_t engine;
    if (protocol == 0x88ccU)
        return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_LLDP) ||
               argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_LLDP_MED);
    engine = argos_dispatch_l2_protocol(protocol);
    return engine < ARGOS_PROTOCOL_COUNT &&
           argos_dispatch_protocol_enabled(plan, engine);
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

static inline argos_protocol_id_t argos_dispatch_first_enabled(
    const argos_dispatch_plan_t *plan, argos_protocol_id_t first,
    argos_protocol_id_t second, argos_protocol_id_t third)
{
    if (argos_dispatch_protocol_enabled(plan, first)) return first;
    if (argos_dispatch_protocol_enabled(plan, second)) return second;
    if (argos_dispatch_protocol_enabled(plan, third)) return third;
    return ARGOS_PROTOCOL_COUNT;
}

/* Resolve the current cohesive transport owner's parser before payload/state
 * work. Destination service wins, matching the frozen parser; source is used
 * for the response direction only when destination is not a known service. */
static inline argos_protocol_id_t argos_dispatch_tcp_port_engine(
    const argos_dispatch_plan_t *plan, uint16_t sport, uint16_t dport)
{
    if (!plan || (plan->transport_routes & ARGOS_DISPATCH_TRANSPORT_TCP_OWNER) == 0U)
        return ARGOS_PROTOCOL_COUNT;
    uint16_t port = dport;
    switch (port) {
        case 22: case 88: case 111: case 179: case 445: case 502: case 514: case 515: case 631:
        case 1433: case 1521: case 1883: case 2000: case 2049: case 3260:
        case 3306: case 3389: case 4739: case 5060: case 5432: case 9100: case 44818:
            break;
        default: port = sport; break;
    }
    switch (port) {
        case 22: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SSH) ? ARGOS_PROTOCOL_SSH : ARGOS_PROTOCOL_COUNT;
        case 88: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_KERBEROS) ? ARGOS_PROTOCOL_KERBEROS : ARGOS_PROTOCOL_COUNT;
        case 111: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SUNRPC) ? ARGOS_PROTOCOL_SUNRPC : ARGOS_PROTOCOL_COUNT;
        case 179: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_BGP) ? ARGOS_PROTOCOL_BGP : ARGOS_PROTOCOL_COUNT;
        case 445: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SMB) ? ARGOS_PROTOCOL_SMB : ARGOS_PROTOCOL_COUNT;
        case 502: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_MODBUS) ? ARGOS_PROTOCOL_MODBUS : ARGOS_PROTOCOL_COUNT;
        case 514: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SYSLOG) ? ARGOS_PROTOCOL_SYSLOG : ARGOS_PROTOCOL_COUNT;
        case 515: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_LPD) ? ARGOS_PROTOCOL_LPD : ARGOS_PROTOCOL_COUNT;
        case 631: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_IPP) ? ARGOS_PROTOCOL_IPP : ARGOS_PROTOCOL_COUNT;
        case 1433: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_MSSQL) ? ARGOS_PROTOCOL_MSSQL : ARGOS_PROTOCOL_COUNT;
        case 1521: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_ORACLE) ? ARGOS_PROTOCOL_ORACLE : ARGOS_PROTOCOL_COUNT;
        case 1883: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_MQTT) ? ARGOS_PROTOCOL_MQTT : ARGOS_PROTOCOL_COUNT;
        case 2000: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SCCP) ? ARGOS_PROTOCOL_SCCP : ARGOS_PROTOCOL_COUNT;
        case 2049: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_NFS) ? ARGOS_PROTOCOL_NFS : ARGOS_PROTOCOL_COUNT;
        case 3260: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_ISCSI) ? ARGOS_PROTOCOL_ISCSI : ARGOS_PROTOCOL_COUNT;
        case 3306: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_MYSQL) ? ARGOS_PROTOCOL_MYSQL : ARGOS_PROTOCOL_COUNT;
        case 3389: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_RDP) ? ARGOS_PROTOCOL_RDP : ARGOS_PROTOCOL_COUNT;
        case 4739: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_IPFIX) ? ARGOS_PROTOCOL_IPFIX : ARGOS_PROTOCOL_COUNT;
        case 5060: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SIP) ? ARGOS_PROTOCOL_SIP : ARGOS_PROTOCOL_COUNT;
        case 5432: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_POSTGRESQL) ? ARGOS_PROTOCOL_POSTGRESQL : ARGOS_PROTOCOL_COUNT;
        case 9100: return argos_dispatch_first_enabled(plan, ARGOS_PROTOCOL_PJL, ARGOS_PROTOCOL_JETDIRECT, ARGOS_PROTOCOL_COUNT);
        case 44818: return argos_dispatch_first_enabled(plan, ARGOS_PROTOCOL_ETHERNET_IP, ARGOS_PROTOCOL_CIP, ARGOS_PROTOCOL_COUNT);
        default: return ARGOS_PROTOCOL_COUNT;
    }
}

static inline argos_protocol_id_t argos_dispatch_udp_port_engine(
    const argos_dispatch_plan_t *plan, uint16_t sport, uint16_t dport)
{
    if (!plan || (plan->transport_routes & ARGOS_DISPATCH_TRANSPORT_UDP_OWNER) == 0U)
        return ARGOS_PROTOCOL_COUNT;
    uint16_t port = dport;
    switch (port) {
        case 88: case 111: case 123: case 161: case 162: case 389: case 427: case 514:
        case 520: case 521:
        case 623: case 1812: case 1813: case 1985: case 2049: case 2055: case 3478:
        case 4739: case 5060: case 5678: case 5683: case 6343: case 9995: case 9996:
        case 44818: case 47808:
            break;
        default: port = sport; break;
    }
    switch (port) {
        case 88: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_KERBEROS) ? ARGOS_PROTOCOL_KERBEROS : ARGOS_PROTOCOL_COUNT;
        case 111: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SUNRPC) ? ARGOS_PROTOCOL_SUNRPC : ARGOS_PROTOCOL_COUNT;
        case 123: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_NTP) ? ARGOS_PROTOCOL_NTP : ARGOS_PROTOCOL_COUNT;
        case 161: case 162: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SNMP) ? ARGOS_PROTOCOL_SNMP : ARGOS_PROTOCOL_COUNT;
        case 389: return argos_dispatch_first_enabled(plan, ARGOS_PROTOCOL_CLDAP, ARGOS_PROTOCOL_NETLOGON, ARGOS_PROTOCOL_COUNT);
        case 427: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_VMWARE_SLP) ? ARGOS_PROTOCOL_VMWARE_SLP : ARGOS_PROTOCOL_COUNT;
        case 514: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SYSLOG) ? ARGOS_PROTOCOL_SYSLOG : ARGOS_PROTOCOL_COUNT;
        case 520: case 521: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_RIP) ? ARGOS_PROTOCOL_RIP : ARGOS_PROTOCOL_COUNT;
        case 623: return argos_dispatch_first_enabled(plan, ARGOS_PROTOCOL_IPMI, ARGOS_PROTOCOL_RMCP, ARGOS_PROTOCOL_ASF);
        case 1812: case 1813: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_RADIUS) ? ARGOS_PROTOCOL_RADIUS : ARGOS_PROTOCOL_COUNT;
        case 1985: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_HSRP) ? ARGOS_PROTOCOL_HSRP : ARGOS_PROTOCOL_COUNT;
        case 2049: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_NFS) ? ARGOS_PROTOCOL_NFS : ARGOS_PROTOCOL_COUNT;
        case 2055: case 9995: case 9996: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_NETFLOW) ? ARGOS_PROTOCOL_NETFLOW : ARGOS_PROTOCOL_COUNT;
        case 3478: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_STUN_TURN) ? ARGOS_PROTOCOL_STUN_TURN : ARGOS_PROTOCOL_COUNT;
        case 4739: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_IPFIX) ? ARGOS_PROTOCOL_IPFIX : ARGOS_PROTOCOL_COUNT;
        case 5060: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SIP) ? ARGOS_PROTOCOL_SIP : ARGOS_PROTOCOL_COUNT;
        case 5678: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_MNDP) ? ARGOS_PROTOCOL_MNDP : ARGOS_PROTOCOL_COUNT;
        case 5683: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_COAP) ? ARGOS_PROTOCOL_COAP : ARGOS_PROTOCOL_COUNT;
        case 6343: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_SFLOW) ? ARGOS_PROTOCOL_SFLOW : ARGOS_PROTOCOL_COUNT;
        case 44818: return argos_dispatch_first_enabled(plan, ARGOS_PROTOCOL_ETHERNET_IP, ARGOS_PROTOCOL_CIP, ARGOS_PROTOCOL_COUNT);
        case 47808: return argos_dispatch_protocol_enabled(plan, ARGOS_PROTOCOL_BACNET) ? ARGOS_PROTOCOL_BACNET : ARGOS_PROTOCOL_COUNT;
        default: return ARGOS_PROTOCOL_COUNT;
    }
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
    if (ARGOS_DISPATCH_HAS(PTP)) plan->l2_routes |= ARGOS_DISPATCH_L2_PTP;

    if (ARGOS_DISPATCH_HAS(NDP) || ARGOS_DISPATCH_HAS(RA) || ARGOS_DISPATCH_HAS(MLD))
        plan->l3_routes |= ARGOS_DISPATCH_L3_ICMPV6;
    if (ARGOS_DISPATCH_HAS(IGMP)) plan->l3_routes |= ARGOS_DISPATCH_L3_IGMP;
    if (ARGOS_DISPATCH_HAS(OSPF)) plan->l3_routes |= ARGOS_DISPATCH_L3_OSPF;
    if (ARGOS_DISPATCH_HAS(VRRP)) plan->l3_routes |= ARGOS_DISPATCH_L3_VRRP;
    if (ARGOS_DISPATCH_HAS(ESP)) plan->l3_routes |= ARGOS_DISPATCH_L3_ESP;
    if (ARGOS_DISPATCH_HAS(AH)) plan->l3_routes |= ARGOS_DISPATCH_L3_AH;

    if (ARGOS_DISPATCH_HAS(SSH) || ARGOS_DISPATCH_HAS(KERBEROS) ||
        ARGOS_DISPATCH_HAS(SUNRPC) || ARGOS_DISPATCH_HAS(BGP) ||
        ARGOS_DISPATCH_HAS(SMB) || ARGOS_DISPATCH_HAS(MODBUS) ||
        ARGOS_DISPATCH_HAS(IPP) || ARGOS_DISPATCH_HAS(MSSQL) ||
        ARGOS_DISPATCH_HAS(ORACLE) || ARGOS_DISPATCH_HAS(MQTT) ||
        ARGOS_DISPATCH_HAS(SCCP) || ARGOS_DISPATCH_HAS(NFS) ||
        ARGOS_DISPATCH_HAS(ISCSI) || ARGOS_DISPATCH_HAS(MYSQL) ||
        ARGOS_DISPATCH_HAS(RDP) || ARGOS_DISPATCH_HAS(SIP) ||
        ARGOS_DISPATCH_HAS(POSTGRESQL) || ARGOS_DISPATCH_HAS(PJL) ||
        ARGOS_DISPATCH_HAS(JETDIRECT) || ARGOS_DISPATCH_HAS(ETHERNET_IP) ||
        ARGOS_DISPATCH_HAS(CIP) || ARGOS_DISPATCH_HAS(SYSLOG) ||
        ARGOS_DISPATCH_HAS(IPFIX) || ARGOS_DISPATCH_HAS(LPD))
        plan->transport_routes |= ARGOS_DISPATCH_TRANSPORT_TCP_OWNER;
    if (ARGOS_DISPATCH_HAS(KERBEROS) || ARGOS_DISPATCH_HAS(SUNRPC) ||
        ARGOS_DISPATCH_HAS(NTP) || ARGOS_DISPATCH_HAS(SNMP) ||
        ARGOS_DISPATCH_HAS(CLDAP) || ARGOS_DISPATCH_HAS(NETLOGON) ||
        ARGOS_DISPATCH_HAS(VMWARE_SLP) || ARGOS_DISPATCH_HAS(IPMI) ||
        ARGOS_DISPATCH_HAS(RMCP) || ARGOS_DISPATCH_HAS(ASF) ||
        ARGOS_DISPATCH_HAS(RADIUS) || ARGOS_DISPATCH_HAS(HSRP) ||
        ARGOS_DISPATCH_HAS(NFS) || ARGOS_DISPATCH_HAS(STUN_TURN) ||
        ARGOS_DISPATCH_HAS(SIP) || ARGOS_DISPATCH_HAS(MNDP) ||
        ARGOS_DISPATCH_HAS(COAP) || ARGOS_DISPATCH_HAS(ETHERNET_IP) ||
        ARGOS_DISPATCH_HAS(CIP) || ARGOS_DISPATCH_HAS(BACNET) ||
        ARGOS_DISPATCH_HAS(RIP) || ARGOS_DISPATCH_HAS(SYSLOG) ||
        ARGOS_DISPATCH_HAS(NETFLOW) || ARGOS_DISPATCH_HAS(IPFIX) ||
        ARGOS_DISPATCH_HAS(SFLOW))
        plan->transport_routes |= ARGOS_DISPATCH_TRANSPORT_UDP_OWNER;

    if (argos_feature_selection_has(&plan->features, ARGOS_FEATURE_TCP_SYN) ||
        ARGOS_DISPATCH_HAS(HTTP) || ARGOS_DISPATCH_HAS(TLS) ||
        ARGOS_DISPATCH_HAS(DOT) || ARGOS_DISPATCH_HAS(NTLM) ||
        (plan->transport_routes & ARGOS_DISPATCH_TRANSPORT_TCP_OWNER) != 0U)
        plan->l4_routes |= ARGOS_DISPATCH_L4_TCP;
    if (ARGOS_DISPATCH_HAS(MDNS) || ARGOS_DISPATCH_HAS(SSDP) ||
        ARGOS_DISPATCH_HAS(UPNP) || ARGOS_DISPATCH_HAS(WSD) ||
        ARGOS_DISPATCH_HAS(DHCP) || ARGOS_DISPATCH_HAS(DHCPV6) ||
        ARGOS_DISPATCH_HAS(NBNS) || ARGOS_DISPATCH_HAS(DNS) ||
        ARGOS_DISPATCH_HAS(QUIC) || ARGOS_DISPATCH_HAS(WIREGUARD) ||
        ARGOS_DISPATCH_HAS(PTP) ||
        (plan->transport_routes & ARGOS_DISPATCH_TRANSPORT_UDP_OWNER) != 0U)
        plan->l4_routes |= ARGOS_DISPATCH_L4_UDP;
    if (plan->l4_routes != 0U ||
        (plan->l3_routes & (ARGOS_DISPATCH_L3_IGMP | ARGOS_DISPATCH_L3_OSPF |
                            ARGOS_DISPATCH_L3_VRRP | ARGOS_DISPATCH_L3_ESP |
                            ARGOS_DISPATCH_L3_AH)) != 0U)
        plan->l3_routes |= ARGOS_DISPATCH_L3_IPV4;
    if (argos_feature_selection_has(&plan->features, ARGOS_FEATURE_IPV6) &&
        (plan->l4_routes != 0U ||
         (plan->l3_routes & ARGOS_DISPATCH_L3_ICMPV6) != 0U))
        plan->l3_routes |= ARGOS_DISPATCH_L3_IPV6;
#undef ARGOS_DISPATCH_HAS
}

#endif
