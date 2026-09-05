#ifndef ARGOS_CONFIG_H
#define ARGOS_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ARGOS_DEFAULT_RATE_LIMIT_SECONDS 35

/* Canonical v6 selection taxonomy. This catalog is control-plane data: CLI/help
 * may scan it during startup, while packet processing receives only the fixed
 * bitmap. Protocol status describes current source truth and never enables a
 * staging parser by itself. */
#define ARGOS_SUPER_GROUP_CATALOG(X) \
    X(NETWORK, "network") \
    X(APPLICATION, "application") \
    X(ENTERPRISE, "enterprise") \
    X(INDUSTRIAL, "industrial") \
    X(IOT, "iot") \
    X(VPN, "vpn")

typedef enum {
#define ARGOS_SUPER_ENUM(id, name) ARGOS_SUPER_GROUP_##id,
    ARGOS_SUPER_GROUP_CATALOG(ARGOS_SUPER_ENUM)
#undef ARGOS_SUPER_ENUM
    ARGOS_SUPER_GROUP_COUNT
} argos_super_group_id_t;

#define ARGOS_GROUP_CATALOG(X) \
    X(ADDRESSING, NETWORK, "addressing") \
    X(DISCOVERY, NETWORK, "discovery") \
    X(L2_DISCOVERY, NETWORK, "l2-discovery") \
    X(MULTICAST, NETWORK, "multicast") \
    X(ROUTING, NETWORK, "routing") \
    X(REDUNDANCY, NETWORK, "redundancy") \
    X(TIME, NETWORK, "time") \
    X(NAME_SERVICES, APPLICATION, "name-services") \
    X(ENCRYPTED, APPLICATION, "encrypted") \
    X(WEB, APPLICATION, "web") \
    X(REMOTE_ACCESS, APPLICATION, "remote-access") \
    X(REALTIME, APPLICATION, "realtime") \
    X(PRINTING, APPLICATION, "printing") \
    X(VOICE, APPLICATION, "voice") \
    X(MEDIA, APPLICATION, "media") \
    X(FILESHARE, ENTERPRISE, "fileshare") \
    X(STORAGE, ENTERPRISE, "storage") \
    X(DATABASE, ENTERPRISE, "database") \
    X(IDENTITY, ENTERPRISE, "identity") \
    X(DIRECTORY, ENTERPRISE, "directory") \
    X(MANAGEMENT, ENTERPRISE, "management") \
    X(BUILDING, INDUSTRIAL, "building") \
    X(AUTOMATION, INDUSTRIAL, "automation") \
    X(UTILITY, INDUSTRIAL, "utility") \
    X(MESSAGING, IOT, "messaging") \
    X(SMART_HOME, IOT, "smart-home") \
    X(MODERN_VPN, VPN, "modern-vpn") \
    X(IPSEC_SUITE, VPN, "ipsec-suite")

typedef enum {
#define ARGOS_GROUP_ENUM(id, super_id, name) ARGOS_GROUP_##id,
    ARGOS_GROUP_CATALOG(ARGOS_GROUP_ENUM)
#undef ARGOS_GROUP_ENUM
    ARGOS_GROUP_COUNT
} argos_group_id_t;

enum {
    ARGOS_PROTOCOL_STATUS_PRODUCTION = 1U,
    ARGOS_PROTOCOL_STATUS_STAGING = 2U,
    ARGOS_PROTOCOL_STATUS_HOLD = 4U
};

#define ARGOS_PROTOCOL_CATALOG(X) \
    X(DHCP, NETWORK, "dhcp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(DHCPV6, NETWORK, "dhcpv6", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ARP, NETWORK, "arp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NDP, NETWORK, "ndp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(RA, NETWORK, "ra", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MDNS, NETWORK, "mdns", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(SSDP, NETWORK, "ssdp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(UPNP, NETWORK, "upnp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LLMNR, NETWORK, "llmnr", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(WSD, NETWORK, "wsd", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NBNS, NETWORK, "nbns", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LLDP, NETWORK, "lldp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(CDP, NETWORK, "cdp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(EDP, NETWORK, "edp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(FDP, NETWORK, "fdp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MNDP, NETWORK, "mndp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LLDP_MED, NETWORK, "lldp-med", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(STP, NETWORK, "stp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LACP, NETWORK, "lacp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(IGMP, NETWORK, "igmp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MLD, NETWORK, "mld", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(BGP, NETWORK, "bgp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(OSPF, NETWORK, "ospf", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ISIS, NETWORK, "isis", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(RIP, NETWORK, "rip", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(VRRP, NETWORK, "vrrp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(HSRP, NETWORK, "hsrp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NTP, NETWORK, "ntp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(PTP, NETWORK, "ptp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(DNS, APPLICATION, "dns", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(DOT, APPLICATION, "dot", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(TLS, APPLICATION, "tls", ARGOS_PROTOCOL_STATUS_PRODUCTION | ARGOS_PROTOCOL_STATUS_STAGING) \
    X(QUIC, APPLICATION, "quic", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(HTTP, APPLICATION, "http", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(HTTP_PROXY, APPLICATION, "http-proxy", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(RDP, APPLICATION, "rdp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(SSH, APPLICATION, "ssh", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(TELNET, APPLICATION, "telnet", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(VNC, APPLICATION, "vnc", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(WINRM, APPLICATION, "winrm", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(STUN_TURN, APPLICATION, "stun-turn", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(IPP, APPLICATION, "ipp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(PJL, APPLICATION, "pjl", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(JETDIRECT, APPLICATION, "jetdirect", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LPD, APPLICATION, "lpd", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(SIP, APPLICATION, "sip", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(SCCP, APPLICATION, "sccp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(RTP, APPLICATION, "rtp", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(RTCP, APPLICATION, "rtcp", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(RTSP, APPLICATION, "rtsp", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(CAST, APPLICATION, "cast", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(AIRPLAY, APPLICATION, "airplay", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(DLNA, APPLICATION, "dlna", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(SMB, ENTERPRISE, "smb", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NTLM, ENTERPRISE, "ntlm", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NFS, ENTERPRISE, "nfs", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(FTP, ENTERPRISE, "ftp", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(SUNRPC, ENTERPRISE, "sunrpc", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ISCSI, ENTERPRISE, "iscsi", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NVMEOF, ENTERPRISE, "nvmeof", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(MYSQL, ENTERPRISE, "mysql", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(POSTGRESQL, ENTERPRISE, "postgresql", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MSSQL, ENTERPRISE, "mssql", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ORACLE, ENTERPRISE, "oracle", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MONGODB, ENTERPRISE, "mongodb", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(REDIS, ENTERPRISE, "redis", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(KERBEROS, ENTERPRISE, "kerberos", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(EAPOL, ENTERPRISE, "eapol", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(RADIUS, ENTERPRISE, "radius", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(TACACS, ENTERPRISE, "tacacs", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(CLDAP, ENTERPRISE, "cldap", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NETLOGON, ENTERPRISE, "netlogon", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LDAP, ENTERPRISE, "ldap", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(LDAPS, ENTERPRISE, "ldaps", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(SNMP, ENTERPRISE, "snmp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(IPMI, ENTERPRISE, "ipmi", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(RMCP, ENTERPRISE, "rmcp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ASF, ENTERPRISE, "asf", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(VMWARE_SLP, ENTERPRISE, "vmware-slp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(SYSLOG, ENTERPRISE, "syslog", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NETFLOW, ENTERPRISE, "netflow", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(IPFIX, ENTERPRISE, "ipfix", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(SFLOW, ENTERPRISE, "sflow", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(BACNET, INDUSTRIAL, "bacnet", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(KNX, INDUSTRIAL, "knx", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(MODBUS, INDUSTRIAL, "modbus", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(PROFINET, INDUSTRIAL, "profinet", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ETHERNET_IP, INDUSTRIAL, "ethernet-ip", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(CIP, INDUSTRIAL, "cip", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(S7, INDUSTRIAL, "s7", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(OPCUA, INDUSTRIAL, "opcua", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(DNP3, INDUSTRIAL, "dnp3", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(MQTT, IOT, "mqtt", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(COAP, IOT, "coap", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MATTER, IOT, "matter", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(THREAD, IOT, "thread", ARGOS_PROTOCOL_STATUS_STAGING | ARGOS_PROTOCOL_STATUS_HOLD) \
    X(WIREGUARD, VPN, "wireguard", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(OPENVPN, VPN, "openvpn", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(IKE, VPN, "ike", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(ESP, VPN, "esp", ARGOS_PROTOCOL_STATUS_STAGING | ARGOS_PROTOCOL_STATUS_HOLD) \
    X(AH, VPN, "ah", ARGOS_PROTOCOL_STATUS_STAGING | ARGOS_PROTOCOL_STATUS_HOLD)

typedef enum {
#define ARGOS_PROTOCOL_ENUM(id, super_id, name, status) ARGOS_PROTOCOL_##id,
    ARGOS_PROTOCOL_CATALOG(ARGOS_PROTOCOL_ENUM)
#undef ARGOS_PROTOCOL_ENUM
    ARGOS_PROTOCOL_COUNT
} argos_protocol_id_t;

#define ARGOS_PROTOCOL_WORDS ((ARGOS_PROTOCOL_COUNT + 63U) / 64U)
typedef struct { uint64_t words[ARGOS_PROTOCOL_WORDS]; } argos_protocol_set_t;

typedef struct {
    argos_protocol_set_t enabled;
    argos_protocol_set_t unrated;
} argos_protocol_selection_t;

/* Startup/control capabilities which are not protocols. Keep these out of the
 * protocol bitmap: SYN fingerprinting is a TCP feature, while IPv6 handling,
 * extended metrics, stateful QUIC and sensor deployment are runtime modes. */
#define ARGOS_FEATURE_CATALOG(X) \
    X(TCP_SYN, 1) \
    X(IPV6, 0) \
    X(EXTENDED_METRICS, 0) \
    X(QUIC_STATEFUL, 0) \
    X(SENSOR_DEPLOYMENT, 0)

typedef enum {
#define ARGOS_FEATURE_ENUM(id, rate_capable) ARGOS_FEATURE_##id,
    ARGOS_FEATURE_CATALOG(ARGOS_FEATURE_ENUM)
#undef ARGOS_FEATURE_ENUM
    ARGOS_FEATURE_COUNT
} argos_feature_id_t;

typedef uint32_t argos_feature_set_t;
_Static_assert(ARGOS_FEATURE_COUNT <= 32, "feature bitmap exceeds fixed storage");

typedef struct {
    argos_feature_set_t enabled;
    argos_feature_set_t unrated;
} argos_feature_selection_t;

typedef struct {
    argos_protocol_selection_t protocols;
    argos_feature_selection_t features;
    argos_feature_selection_t explicit_features;
    unsigned has_explicit_protocol_selection;
} argos_cli_selection_t;

typedef enum {
    ARGOS_CLI_SELECTOR_PROFILE = 0,
    ARGOS_CLI_SELECTOR_SUPER_GROUP,
    ARGOS_CLI_SELECTOR_GROUP,
    ARGOS_CLI_SELECTOR_PROTOCOL,
    ARGOS_CLI_SELECTOR_NO_RATE_LIMIT
} argos_cli_selector_kind_t;

typedef enum {
    ARGOS_LEGACY_CATEGORY_SYN = 0,
    ARGOS_LEGACY_CATEGORY_MULTI,
    ARGOS_LEGACY_CATEGORY_DHCP,
    ARGOS_LEGACY_CATEGORY_NETBIOS,
    ARGOS_LEGACY_CATEGORY_DNS,
    ARGOS_LEGACY_CATEGORY_HTTP,
    ARGOS_LEGACY_CATEGORY_TLS,
    ARGOS_LEGACY_CATEGORY_L2,
    ARGOS_LEGACY_CATEGORY_ENTERPRISE,
    ARGOS_LEGACY_CATEGORY_COUNT
} argos_legacy_category_id_t;

typedef enum {
    ARGOS_RATE_TARGET_ALL = 0,
    ARGOS_RATE_TARGET_SUPER_GROUP,
    ARGOS_RATE_TARGET_GROUP
} argos_rate_target_kind_t;

typedef struct {
    const char *name;
} argos_super_group_descriptor_t;

typedef struct {
    const char *name;
    argos_super_group_id_t super_group;
} argos_group_descriptor_t;

typedef struct {
    const char *name;
    argos_super_group_id_t super_group;
    unsigned status;
} argos_protocol_descriptor_t;

typedef struct {
    argos_group_id_t group;
    argos_protocol_id_t protocol;
} argos_group_membership_t;

static const argos_super_group_descriptor_t
argos_super_group_catalog[ARGOS_SUPER_GROUP_COUNT] = {
#define ARGOS_SUPER_DESC(id, name) [ARGOS_SUPER_GROUP_##id] = {name},
    ARGOS_SUPER_GROUP_CATALOG(ARGOS_SUPER_DESC)
#undef ARGOS_SUPER_DESC
};

static const argos_group_descriptor_t argos_group_catalog[ARGOS_GROUP_COUNT] = {
#define ARGOS_GROUP_DESC(id, super_id, name) \
    [ARGOS_GROUP_##id] = {name, ARGOS_SUPER_GROUP_##super_id},
    ARGOS_GROUP_CATALOG(ARGOS_GROUP_DESC)
#undef ARGOS_GROUP_DESC
};

static const argos_protocol_descriptor_t
argos_protocol_catalog[ARGOS_PROTOCOL_COUNT] = {
#define ARGOS_PROTOCOL_DESC(id, super_id, name, status) \
    [ARGOS_PROTOCOL_##id] = {name, ARGOS_SUPER_GROUP_##super_id, status},
    ARGOS_PROTOCOL_CATALOG(ARGOS_PROTOCOL_DESC)
#undef ARGOS_PROTOCOL_DESC
};

#define ARGOS_GROUP_MEMBERSHIP_CATALOG(X) \
    X(ADDRESSING, DHCP) X(ADDRESSING, DHCPV6) X(ADDRESSING, ARP) X(ADDRESSING, NDP) X(ADDRESSING, RA) \
    X(DISCOVERY, MDNS) X(DISCOVERY, SSDP) X(DISCOVERY, UPNP) X(DISCOVERY, LLMNR) X(DISCOVERY, WSD) X(DISCOVERY, NBNS) \
    X(L2_DISCOVERY, LLDP) X(L2_DISCOVERY, CDP) X(L2_DISCOVERY, EDP) X(L2_DISCOVERY, FDP) X(L2_DISCOVERY, MNDP) X(L2_DISCOVERY, LLDP_MED) X(L2_DISCOVERY, STP) X(L2_DISCOVERY, LACP) \
    X(MULTICAST, IGMP) X(MULTICAST, MLD) \
    X(ROUTING, BGP) X(ROUTING, OSPF) X(ROUTING, ISIS) X(ROUTING, RIP) \
    X(REDUNDANCY, VRRP) X(REDUNDANCY, HSRP) \
    X(TIME, NTP) X(TIME, PTP) \
    X(NAME_SERVICES, DNS) X(NAME_SERVICES, DOT) \
    X(ENCRYPTED, TLS) X(ENCRYPTED, QUIC) \
    X(WEB, HTTP) X(WEB, HTTP_PROXY) \
    X(REMOTE_ACCESS, RDP) X(REMOTE_ACCESS, SSH) X(REMOTE_ACCESS, TELNET) X(REMOTE_ACCESS, VNC) X(REMOTE_ACCESS, WINRM) \
    X(REALTIME, STUN_TURN) \
    X(PRINTING, IPP) X(PRINTING, PJL) X(PRINTING, JETDIRECT) X(PRINTING, LPD) \
    X(VOICE, SIP) X(VOICE, SCCP) X(VOICE, RTP) X(VOICE, RTCP) \
    X(MEDIA, RTSP) X(MEDIA, CAST) X(MEDIA, AIRPLAY) X(MEDIA, DLNA) \
    X(FILESHARE, SMB) X(FILESHARE, NTLM) X(FILESHARE, NFS) X(FILESHARE, FTP) \
    X(STORAGE, SUNRPC) X(STORAGE, NFS) X(STORAGE, ISCSI) X(STORAGE, NVMEOF) \
    X(DATABASE, MYSQL) X(DATABASE, POSTGRESQL) X(DATABASE, MSSQL) X(DATABASE, ORACLE) X(DATABASE, MONGODB) X(DATABASE, REDIS) \
    X(IDENTITY, KERBEROS) X(IDENTITY, NTLM) X(IDENTITY, EAPOL) X(IDENTITY, RADIUS) X(IDENTITY, TACACS) \
    X(DIRECTORY, CLDAP) X(DIRECTORY, NETLOGON) X(DIRECTORY, LDAP) X(DIRECTORY, LDAPS) \
    X(MANAGEMENT, SNMP) X(MANAGEMENT, IPMI) X(MANAGEMENT, RMCP) X(MANAGEMENT, ASF) X(MANAGEMENT, VMWARE_SLP) X(MANAGEMENT, SYSLOG) X(MANAGEMENT, NETFLOW) X(MANAGEMENT, IPFIX) X(MANAGEMENT, SFLOW) \
    X(BUILDING, BACNET) X(BUILDING, KNX) \
    X(AUTOMATION, MODBUS) X(AUTOMATION, PROFINET) X(AUTOMATION, ETHERNET_IP) X(AUTOMATION, CIP) X(AUTOMATION, S7) X(AUTOMATION, OPCUA) \
    X(UTILITY, DNP3) \
    X(MESSAGING, MQTT) X(MESSAGING, COAP) \
    X(SMART_HOME, MATTER) X(SMART_HOME, THREAD) \
    X(MODERN_VPN, WIREGUARD) X(MODERN_VPN, OPENVPN) \
    X(IPSEC_SUITE, IKE) X(IPSEC_SUITE, ESP) X(IPSEC_SUITE, AH)

static const argos_group_membership_t argos_group_memberships[] = {
#define ARGOS_MEMBER_DESC(group_id, protocol_id) \
    {ARGOS_GROUP_##group_id, ARGOS_PROTOCOL_##protocol_id},
    ARGOS_GROUP_MEMBERSHIP_CATALOG(ARGOS_MEMBER_DESC)
#undef ARGOS_MEMBER_DESC
};

#define ARGOS_GROUP_MEMBERSHIP_COUNT \
    (sizeof(argos_group_memberships) / sizeof(argos_group_memberships[0]))

#define ARGOS_PROFILE_CATALOG(X) \
    X(CORE, "core") X(STANDARD, "standard") X(FULL, "full") \
    X(HOME, "home") X(ENTERPRISE, "enterprise") X(SENSOR, "sensor")

typedef enum {
#define ARGOS_PROFILE_ENUM(id, name) ARGOS_PROFILE_##id,
    ARGOS_PROFILE_CATALOG(ARGOS_PROFILE_ENUM)
#undef ARGOS_PROFILE_ENUM
    ARGOS_PROFILE_COUNT
} argos_profile_id_t;

static const char *const argos_profile_names[ARGOS_PROFILE_COUNT] = {
#define ARGOS_PROFILE_NAME(id, name) [ARGOS_PROFILE_##id] = name,
    ARGOS_PROFILE_CATALOG(ARGOS_PROFILE_NAME)
#undef ARGOS_PROFILE_NAME
};

static inline void argos_protocol_set_clear(argos_protocol_set_t *set) {
    if (set) memset(set, 0, sizeof(*set));
}

static inline void argos_protocol_set_add(argos_protocol_set_t *set,
                                          argos_protocol_id_t protocol) {
    if (!set || (unsigned)protocol >= ARGOS_PROTOCOL_COUNT) return;
    set->words[(unsigned)protocol >> 6] |= UINT64_C(1) << ((unsigned)protocol & 63U);
}

static inline int argos_protocol_set_has(const argos_protocol_set_t *set,
                                         argos_protocol_id_t protocol) {
    if (!set || (unsigned)protocol >= ARGOS_PROTOCOL_COUNT) return 0;
    return (set->words[(unsigned)protocol >> 6] &
            (UINT64_C(1) << ((unsigned)protocol & 63U))) != 0U;
}

static inline int argos_protocol_set_any(const argos_protocol_set_t *set) {
    if (!set) return 0;
    for (size_t i = 0; i < ARGOS_PROTOCOL_WORDS; ++i)
        if (set->words[i] != 0U) return 1;
    return 0;
}

static inline void argos_protocol_set_union(argos_protocol_set_t *destination,
                                            const argos_protocol_set_t *source) {
    if (!destination || !source) return;
    for (size_t i = 0; i < ARGOS_PROTOCOL_WORDS; ++i)
        destination->words[i] |= source->words[i];
}

static inline void argos_protocol_set_intersect(argos_protocol_set_t *destination,
                                                const argos_protocol_set_t *source) {
    if (!destination || !source) return;
    for (size_t i = 0; i < ARGOS_PROTOCOL_WORDS; ++i)
        destination->words[i] &= source->words[i];
}

static inline void argos_protocol_set_subtract(argos_protocol_set_t *destination,
                                               const argos_protocol_set_t *source) {
    if (!destination || !source) return;
    for (size_t i = 0; i < ARGOS_PROTOCOL_WORDS; ++i)
        destination->words[i] &= ~source->words[i];
}

static inline void argos_group_protocol_mask(argos_group_id_t group,
                                             argos_protocol_set_t *out) {
    argos_protocol_set_clear(out);
    if (!out || (unsigned)group >= ARGOS_GROUP_COUNT) return;
    for (size_t i = 0; i < ARGOS_GROUP_MEMBERSHIP_COUNT; ++i)
        if (argos_group_memberships[i].group == group)
            argos_protocol_set_add(out, argos_group_memberships[i].protocol);
}

static inline void argos_super_group_protocol_mask(argos_super_group_id_t super_group,
                                                   argos_protocol_set_t *out) {
    argos_protocol_set_clear(out);
    if (!out || (unsigned)super_group >= ARGOS_SUPER_GROUP_COUNT) return;
    for (size_t i = 0; i < ARGOS_GROUP_MEMBERSHIP_COUNT; ++i) {
        argos_group_id_t group = argos_group_memberships[i].group;
        if (argos_group_catalog[group].super_group == super_group)
            argos_protocol_set_add(out, argos_group_memberships[i].protocol);
    }
}

static inline int argos_protocol_is_production(argos_protocol_id_t protocol) {
    return (unsigned)protocol < ARGOS_PROTOCOL_COUNT &&
           (argos_protocol_catalog[protocol].status & ARGOS_PROTOCOL_STATUS_PRODUCTION) != 0U;
}

static inline void argos_production_protocol_mask(argos_protocol_set_t *out) {
    argos_protocol_set_clear(out);
    if (!out) return;
    for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p)
        if (argos_protocol_is_production((argos_protocol_id_t)p))
            argos_protocol_set_add(out, (argos_protocol_id_t)p);
}

static inline void argos_protocol_selection_clear(argos_protocol_selection_t *selection) {
    if (selection) memset(selection, 0, sizeof(*selection));
}

/* Startup-only selection compiler. Only current production bits survive. The
 * most recent overlapping lowercase/uppercase selection determines rate mode,
 * matching existing short-option order; it never changes safety budgets. */
static inline void argos_protocol_selection_apply_mask(
    argos_protocol_selection_t *selection, const argos_protocol_set_t *requested,
    int unrated) {
    if (!selection || !requested) return;
    argos_protocol_set_t production;
    argos_production_protocol_mask(&production);
    argos_protocol_set_intersect(&production, requested);
    argos_protocol_set_union(&selection->enabled, &production);
    if (unrated) argos_protocol_set_union(&selection->unrated, &production);
    else argos_protocol_set_subtract(&selection->unrated, &production);
}

static inline int argos_protocol_selection_apply_protocol(
    argos_protocol_selection_t *selection, argos_protocol_id_t protocol,
    int unrated) {
    if (!selection || !argos_protocol_is_production(protocol)) return 0;
    argos_protocol_set_t requested = {0};
    argos_protocol_set_add(&requested, protocol);
    argos_protocol_selection_apply_mask(selection, &requested, unrated);
    return 1;
}

/* `--no-rate-limit` changes emission policy only for already-enabled bits; it
 * cannot activate a parser or bypass packet/byte/state safety ceilings. */
static inline void argos_protocol_selection_unrate_enabled(
    argos_protocol_selection_t *selection, const argos_protocol_set_t *target) {
    if (!selection || !target) return;
    argos_protocol_set_t active = *target;
    argos_protocol_set_intersect(&active, &selection->enabled);
    argos_protocol_set_union(&selection->unrated, &active);
}

static inline argos_feature_set_t argos_feature_bit(argos_feature_id_t feature) {
    if ((unsigned)feature >= ARGOS_FEATURE_COUNT) return 0U;
    return (argos_feature_set_t)UINT32_C(1) << (unsigned)feature;
}

static inline int argos_feature_rate_capable(argos_feature_id_t feature) {
    static const uint8_t rate_capable[ARGOS_FEATURE_COUNT] = {
#define ARGOS_FEATURE_RATE(id, can_rate) [ARGOS_FEATURE_##id] = (can_rate),
        ARGOS_FEATURE_CATALOG(ARGOS_FEATURE_RATE)
#undef ARGOS_FEATURE_RATE
    };
    return (unsigned)feature < ARGOS_FEATURE_COUNT && rate_capable[feature] != 0U;
}

static inline void argos_feature_selection_clear(argos_feature_selection_t *selection) {
    if (selection) memset(selection, 0, sizeof(*selection));
}

static inline void argos_feature_selection_apply(argos_feature_selection_t *selection,
                                                 argos_feature_id_t feature,
                                                 int unrated) {
    if (!selection || (unsigned)feature >= ARGOS_FEATURE_COUNT) return;
    argos_feature_set_t bit = argos_feature_bit(feature);
    selection->enabled |= bit;
    if (unrated && argos_feature_rate_capable(feature)) selection->unrated |= bit;
    else selection->unrated &= ~bit;
}

static inline int argos_feature_selection_has(const argos_feature_selection_t *selection,
                                              argos_feature_id_t feature) {
    return selection && (selection->enabled & argos_feature_bit(feature)) != 0U;
}

/* Exact compatibility bundle reached by the current --enterprise parser gate.
 * It intentionally spans several canonical super-groups; it is not the new
 * enterprise super-group and therefore must not be used to define that mask. */
static inline void argos_legacy_enterprise_protocol_mask(argos_protocol_set_t *out) {
    static const argos_protocol_id_t protocols[] = {
        ARGOS_PROTOCOL_CDP, ARGOS_PROTOCOL_EDP, ARGOS_PROTOCOL_FDP,
        ARGOS_PROTOCOL_MNDP, ARGOS_PROTOCOL_LLDP_MED, ARGOS_PROTOCOL_STP,
        ARGOS_PROTOCOL_LACP, ARGOS_PROTOCOL_IGMP, ARGOS_PROTOCOL_MLD,
        ARGOS_PROTOCOL_BGP, ARGOS_PROTOCOL_OSPF, ARGOS_PROTOCOL_ISIS,
        ARGOS_PROTOCOL_VRRP, ARGOS_PROTOCOL_HSRP, ARGOS_PROTOCOL_NTP,
        ARGOS_PROTOCOL_STUN_TURN, ARGOS_PROTOCOL_RDP, ARGOS_PROTOCOL_SSH,
        ARGOS_PROTOCOL_IPP, ARGOS_PROTOCOL_PJL, ARGOS_PROTOCOL_JETDIRECT,
        ARGOS_PROTOCOL_SIP, ARGOS_PROTOCOL_SCCP,
        ARGOS_PROTOCOL_SMB, ARGOS_PROTOCOL_NTLM, ARGOS_PROTOCOL_NFS,
        ARGOS_PROTOCOL_SUNRPC, ARGOS_PROTOCOL_ISCSI, ARGOS_PROTOCOL_MYSQL,
        ARGOS_PROTOCOL_POSTGRESQL, ARGOS_PROTOCOL_MSSQL, ARGOS_PROTOCOL_ORACLE,
        ARGOS_PROTOCOL_KERBEROS, ARGOS_PROTOCOL_EAPOL, ARGOS_PROTOCOL_RADIUS,
        ARGOS_PROTOCOL_CLDAP, ARGOS_PROTOCOL_NETLOGON, ARGOS_PROTOCOL_SNMP,
        ARGOS_PROTOCOL_IPMI, ARGOS_PROTOCOL_RMCP, ARGOS_PROTOCOL_ASF,
        ARGOS_PROTOCOL_VMWARE_SLP, ARGOS_PROTOCOL_BACNET, ARGOS_PROTOCOL_MODBUS,
        ARGOS_PROTOCOL_PROFINET, ARGOS_PROTOCOL_ETHERNET_IP, ARGOS_PROTOCOL_CIP,
        ARGOS_PROTOCOL_MQTT, ARGOS_PROTOCOL_COAP, ARGOS_PROTOCOL_WIREGUARD
    };
    argos_protocol_set_clear(out);
    if (!out) return;
    for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); ++i)
        argos_protocol_set_add(out, protocols[i]);
}

/* Translate one existing telemetry category to canonical protocol/capability
 * ownership. This is startup-only characterization; main does not consume it
 * until the C4 equivalence gate. */
static inline void argos_legacy_category_mask(argos_legacy_category_id_t category,
                                              argos_protocol_set_t *protocols,
                                              argos_feature_set_t *features) {
    argos_protocol_set_clear(protocols);
    if (features) *features = 0U;
    if (!protocols || !features || (unsigned)category >= ARGOS_LEGACY_CATEGORY_COUNT) return;
#define ARGOS_LEGACY_ADD(protocol) argos_protocol_set_add(protocols, ARGOS_PROTOCOL_##protocol)
    switch (category) {
        case ARGOS_LEGACY_CATEGORY_SYN:
            *features = argos_feature_bit(ARGOS_FEATURE_TCP_SYN);
            break;
        case ARGOS_LEGACY_CATEGORY_MULTI:
            ARGOS_LEGACY_ADD(MDNS); ARGOS_LEGACY_ADD(SSDP);
            ARGOS_LEGACY_ADD(UPNP); ARGOS_LEGACY_ADD(WSD);
            break;
        case ARGOS_LEGACY_CATEGORY_DHCP:
            ARGOS_LEGACY_ADD(DHCP); ARGOS_LEGACY_ADD(DHCPV6);
            break;
        case ARGOS_LEGACY_CATEGORY_NETBIOS: ARGOS_LEGACY_ADD(NBNS); break;
        case ARGOS_LEGACY_CATEGORY_DNS: ARGOS_LEGACY_ADD(DNS); break;
        case ARGOS_LEGACY_CATEGORY_HTTP: ARGOS_LEGACY_ADD(HTTP); break;
        case ARGOS_LEGACY_CATEGORY_TLS:
            ARGOS_LEGACY_ADD(TLS); ARGOS_LEGACY_ADD(DOT); ARGOS_LEGACY_ADD(QUIC);
            break;
        case ARGOS_LEGACY_CATEGORY_L2:
            ARGOS_LEGACY_ADD(LLDP); ARGOS_LEGACY_ADD(ARP);
            ARGOS_LEGACY_ADD(NDP); ARGOS_LEGACY_ADD(RA);
            break;
        case ARGOS_LEGACY_CATEGORY_ENTERPRISE:
            argos_legacy_enterprise_protocol_mask(protocols);
            break;
        default: break;
    }
#undef ARGOS_LEGACY_ADD
}

static inline void argos_legacy_selection_apply(argos_protocol_selection_t *protocols,
                                                argos_feature_selection_t *features,
                                                argos_legacy_category_id_t category,
                                                int unrated) {
    argos_protocol_set_t mask;
    argos_feature_set_t feature_mask;
    if (!protocols || !features) return;
    argos_legacy_category_mask(category, &mask, &feature_mask);
    argos_protocol_selection_apply_mask(protocols, &mask, unrated);
    for (unsigned feature = 0; feature < ARGOS_FEATURE_COUNT; ++feature)
        if ((feature_mask & argos_feature_bit((argos_feature_id_t)feature)) != 0U)
            argos_feature_selection_apply(features, (argos_feature_id_t)feature, unrated);
}

/* -a/-A and positional-interface shorthand cover only the eight historical
 * short categories, never the separate --enterprise compatibility bundle. */
static inline void argos_legacy_selection_apply_all(argos_protocol_selection_t *protocols,
                                                    argos_feature_selection_t *features,
                                                    int unrated) {
    for (unsigned category = ARGOS_LEGACY_CATEGORY_SYN;
         category <= ARGOS_LEGACY_CATEGORY_L2; ++category)
        argos_legacy_selection_apply(protocols, features,
                                     (argos_legacy_category_id_t)category, unrated);
    argos_feature_selection_apply(features, ARGOS_FEATURE_IPV6, 0);
}

/* Existing no-option telemetry default: SYN + multicast discovery + DHCP +
 * NBNS, all rate-limited, with IPv6 handling enabled. */
static inline void argos_legacy_selection_apply_default(
    argos_protocol_selection_t *protocols, argos_feature_selection_t *features) {
    static const argos_legacy_category_id_t categories[] = {
        ARGOS_LEGACY_CATEGORY_SYN, ARGOS_LEGACY_CATEGORY_MULTI,
        ARGOS_LEGACY_CATEGORY_DHCP, ARGOS_LEGACY_CATEGORY_NETBIOS
    };
    for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); ++i)
        argos_legacy_selection_apply(protocols, features, categories[i], 0);
    argos_feature_selection_apply(features, ARGOS_FEATURE_IPV6, 0);
}

static inline void argos_profile_add_group(argos_protocol_selection_t *protocols,
                                           argos_group_id_t group) {
    argos_protocol_set_t mask;
    argos_group_protocol_mask(group, &mask);
    argos_protocol_selection_apply_mask(protocols, &mask, 0);
}

/* Frozen profile membership is production-only and startup-only. Profiles
 * select protocol/capability demand, not capture deployment or privacy modes:
 * SENSOR_DEPLOYMENT, QUIC_STATEFUL and identity raw/hash remain explicit CLI
 * choices. The sensor profile opts into bounded extended metrics, not -W. */
static inline int argos_profile_selection(argos_profile_id_t profile,
                                          argos_protocol_selection_t *protocols,
                                          argos_feature_selection_t *features) {
    if (!protocols || !features || (unsigned)profile >= ARGOS_PROFILE_COUNT) return 0;
    argos_protocol_selection_clear(protocols);
    argos_feature_selection_clear(features);
    switch (profile) {
        case ARGOS_PROFILE_CORE:
            argos_legacy_selection_apply_default(protocols, features);
            break;
        case ARGOS_PROFILE_STANDARD:
            argos_legacy_selection_apply_all(protocols, features, 0);
            break;
        case ARGOS_PROFILE_FULL: {
            argos_protocol_set_t production;
            argos_production_protocol_mask(&production);
            argos_protocol_selection_apply_mask(protocols, &production, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_TCP_SYN, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_IPV6, 0);
            break;
        }
        case ARGOS_PROFILE_HOME: {
            static const argos_group_id_t groups[] = {
                ARGOS_GROUP_ADDRESSING, ARGOS_GROUP_DISCOVERY,
                ARGOS_GROUP_L2_DISCOVERY, ARGOS_GROUP_MULTICAST,
                ARGOS_GROUP_TIME, ARGOS_GROUP_NAME_SERVICES,
                ARGOS_GROUP_ENCRYPTED, ARGOS_GROUP_WEB,
                ARGOS_GROUP_REALTIME, ARGOS_GROUP_PRINTING,
                ARGOS_GROUP_VOICE, ARGOS_GROUP_MESSAGING,
                ARGOS_GROUP_SMART_HOME, ARGOS_GROUP_MODERN_VPN
            };
            for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i)
                argos_profile_add_group(protocols, groups[i]);
            argos_feature_selection_apply(features, ARGOS_FEATURE_TCP_SYN, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_IPV6, 0);
            break;
        }
        case ARGOS_PROFILE_ENTERPRISE:
            argos_legacy_selection_apply(protocols, features,
                                         ARGOS_LEGACY_CATEGORY_ENTERPRISE, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_IPV6, 0);
            break;
        case ARGOS_PROFILE_SENSOR: {
            argos_protocol_set_t production;
            argos_production_protocol_mask(&production);
            argos_protocol_selection_apply_mask(protocols, &production, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_TCP_SYN, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_IPV6, 0);
            argos_feature_selection_apply(features, ARGOS_FEATURE_EXTENDED_METRICS, 0);
            break;
        }
        default: return 0;
    }
    return 1;
}

static inline int argos_protocol_name_lookup(const char *name,
                                             argos_protocol_id_t *protocol,
                                             int *unrated) {
    if (!name || !*name || !protocol || !unrated) return 0;
    for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p) {
        const char *canonical = argos_protocol_catalog[p].name;
        size_t i = 0;
        int saw_lower = 0, saw_upper = 0;
        for (;; ++i) {
            unsigned char input = (unsigned char)name[i];
            unsigned char expected = (unsigned char)canonical[i];
            if (input >= 'A' && input <= 'Z') { saw_upper = 1; input = (unsigned char)(input + ('a' - 'A')); }
            else if (input >= 'a' && input <= 'z') saw_lower = 1;
            if (input != expected) break;
            if (input == '\0') {
                if (saw_lower && saw_upper) break;
                *protocol = (argos_protocol_id_t)p;
                *unrated = saw_upper != 0;
                return 1;
            }
        }
    }
    return 0;
}

static inline int argos_group_name_lookup(const char *name, argos_group_id_t *group) {
    if (!name || !group) return 0;
    for (unsigned i = 0; i < ARGOS_GROUP_COUNT; ++i)
        if (strcmp(name, argos_group_catalog[i].name) == 0) {
            *group = (argos_group_id_t)i; return 1;
        }
    return 0;
}

static inline int argos_super_group_name_lookup(const char *name,
                                                argos_super_group_id_t *super_group) {
    if (!name || !super_group) return 0;
    for (unsigned i = 0; i < ARGOS_SUPER_GROUP_COUNT; ++i)
        if (strcmp(name, argos_super_group_catalog[i].name) == 0) {
            *super_group = (argos_super_group_id_t)i; return 1;
        }
    return 0;
}

/* Compile a --no-rate-limit target once during startup. Targets are lowercase
 * exact and limited to all, a super-group or a group; individual protocols use
 * their existing uppercase selector. Only production bits are returned. */
static inline int argos_rate_target_mask(const char *name,
                                         argos_protocol_set_t *out,
                                         argos_rate_target_kind_t *kind) {
    if (!name || !*name || !out) return 0;
    if (strcmp(name, "all") == 0) {
        argos_production_protocol_mask(out);
        if (kind) *kind = ARGOS_RATE_TARGET_ALL;
        return 1;
    }
    argos_super_group_id_t super_group;
    if (argos_super_group_name_lookup(name, &super_group)) {
        argos_protocol_set_t production;
        argos_super_group_protocol_mask(super_group, out);
        argos_production_protocol_mask(&production);
        argos_protocol_set_intersect(out, &production);
        if (kind) *kind = ARGOS_RATE_TARGET_SUPER_GROUP;
        return 1;
    }
    argos_group_id_t group;
    if (argos_group_name_lookup(name, &group)) {
        argos_protocol_set_t production;
        argos_group_protocol_mask(group, out);
        argos_production_protocol_mask(&production);
        argos_protocol_set_intersect(out, &production);
        if (kind) *kind = ARGOS_RATE_TARGET_GROUP;
        return 1;
    }
    argos_protocol_set_clear(out);
    return 0;
}

static inline int argos_protocol_selection_apply_no_rate_limit(
    argos_protocol_selection_t *selection, const char *target_name) {
    argos_protocol_set_t target;
    if (!selection || !argos_rate_target_mask(target_name, &target, NULL)) return 0;
    argos_protocol_selection_unrate_enabled(selection, &target);
    return 1;
}

static inline int argos_profile_name_lookup(const char *name, argos_profile_id_t *profile) {
    if (!name || !profile) return 0;
    for (unsigned i = 0; i < ARGOS_PROFILE_COUNT; ++i)
        if (strcmp(name, argos_profile_names[i]) == 0) {
            *profile = (argos_profile_id_t)i; return 1;
        }
    return 0;
}

/* Compile canonical selectors once, in argv order, before capture/state setup.
 * A profile replaces the current protocol/profile-feature base while preserving
 * separately explicit feature options; later group/super-group/protocol selectors
 * add to it. Protocol case retains the established rate-mode rule.
 * A no-rate target changes only bits enabled at that point. Feature-only options
 * do not suppress the historical default evidence set. Packet processing must
 * consume only the resulting fixed masks, never selector strings. */
static inline void argos_cli_selection_init(argos_cli_selection_t *selection) {
    if (selection) memset(selection, 0, sizeof(*selection));
}

static inline void argos_cli_selection_apply_feature(
    argos_cli_selection_t *selection, argos_feature_id_t feature, int unrated) {
    if (!selection || (unsigned)feature >= ARGOS_FEATURE_COUNT) return;
    argos_feature_selection_apply(&selection->explicit_features, feature, unrated);
    argos_feature_selection_apply(&selection->features, feature, unrated);
}

static inline int argos_cli_selection_apply_named(
    argos_cli_selection_t *selection, argos_cli_selector_kind_t kind,
    const char *name) {
    if (!selection || !name || !*name) return 0;
    argos_protocol_set_t mask;
    switch (kind) {
        case ARGOS_CLI_SELECTOR_PROFILE: {
            argos_profile_id_t profile;
            argos_protocol_selection_t protocols;
            argos_feature_selection_t features;
            if (!argos_profile_name_lookup(name, &profile) ||
                !argos_profile_selection(profile, &protocols, &features)) return 0;
            selection->protocols = protocols;
            selection->features = features;
            selection->features.enabled |= selection->explicit_features.enabled;
            selection->features.unrated |= selection->explicit_features.unrated;
            selection->has_explicit_protocol_selection = 1U;
            return 1;
        }
        case ARGOS_CLI_SELECTOR_SUPER_GROUP: {
            argos_super_group_id_t super_group;
            if (!argos_super_group_name_lookup(name, &super_group)) return 0;
            argos_super_group_protocol_mask(super_group, &mask);
            argos_protocol_selection_apply_mask(&selection->protocols, &mask, 0);
            break;
        }
        case ARGOS_CLI_SELECTOR_GROUP: {
            argos_group_id_t group;
            if (!argos_group_name_lookup(name, &group)) return 0;
            argos_group_protocol_mask(group, &mask);
            argos_protocol_selection_apply_mask(&selection->protocols, &mask, 0);
            break;
        }
        case ARGOS_CLI_SELECTOR_PROTOCOL: {
            argos_protocol_id_t protocol;
            int unrated;
            if (!argos_protocol_name_lookup(name, &protocol, &unrated) ||
                !argos_protocol_selection_apply_protocol(&selection->protocols,
                                                         protocol, unrated)) return 0;
            break;
        }
        case ARGOS_CLI_SELECTOR_NO_RATE_LIMIT:
            return argos_protocol_selection_apply_no_rate_limit(&selection->protocols,
                                                                 name);
        default: return 0;
    }
    selection->has_explicit_protocol_selection = 1U;
    return 1;
}

static inline void argos_cli_selection_apply_legacy(
    argos_cli_selection_t *selection, argos_legacy_category_id_t category,
    int unrated) {
    if (!selection || (unsigned)category >= ARGOS_LEGACY_CATEGORY_COUNT) return;
    argos_legacy_selection_apply(&selection->protocols, &selection->features,
                                 category, unrated);
    selection->has_explicit_protocol_selection = 1U;
}

static inline void argos_cli_selection_apply_legacy_all(
    argos_cli_selection_t *selection, int unrated) {
    if (!selection) return;
    argos_legacy_selection_apply_all(&selection->protocols, &selection->features,
                                     unrated);
    selection->has_explicit_protocol_selection = 1U;
}

/* Startup-only legacy compatibility query. It lets tests and compatibility
 * owners compare canonical masks without packet-time catalog scans. A category is
 * rate-limited when at least one of its enabled members remains rated. This is
 * exact for legacy selectors, whose category members always share rate mode;
 * qualified runtime selectors retain exact per-protocol rate bits. */
static inline int argos_cli_legacy_category_enabled(
    const argos_cli_selection_t *selection, argos_legacy_category_id_t category) {
    if (!selection || (unsigned)category >= ARGOS_LEGACY_CATEGORY_COUNT) return 0;
    if (category == ARGOS_LEGACY_CATEGORY_SYN)
        return argos_feature_selection_has(&selection->features, ARGOS_FEATURE_TCP_SYN);
    argos_protocol_set_t mask;
    argos_feature_set_t features;
    argos_legacy_category_mask(category, &mask, &features);
    (void)features;
    argos_protocol_set_intersect(&mask, &selection->protocols.enabled);
    return argos_protocol_set_any(&mask);
}

static inline int argos_cli_legacy_category_rate_limited(
    const argos_cli_selection_t *selection, argos_legacy_category_id_t category) {
    if (!argos_cli_legacy_category_enabled(selection, category)) return 0;
    if (category == ARGOS_LEGACY_CATEGORY_SYN)
        return (selection->features.unrated &
                argos_feature_bit(ARGOS_FEATURE_TCP_SYN)) == 0U;
    argos_protocol_set_t mask;
    argos_feature_set_t features;
    argos_legacy_category_mask(category, &mask, &features);
    (void)features;
    argos_protocol_set_intersect(&mask, &selection->protocols.enabled);
    argos_protocol_set_subtract(&mask, &selection->protocols.unrated);
    return argos_protocol_set_any(&mask);
}

static inline void argos_cli_selection_finalize(argos_cli_selection_t *selection) {
    if (!selection || selection->has_explicit_protocol_selection) return;
    argos_legacy_selection_apply_default(&selection->protocols, &selection->features);
}

/* Runtime modes are explicit state, not combinations of loosely-related
 * booleans. RAW is always an explicit opt-in; HASH remains the safe default. */
typedef enum {
    ARGOS_IDENTITY_OFF = 0,
    ARGOS_IDENTITY_HASH = 1,
    ARGOS_IDENTITY_RAW = 2
} argos_identity_mode_t;

static inline int argos_identity_mode_parse(const char *arg,
                                            argos_identity_mode_t *out) {
    if (!out) return 0;
    if (!arg || !*arg || strcmp(arg, "hash") == 0) {
        *out = ARGOS_IDENTITY_HASH;
        return 1;
    }
    if (strcmp(arg, "raw") == 0) {
        *out = ARGOS_IDENTITY_RAW;
        return 1;
    }
    return 0;
}

static inline int argos_identity_enabled(argos_identity_mode_t mode) {
    return mode != ARGOS_IDENTITY_OFF;
}

static inline int argos_identity_raw(argos_identity_mode_t mode) {
    return mode == ARGOS_IDENTITY_RAW;
}

typedef struct {
    int enterprise_enabled;
    int enterprise_rate_limited;
    argos_identity_mode_t identity_mode;
    uint16_t wireguard_port;
    int wireguard_port_explicit;
} argos_runtime_config_t;

static inline void argos_runtime_config_init(argos_runtime_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enterprise_rate_limited = 1;
    cfg->identity_mode = ARGOS_IDENTITY_OFF;
    cfg->wireguard_port = 51820U;
}

static inline void argos_runtime_enable_enterprise(argos_runtime_config_t *cfg,
                                                   int verbose) {
    if (!cfg) return;
    cfg->enterprise_enabled = 1;
    cfg->enterprise_rate_limited = verbose ? 0 : 1;
}

/* Return a stable message owned by this module; NULL means valid. */
static inline const char *argos_runtime_config_validate(const argos_runtime_config_t *cfg) {
    if (!cfg) return "invalid runtime configuration";
    if (cfg->wireguard_port_explicit && !cfg->enterprise_enabled)
        return "--wireguard-port requires --enterprise or --enterprise-verbose.";
    if (argos_identity_enabled(cfg->identity_mode) && !cfg->enterprise_enabled)
        return "--identity requires --enterprise or --enterprise-verbose.";
    return NULL;
}

#endif
