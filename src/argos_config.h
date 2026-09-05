#ifndef ARGOS_CONFIG_H
#define ARGOS_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

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
    X(LLMNR, NETWORK, "llmnr", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(WSD, NETWORK, "wsd", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NBNS, NETWORK, "nbns", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LLDP, NETWORK, "lldp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(CDP, NETWORK, "cdp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(EDP, NETWORK, "edp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(FDP, NETWORK, "fdp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MNDP, NETWORK, "mndp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(LLDP_MED, NETWORK, "lldp-med", ARGOS_PROTOCOL_STATUS_PRODUCTION | ARGOS_PROTOCOL_STATUS_STAGING) \
    X(STP, NETWORK, "stp", ARGOS_PROTOCOL_STATUS_PRODUCTION | ARGOS_PROTOCOL_STATUS_STAGING) \
    X(LACP, NETWORK, "lacp", ARGOS_PROTOCOL_STATUS_PRODUCTION | ARGOS_PROTOCOL_STATUS_STAGING) \
    X(IGMP, NETWORK, "igmp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(MLD, NETWORK, "mld", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(BGP, NETWORK, "bgp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(OSPF, NETWORK, "ospf", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(ISIS, NETWORK, "isis", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(RIP, NETWORK, "rip", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(VRRP, NETWORK, "vrrp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(HSRP, NETWORK, "hsrp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(NTP, NETWORK, "ntp", ARGOS_PROTOCOL_STATUS_PRODUCTION) \
    X(PTP, NETWORK, "ptp", ARGOS_PROTOCOL_STATUS_STAGING) \
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
    X(SYSLOG, ENTERPRISE, "syslog", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(NETFLOW, ENTERPRISE, "netflow", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(IPFIX, ENTERPRISE, "ipfix", ARGOS_PROTOCOL_STATUS_STAGING) \
    X(SFLOW, ENTERPRISE, "sflow", ARGOS_PROTOCOL_STATUS_STAGING) \
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

static inline int argos_profile_name_lookup(const char *name, argos_profile_id_t *profile) {
    if (!name || !profile) return 0;
    for (unsigned i = 0; i < ARGOS_PROFILE_COUNT; ++i)
        if (strcmp(name, argos_profile_names[i]) == 0) {
            *profile = (argos_profile_id_t)i; return 1;
        }
    return 0;
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
