#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_dispatch.h"

typedef struct {
    unsigned parser_calls;
    unsigned state_lookups;
} call_counts_t;

static void attempt_engine(const argos_dispatch_plan_t *plan,
                           argos_protocol_id_t protocol,
                           call_counts_t *counts)
{
    if (!argos_dispatch_protocol_enabled(plan, protocol)) return;
    counts->state_lookups++;
    counts->parser_calls++;
}

int main(void)
{
    argos_cli_selection_t cli;
    argos_dispatch_plan_t plan;
    call_counts_t counts = {0};

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_PROTOCOL, "dns"));
    argos_dispatch_plan_compile(&plan, &cli);

    assert(argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_DNS));
    assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_HTTP));
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_UDP));
    assert(!argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));
    assert(argos_dispatch_l3_enabled(&plan, ARGOS_DISPATCH_L3_IPV4));
    assert(argos_dispatch_protocol_rate_limited(&plan, ARGOS_PROTOCOL_DNS));
    assert(!argos_dispatch_l2_frame_enabled(&plan, 0x88ccU));

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_PROTOCOL, "http"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));
    assert(!argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_UDP));

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_PROTOCOL, "quic"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(!argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_UDP));

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_PROTOCOL, "nfs"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_UDP));

    for (unsigned protocol = 0; protocol < ARGOS_PROTOCOL_COUNT; ++protocol)
        attempt_engine(&plan, (argos_protocol_id_t)protocol, &counts);
    assert(counts.parser_calls == 1U);
    assert(counts.state_lookups == 1U);

    /* Every selectable production bit is an independent hard gate. A disabled
     * neighbor can never inherit parser or state work from the selected bit. */
    for (unsigned selected = 0; selected < ARGOS_PROTOCOL_COUNT; ++selected) {
        argos_protocol_id_t selected_id = (argos_protocol_id_t)selected;
        argos_cli_selection_init(&cli);
        if (!argos_protocol_is_production(selected_id)) {
            assert(!argos_protocol_selection_apply_protocol(
                &cli.protocols, selected_id, 0));
            continue;
        }
        assert(argos_protocol_selection_apply_protocol(
            &cli.protocols, selected_id, 0));
        argos_dispatch_plan_compile(&plan, &cli);
        memset(&counts, 0, sizeof(counts));
        for (unsigned candidate = 0; candidate < ARGOS_PROTOCOL_COUNT; ++candidate)
            attempt_engine(&plan, (argos_protocol_id_t)candidate, &counts);
        assert(counts.parser_calls == 1U);
        assert(counts.state_lookups == 1U);
        assert(argos_dispatch_protocol_enabled(&plan, selected_id));
    }

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_PROTOCOL, "lldp"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_l2_enabled(&plan, ARGOS_DISPATCH_L2_LLDP));
    assert(argos_dispatch_l2_frame_enabled(&plan, 0x88ccU));
    assert(!argos_dispatch_l2_frame_enabled(&plan, 0x0806U));
    assert(!argos_dispatch_l3_enabled(&plan, ARGOS_DISPATCH_L3_IPV4));
    assert(!argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));
    assert(!argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_UDP));

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_GROUP, "routing"));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_BGP));
    assert(argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_OSPF));
    assert(argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_ISIS));
    assert(argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_RIP));
    assert(argos_dispatch_l2_enabled(&plan, ARGOS_DISPATCH_L2_LLC));
    assert(argos_dispatch_l3_enabled(&plan, ARGOS_DISPATCH_L3_OSPF));
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_UDP));
    assert(argos_dispatch_l2_frame_enabled(&plan, 0x00feU));
    assert(!argos_dispatch_l2_frame_enabled(&plan, 0x888eU));

    static const struct {
        uint16_t wire_protocol;
        argos_protocol_id_t engine;
    } l2_engines[] = {
        {0x0806U, ARGOS_PROTOCOL_ARP}, {0x8809U, ARGOS_PROTOCOL_LACP},
        {0x888eU, ARGOS_PROTOCOL_EAPOL}, {0x8892U, ARGOS_PROTOCOL_PROFINET},
        {0x2000U, ARGOS_PROTOCOL_CDP}, {0x00feU, ARGOS_PROTOCOL_ISIS},
        {0x00bbU, ARGOS_PROTOCOL_EDP}, {0xf200U, ARGOS_PROTOCOL_FDP},
        {100U, ARGOS_PROTOCOL_STP},
    };
    for (size_t i = 0; i < sizeof(l2_engines) / sizeof(l2_engines[0]); ++i)
        assert(argos_dispatch_l2_protocol(l2_engines[i].wire_protocol) ==
               l2_engines[i].engine);
    assert(argos_dispatch_l2_protocol(0x0800U) == ARGOS_PROTOCOL_COUNT);

    /* PTP is production-selectable; HOLD ESP/AH adapters remain characterized
     * only through manually constructed masks. */
    argos_cli_selection_init(&cli);
    assert(argos_protocol_selection_apply_protocol(&cli.protocols,
                                                    ARGOS_PROTOCOL_PTP, 0));
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_l2_enabled(&plan, ARGOS_DISPATCH_L2_PTP));
    assert(argos_dispatch_l2_frame_enabled(&plan, 0x88f7U));
    assert(argos_dispatch_ptp_udp_enabled(&plan, 50000U, 319U));
    assert(argos_dispatch_ptp_udp_enabled(&plan, 320U, 50000U));
    assert(!argos_dispatch_ptp_udp_enabled(&plan, 50000U, 321U));

    argos_cli_selection_init(&cli);
    argos_protocol_set_add(&cli.protocols.enabled, ARGOS_PROTOCOL_ESP);
    argos_protocol_set_add(&cli.protocols.enabled, ARGOS_PROTOCOL_AH);
    argos_dispatch_plan_compile(&plan, &cli);
    assert(argos_dispatch_ip_protocol_engine(&plan, 50U) == ARGOS_PROTOCOL_ESP);
    assert(argos_dispatch_ip_protocol_engine(&plan, 51U) == ARGOS_PROTOCOL_AH);
    assert(argos_dispatch_ip_protocol_engine(&plan, 89U) == ARGOS_PROTOCOL_COUNT);

    static const struct {
        uint16_t port;
        argos_protocol_id_t engine;
    } tcp_engines[] = {
        {22U, ARGOS_PROTOCOL_SSH}, {88U, ARGOS_PROTOCOL_KERBEROS},
        {111U, ARGOS_PROTOCOL_SUNRPC}, {179U, ARGOS_PROTOCOL_BGP},
        {445U, ARGOS_PROTOCOL_SMB}, {502U, ARGOS_PROTOCOL_MODBUS},
        {514U, ARGOS_PROTOCOL_SYSLOG},
        {631U, ARGOS_PROTOCOL_IPP}, {1433U, ARGOS_PROTOCOL_MSSQL},
        {1521U, ARGOS_PROTOCOL_ORACLE}, {1883U, ARGOS_PROTOCOL_MQTT},
        {2000U, ARGOS_PROTOCOL_SCCP}, {2049U, ARGOS_PROTOCOL_NFS},
        {3260U, ARGOS_PROTOCOL_ISCSI}, {3306U, ARGOS_PROTOCOL_MYSQL},
        {3389U, ARGOS_PROTOCOL_RDP}, {5060U, ARGOS_PROTOCOL_SIP},
        {4739U, ARGOS_PROTOCOL_IPFIX},
        {5432U, ARGOS_PROTOCOL_POSTGRESQL}, {9100U, ARGOS_PROTOCOL_PJL},
        {44818U, ARGOS_PROTOCOL_ETHERNET_IP},
    };
    for (size_t i = 0; i < sizeof(tcp_engines) / sizeof(tcp_engines[0]); ++i) {
        argos_cli_selection_init(&cli);
        assert(argos_protocol_selection_apply_protocol(
            &cli.protocols, tcp_engines[i].engine, 0));
        argos_dispatch_plan_compile(&plan, &cli);
        assert(argos_dispatch_tcp_port_engine(
            &plan, 50000U, tcp_engines[i].port) == tcp_engines[i].engine);
        assert(argos_dispatch_tcp_port_engine(
            &plan, tcp_engines[i].port, 50000U) == tcp_engines[i].engine);
        assert(argos_dispatch_tcp_port_engine(&plan, 50000U, 65535U) ==
               ARGOS_PROTOCOL_COUNT);
    }
    static const struct {
        uint16_t port;
        argos_protocol_id_t engine;
    } udp_engines[] = {
        {88U, ARGOS_PROTOCOL_KERBEROS}, {111U, ARGOS_PROTOCOL_SUNRPC},
        {123U, ARGOS_PROTOCOL_NTP}, {161U, ARGOS_PROTOCOL_SNMP},
        {162U, ARGOS_PROTOCOL_SNMP}, {389U, ARGOS_PROTOCOL_CLDAP},
        {514U, ARGOS_PROTOCOL_SYSLOG},
        {520U, ARGOS_PROTOCOL_RIP}, {521U, ARGOS_PROTOCOL_RIP},
        {427U, ARGOS_PROTOCOL_VMWARE_SLP}, {623U, ARGOS_PROTOCOL_IPMI},
        {1812U, ARGOS_PROTOCOL_RADIUS}, {1813U, ARGOS_PROTOCOL_RADIUS},
        {1985U, ARGOS_PROTOCOL_HSRP}, {2049U, ARGOS_PROTOCOL_NFS},
        {2055U, ARGOS_PROTOCOL_NETFLOW}, {9995U, ARGOS_PROTOCOL_NETFLOW},
        {9996U, ARGOS_PROTOCOL_NETFLOW}, {4739U, ARGOS_PROTOCOL_IPFIX},
        {6343U, ARGOS_PROTOCOL_SFLOW},
        {3478U, ARGOS_PROTOCOL_STUN_TURN}, {5060U, ARGOS_PROTOCOL_SIP},
        {5678U, ARGOS_PROTOCOL_MNDP}, {5683U, ARGOS_PROTOCOL_COAP},
        {44818U, ARGOS_PROTOCOL_ETHERNET_IP}, {47808U, ARGOS_PROTOCOL_BACNET},
    };
    for (size_t i = 0; i < sizeof(udp_engines) / sizeof(udp_engines[0]); ++i) {
        argos_cli_selection_init(&cli);
        assert(argos_protocol_selection_apply_protocol(
            &cli.protocols, udp_engines[i].engine, 0));
        argos_dispatch_plan_compile(&plan, &cli);
        assert(argos_dispatch_udp_port_engine(
            &plan, 50000U, udp_engines[i].port) == udp_engines[i].engine);
        assert(argos_dispatch_udp_port_engine(
            &plan, udp_engines[i].port, 50000U) == udp_engines[i].engine);
    }
    static const struct {
        uint16_t port;
        argos_protocol_id_t engine;
        int tcp;
    } shared_engines[] = {
        {9100U, ARGOS_PROTOCOL_JETDIRECT, 1},
        {44818U, ARGOS_PROTOCOL_CIP, 1},
        {389U, ARGOS_PROTOCOL_NETLOGON, 0},
        {623U, ARGOS_PROTOCOL_RMCP, 0},
        {623U, ARGOS_PROTOCOL_ASF, 0},
        {44818U, ARGOS_PROTOCOL_CIP, 0},
    };
    for (size_t i = 0; i < sizeof(shared_engines) / sizeof(shared_engines[0]); ++i) {
        argos_cli_selection_init(&cli);
        assert(argos_protocol_selection_apply_protocol(
            &cli.protocols, shared_engines[i].engine, 0));
        argos_dispatch_plan_compile(&plan, &cli);
        argos_protocol_id_t engine = shared_engines[i].tcp ?
            argos_dispatch_tcp_port_engine(&plan, 50000U, shared_engines[i].port) :
            argos_dispatch_udp_port_engine(&plan, 50000U, shared_engines[i].port);
        assert(engine == shared_engines[i].engine);
    }

    argos_cli_selection_init(&cli);
    argos_cli_selection_apply_legacy_all(&cli, 0);
    argos_dispatch_plan_compile(&plan, &cli);
    for (unsigned category = ARGOS_LEGACY_CATEGORY_SYN;
         category <= ARGOS_LEGACY_CATEGORY_L2; ++category)
        assert(argos_dispatch_legacy_enabled(
            &plan, (argos_legacy_category_id_t)category));
    assert(!argos_dispatch_legacy_enabled(
        &plan, ARGOS_LEGACY_CATEGORY_ENTERPRISE));

    /* Legacy projections remain exact for both rate modes. */
    for (unsigned category = 0; category < ARGOS_LEGACY_CATEGORY_COUNT; ++category) {
        argos_cli_selection_init(&cli);
        argos_cli_selection_apply_legacy(
            &cli, (argos_legacy_category_id_t)category, 0);
        argos_dispatch_plan_compile(&plan, &cli);
        assert(argos_dispatch_legacy_enabled(
            &plan, (argos_legacy_category_id_t)category));
        assert(argos_dispatch_legacy_rate_limited(
            &plan, (argos_legacy_category_id_t)category));

        argos_cli_selection_apply_legacy(
            &cli, (argos_legacy_category_id_t)category, 1);
        argos_dispatch_plan_compile(&plan, &cli);
        assert(argos_dispatch_legacy_enabled(
            &plan, (argos_legacy_category_id_t)category));
        assert(!argos_dispatch_legacy_rate_limited(
            &plan, (argos_legacy_category_id_t)category));
        for (unsigned protocol = 0; protocol < ARGOS_PROTOCOL_COUNT; ++protocol) {
            if (argos_dispatch_protocol_enabled(&plan, (argos_protocol_id_t)protocol))
                assert(!argos_dispatch_protocol_rate_limited(
                    &plan, (argos_protocol_id_t)protocol));
        }
    }

    memset(&plan, 0xa5, sizeof(plan));
    argos_dispatch_plan_compile(&plan, NULL);
    assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_DNS));
    assert(plan.l2_routes == 0U && plan.l3_routes == 0U && plan.l4_routes == 0U &&
           plan.transport_routes == 0U);

    puts("Startup dispatch plan and disabled-engine gates: PASS");
    return 0;
}
