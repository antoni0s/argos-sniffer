#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_config.h"

static size_t bit_count(const argos_protocol_set_t *set) {
    size_t count = 0;
    for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p)
        count += (size_t)argos_protocol_set_has(set, (argos_protocol_id_t)p);
    return count;
}

int main(void) {
    static const unsigned expected_group_counts[ARGOS_GROUP_COUNT] = {
        5, 6, 8, 2, 4, 2, 2, 2, 2, 2, 5, 1, 4, 4, 4,
        4, 4, 6, 5, 4, 9, 2, 6, 1, 2, 2, 2, 3
    };
    unsigned memberships[ARGOS_PROTOCOL_COUNT] = {0};
    assert(ARGOS_PROTOCOL_COUNT == 101);
    assert(ARGOS_PROTOCOL_WORDS == 2U);
    assert(sizeof(argos_protocol_set_t) == 16U);
    assert(sizeof(argos_protocol_selection_t) == 32U);
    assert(sizeof(argos_feature_selection_t) == 8U);
    assert(sizeof(argos_cli_selection_t) == 56U);
    assert(ARGOS_FEATURE_COUNT == 5);
    assert(ARGOS_GROUP_COUNT == 28);
    assert(ARGOS_GROUP_MEMBERSHIP_COUNT == 103U);
    assert(ARGOS_SUPER_GROUP_COUNT == 6);
    assert(ARGOS_PROFILE_COUNT == 6);

    for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p) {
        assert(argos_protocol_catalog[p].name && argos_protocol_catalog[p].name[0]);
        assert(argos_protocol_catalog[p].status != 0U);
        for (unsigned q = p + 1U; q < ARGOS_PROTOCOL_COUNT; ++q)
            assert(strcmp(argos_protocol_catalog[p].name,
                          argos_protocol_catalog[q].name) != 0);
    }
    for (unsigned g = 0; g < ARGOS_GROUP_COUNT; ++g) {
        assert(argos_group_catalog[g].name && argos_group_catalog[g].name[0]);
        for (unsigned h = g + 1U; h < ARGOS_GROUP_COUNT; ++h)
            assert(strcmp(argos_group_catalog[g].name, argos_group_catalog[h].name) != 0);
    }
    for (size_t i = 0; i < ARGOS_GROUP_MEMBERSHIP_COUNT; ++i) {
        argos_group_id_t group = argos_group_memberships[i].group;
        argos_protocol_id_t protocol = argos_group_memberships[i].protocol;
        assert((unsigned)group < ARGOS_GROUP_COUNT);
        assert((unsigned)protocol < ARGOS_PROTOCOL_COUNT);
        assert(argos_group_catalog[group].super_group ==
               argos_protocol_catalog[protocol].super_group);
        memberships[protocol]++;
    }
    for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p) {
        unsigned expected = (p == ARGOS_PROTOCOL_NFS || p == ARGOS_PROTOCOL_NTLM) ? 2U : 1U;
        assert(memberships[p] == expected);
    }

    for (unsigned g = 0; g < ARGOS_GROUP_COUNT; ++g) {
        argos_protocol_set_t mask;
        argos_group_protocol_mask((argos_group_id_t)g, &mask);
        assert(bit_count(&mask) == expected_group_counts[g]);
    }
    static const unsigned expected_super_counts[ARGOS_SUPER_GROUP_COUNT] = {
        29, 24, 30, 9, 4, 5
    };
    for (unsigned s = 0; s < ARGOS_SUPER_GROUP_COUNT; ++s) {
        argos_protocol_set_t mask;
        argos_super_group_protocol_mask((argos_super_group_id_t)s, &mask);
        assert(bit_count(&mask) == expected_super_counts[s]);
    }
    argos_protocol_set_t enterprise, fileshare, storage, identity;
    argos_super_group_protocol_mask(ARGOS_SUPER_GROUP_ENTERPRISE, &enterprise);
    argos_group_protocol_mask(ARGOS_GROUP_FILESHARE, &fileshare);
    argos_group_protocol_mask(ARGOS_GROUP_STORAGE, &storage);
    argos_group_protocol_mask(ARGOS_GROUP_IDENTITY, &identity);
    assert(bit_count(&enterprise) == 30U);
    assert(argos_protocol_set_has(&fileshare, ARGOS_PROTOCOL_NFS));
    assert(argos_protocol_set_has(&storage, ARGOS_PROTOCOL_NFS));
    assert(argos_protocol_set_has(&fileshare, ARGOS_PROTOCOL_NTLM));
    assert(argos_protocol_set_has(&identity, ARGOS_PROTOCOL_NTLM));

    argos_protocol_id_t protocol;
    int unrated;
    assert(argos_protocol_name_lookup("dns", &protocol, &unrated));
    assert(protocol == ARGOS_PROTOCOL_DNS && !unrated);
    assert(argos_protocol_name_lookup("DNS", &protocol, &unrated));
    assert(protocol == ARGOS_PROTOCOL_DNS && unrated);
    assert(argos_protocol_name_lookup("STUN-TURN", &protocol, &unrated));
    assert(protocol == ARGOS_PROTOCOL_STUN_TURN && unrated);
    assert(!argos_protocol_name_lookup("Dns", &protocol, &unrated));
    assert(!argos_protocol_name_lookup("unknown", &protocol, &unrated));

    argos_group_id_t group;
    argos_super_group_id_t super_group;
    argos_profile_id_t profile;
    assert(argos_group_name_lookup("identity", &group) && group == ARGOS_GROUP_IDENTITY);
    assert(argos_super_group_name_lookup("vpn", &super_group) &&
           super_group == ARGOS_SUPER_GROUP_VPN);
    assert(argos_profile_name_lookup("sensor", &profile) && profile == ARGOS_PROFILE_SENSOR);
    assert(!argos_group_name_lookup("IDENTITY", &group));

    argos_protocol_set_t edges = {0};
    argos_protocol_set_add(&edges, ARGOS_PROTOCOL_DHCP);
    argos_protocol_set_add(&edges, ARGOS_PROTOCOL_AH);
    assert(argos_protocol_set_has(&edges, ARGOS_PROTOCOL_DHCP));
    assert(argos_protocol_set_has(&edges, ARGOS_PROTOCOL_AH));
    assert(!argos_protocol_set_has(&edges, (argos_protocol_id_t)ARGOS_PROTOCOL_COUNT));

    assert(argos_protocol_catalog[ARGOS_PROTOCOL_LLDP_MED].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_STP].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_LACP].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_RIP].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_SYSLOG].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_NETFLOW].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_IPFIX].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert(argos_protocol_catalog[ARGOS_PROTOCOL_SFLOW].status == ARGOS_PROTOCOL_STATUS_PRODUCTION);
    assert((argos_protocol_catalog[ARGOS_PROTOCOL_THREAD].status &
            ARGOS_PROTOCOL_STATUS_HOLD) != 0U);
    assert((argos_protocol_catalog[ARGOS_PROTOCOL_ESP].status &
            ARGOS_PROTOCOL_STATUS_HOLD) != 0U);

    argos_protocol_selection_t selection;
    argos_protocol_selection_clear(&selection);
    assert(argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_DNS, 0));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_DNS));
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));
    assert(argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_DNS, 1));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));
    assert(argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_DNS, 0));
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));
    assert(argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_RIP, 1));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_RIP));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_RIP));

    argos_protocol_selection_clear(&selection);
    argos_cli_selection_t rip_cli;
    argos_cli_selection_init(&rip_cli);
    assert(argos_cli_selection_apply_named(
        &rip_cli, ARGOS_CLI_SELECTOR_PROTOCOL, "rip"));
    assert(argos_protocol_set_has(&rip_cli.protocols.enabled, ARGOS_PROTOCOL_RIP));
    assert(!argos_protocol_set_has(&rip_cli.protocols.unrated, ARGOS_PROTOCOL_RIP));
    assert(argos_cli_selection_apply_named(
        &rip_cli, ARGOS_CLI_SELECTOR_PROTOCOL, "RIP"));
    assert(argos_protocol_set_has(&rip_cli.protocols.unrated, ARGOS_PROTOCOL_RIP));

    argos_protocol_set_t routing;
    argos_group_protocol_mask(ARGOS_GROUP_ROUTING, &routing);
    argos_protocol_selection_apply_mask(&selection, &routing, 1);
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_BGP));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_OSPF));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_RIP));

    argos_protocol_set_t all_production;
    argos_production_protocol_mask(&all_production);
    argos_protocol_selection_clear(&selection);
    argos_protocol_selection_apply_mask(&selection, &all_production, 0);
    assert(memcmp(&selection.enabled, &all_production, sizeof(all_production)) == 0);
    assert(bit_count(&selection.unrated) == 0U);
    argos_super_group_protocol_mask(ARGOS_SUPER_GROUP_ENTERPRISE, &enterprise);
    argos_protocol_selection_unrate_enabled(&selection, &enterprise);
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_SMB));
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));

    argos_protocol_selection_clear(&selection);
    argos_protocol_selection_unrate_enabled(&selection, &enterprise);
    assert(bit_count(&selection.enabled) == 0U && bit_count(&selection.unrated) == 0U);

    argos_protocol_set_t rate_target;
    argos_rate_target_kind_t target_kind;
    assert(argos_rate_target_mask("all", &rate_target, &target_kind));
    assert(target_kind == ARGOS_RATE_TARGET_ALL);
    assert(memcmp(&rate_target, &all_production, sizeof(rate_target)) == 0);
    assert(argos_rate_target_mask("enterprise", &rate_target, &target_kind));
    assert(target_kind == ARGOS_RATE_TARGET_SUPER_GROUP);
    assert(argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_SMB));
    assert(argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_SYSLOG));
    assert(argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_NETFLOW));
    assert(argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_IPFIX));
    assert(argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_SFLOW));
    assert(argos_rate_target_mask("identity", &rate_target, &target_kind));
    assert(target_kind == ARGOS_RATE_TARGET_GROUP);
    assert(argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_KERBEROS));
    assert(!argos_protocol_set_has(&rate_target, ARGOS_PROTOCOL_TACACS));
    memset(&rate_target, 0xff, sizeof(rate_target));
    assert(!argos_rate_target_mask("IDENTITY", &rate_target, &target_kind));
    assert(bit_count(&rate_target) == 0U);

    argos_protocol_selection_clear(&selection);
    argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_DNS, 0);
    argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_NTLM, 0);
    assert(argos_protocol_selection_apply_no_rate_limit(&selection, "identity"));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_NTLM));
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));
    argos_protocol_selection_t before_invalid = selection;
    assert(!argos_protocol_selection_apply_no_rate_limit(&selection, "dns"));
    assert(memcmp(&selection, &before_invalid, sizeof(selection)) == 0);
    assert(argos_protocol_selection_apply_no_rate_limit(&selection, "all"));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));

    argos_feature_selection_t feature_selection;
    argos_feature_selection_clear(&feature_selection);
    argos_feature_selection_apply(&feature_selection, ARGOS_FEATURE_TCP_SYN, 1);
    assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_TCP_SYN));
    assert((feature_selection.unrated & argos_feature_bit(ARGOS_FEATURE_TCP_SYN)) != 0U);
    argos_feature_selection_apply(&feature_selection, ARGOS_FEATURE_TCP_SYN, 0);
    assert((feature_selection.unrated & argos_feature_bit(ARGOS_FEATURE_TCP_SYN)) == 0U);
    argos_feature_selection_apply(&feature_selection, ARGOS_FEATURE_IPV6, 1);
    assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_IPV6));
    assert((feature_selection.unrated & argos_feature_bit(ARGOS_FEATURE_IPV6)) == 0U);

    static const size_t expected_legacy_counts[ARGOS_LEGACY_CATEGORY_COUNT] = {
        0U, 4U, 2U, 1U, 1U, 1U, 3U, 4U, 50U
    };
    for (unsigned category = 0; category < ARGOS_LEGACY_CATEGORY_COUNT; ++category) {
        argos_protocol_set_t mask;
        argos_feature_set_t features;
        argos_legacy_category_mask((argos_legacy_category_id_t)category, &mask, &features);
        assert(bit_count(&mask) == expected_legacy_counts[category]);
        assert(features == (category == ARGOS_LEGACY_CATEGORY_SYN
                            ? argos_feature_bit(ARGOS_FEATURE_TCP_SYN) : 0U));
    }

    argos_protocol_set_t legacy_enterprise;
    argos_legacy_enterprise_protocol_mask(&legacy_enterprise);
    assert(argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_CDP));
    assert(argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_NTLM));
    assert(argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_JETDIRECT));
    assert(argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_CIP));
    assert(argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_WIREGUARD));
    assert(!argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_TLS));
    assert(!argos_protocol_set_has(&legacy_enterprise, ARGOS_PROTOCOL_RIP));

    argos_protocol_selection_clear(&selection);
    argos_feature_selection_clear(&feature_selection);
    argos_legacy_selection_apply(&selection, &feature_selection,
                                 ARGOS_LEGACY_CATEGORY_ENTERPRISE, 1);
    assert(bit_count(&selection.enabled) == 50U);
    assert(bit_count(&selection.unrated) == 50U);
    assert(feature_selection.enabled == 0U && feature_selection.unrated == 0U);

    argos_protocol_selection_clear(&selection);
    argos_feature_selection_clear(&feature_selection);
    argos_legacy_selection_apply_all(&selection, &feature_selection, 1);
    assert(bit_count(&selection.enabled) == 16U);
    assert(bit_count(&selection.unrated) == 16U);
    assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_TCP_SYN));
    assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_IPV6));
    assert((feature_selection.unrated & argos_feature_bit(ARGOS_FEATURE_TCP_SYN)) != 0U);
    assert((feature_selection.unrated & argos_feature_bit(ARGOS_FEATURE_IPV6)) == 0U);
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_SMB));

    argos_legacy_selection_apply(&selection, &feature_selection,
                                 ARGOS_LEGACY_CATEGORY_TLS, 0);
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_TLS));
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DOT));
    assert(!argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_QUIC));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_DNS));

    argos_protocol_selection_clear(&selection);
    argos_feature_selection_clear(&feature_selection);
    argos_legacy_selection_apply_default(&selection, &feature_selection);
    assert(bit_count(&selection.enabled) == 7U);
    assert(bit_count(&selection.unrated) == 0U);
    assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_TCP_SYN));
    assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_IPV6));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_DNS));

    static const size_t expected_profile_counts[ARGOS_PROFILE_COUNT] = {
        7U, 16U, 76U, 38U, 50U, 76U
    };
    for (unsigned profile_id = 0; profile_id < ARGOS_PROFILE_COUNT; ++profile_id) {
        assert(argos_profile_selection((argos_profile_id_t)profile_id,
                                       &selection, &feature_selection));
        assert(bit_count(&selection.enabled) == expected_profile_counts[profile_id]);
        assert(bit_count(&selection.unrated) == 0U);
        assert(argos_feature_selection_has(&feature_selection, ARGOS_FEATURE_IPV6));
        assert(!argos_feature_selection_has(&feature_selection,
                                            ARGOS_FEATURE_QUIC_STATEFUL));
        assert(!argos_feature_selection_has(&feature_selection,
                                            ARGOS_FEATURE_SENSOR_DEPLOYMENT));
        for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p)
            if (argos_protocol_set_has(&selection.enabled, (argos_protocol_id_t)p))
                assert(argos_protocol_is_production((argos_protocol_id_t)p));
    }
    assert(argos_profile_selection(ARGOS_PROFILE_CORE, &selection, &feature_selection));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_DHCP));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_DNS));
    assert(argos_profile_selection(ARGOS_PROFILE_STANDARD, &selection, &feature_selection));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_TLS));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_SMB));
    assert(argos_profile_selection(ARGOS_PROFILE_HOME, &selection, &feature_selection));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_COAP));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_WIREGUARD));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_PTP));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_LLMNR));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_BGP));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_SMB));
    assert(argos_profile_selection(ARGOS_PROFILE_ENTERPRISE, &selection, &feature_selection));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_SMB));
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_BGP));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_TLS));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_RIP));
    assert(argos_profile_selection(ARGOS_PROFILE_SENSOR, &selection, &feature_selection));
    assert(argos_feature_selection_has(&feature_selection,
                                       ARGOS_FEATURE_EXTENDED_METRICS));
    assert(!argos_profile_selection((argos_profile_id_t)ARGOS_PROFILE_COUNT,
                                    &selection, &feature_selection));

    argos_cli_selection_t cli;
    argos_cli_selection_init(&cli);
    argos_cli_selection_finalize(&cli);
    assert(bit_count(&cli.protocols.enabled) == 7U);
    assert(argos_feature_selection_has(&cli.features, ARGOS_FEATURE_TCP_SYN));

    argos_cli_selection_init(&cli);
    argos_cli_selection_apply_feature(&cli, ARGOS_FEATURE_EXTENDED_METRICS, 0);
    argos_cli_selection_finalize(&cli);
    assert(bit_count(&cli.protocols.enabled) == 7U);
    assert(argos_feature_selection_has(&cli.features, ARGOS_FEATURE_EXTENDED_METRICS));

    argos_cli_selection_init(&cli);
    argos_cli_selection_apply_feature(&cli, ARGOS_FEATURE_QUIC_STATEFUL, 0);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROFILE, "sensor"));
    assert(argos_feature_selection_has(&cli.features, ARGOS_FEATURE_QUIC_STATEFUL));
    assert(argos_feature_selection_has(&cli.features, ARGOS_FEATURE_EXTENDED_METRICS));
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROFILE, "home"));
    assert(argos_feature_selection_has(&cli.features, ARGOS_FEATURE_QUIC_STATEFUL));
    assert(!argos_feature_selection_has(&cli.features, ARGOS_FEATURE_EXTENDED_METRICS));

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROFILE, "home"));
    assert(bit_count(&cli.protocols.enabled) == 38U);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_GROUP, "routing"));
    assert(bit_count(&cli.protocols.enabled) == 42U);
    assert(argos_protocol_set_has(&cli.protocols.enabled, ARGOS_PROTOCOL_RIP));
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "DNS"));
    assert(argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_DNS));
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "dns"));
    assert(!argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_DNS));
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_NO_RATE_LIMIT,
                                           "network"));
    assert(argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_BGP));
    assert(!argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_TLS));

    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROFILE, "core"));
    assert(bit_count(&cli.protocols.enabled) == 7U);
    assert(!argos_protocol_set_has(&cli.protocols.enabled, ARGOS_PROTOCOL_BGP));
    assert(!argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_DNS));

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_GROUP, "identity"));
    assert(bit_count(&cli.protocols.enabled) == 4U);
    assert(argos_protocol_set_has(&cli.protocols.enabled, ARGOS_PROTOCOL_KERBEROS));
    assert(!argos_protocol_set_has(&cli.protocols.enabled, ARGOS_PROTOCOL_TACACS));
    assert(cli.features.enabled == 0U);

    argos_cli_selection_t cli_before = cli;
    assert(!argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_GROUP, "IDENTITY"));
    assert(!argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "Rip"));
    assert(!argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "llmnr"));
    assert(!argos_cli_selection_apply_named(&cli, (argos_cli_selector_kind_t)99, "dns"));
    assert(memcmp(&cli, &cli_before, sizeof(cli)) == 0);

    argos_cli_selection_init(&cli);
    assert(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_NO_RATE_LIMIT,
                                           "all"));
    assert(bit_count(&cli.protocols.enabled) == 0U);
    assert(bit_count(&cli.protocols.unrated) == 0U);
    argos_cli_selection_finalize(&cli);
    assert(bit_count(&cli.protocols.enabled) == 7U);
    assert(bit_count(&cli.protocols.unrated) == 0U);

    argos_cli_selection_init(&cli);
    argos_cli_selection_apply_legacy(&cli, ARGOS_LEGACY_CATEGORY_TLS, 1);
    argos_cli_selection_apply_legacy(&cli, ARGOS_LEGACY_CATEGORY_DNS, 0);
    argos_cli_selection_finalize(&cli);
    assert(bit_count(&cli.protocols.enabled) == 4U);
    assert(argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_TLS));
    assert(!argos_protocol_set_has(&cli.protocols.unrated, ARGOS_PROTOCOL_DNS));

    for (unsigned category = 0; category < ARGOS_LEGACY_CATEGORY_COUNT; ++category) {
        argos_cli_selection_init(&cli);
        argos_cli_selection_apply_legacy(&cli, (argos_legacy_category_id_t)category, 0);
        assert(argos_cli_legacy_category_enabled(&cli,
                                                (argos_legacy_category_id_t)category));
        assert(argos_cli_legacy_category_rate_limited(
            &cli, (argos_legacy_category_id_t)category));
        argos_cli_selection_apply_legacy(&cli, (argos_legacy_category_id_t)category, 1);
        assert(argos_cli_legacy_category_enabled(&cli,
                                                (argos_legacy_category_id_t)category));
        assert(!argos_cli_legacy_category_rate_limited(
            &cli, (argos_legacy_category_id_t)category));
        for (unsigned other = 0; other < ARGOS_LEGACY_CATEGORY_COUNT; ++other)
            if (other != category)
                assert(!argos_cli_legacy_category_enabled(
                    &cli, (argos_legacy_category_id_t)other));
    }

    argos_cli_selection_init(&cli);
    argos_cli_selection_apply_legacy_all(&cli, 1);
    for (unsigned category = ARGOS_LEGACY_CATEGORY_SYN;
         category <= ARGOS_LEGACY_CATEGORY_L2; ++category) {
        assert(argos_cli_legacy_category_enabled(
            &cli, (argos_legacy_category_id_t)category));
        assert(!argos_cli_legacy_category_rate_limited(
            &cli, (argos_legacy_category_id_t)category));
    }
    assert(!argos_cli_legacy_category_enabled(&cli,
                                              ARGOS_LEGACY_CATEGORY_ENTERPRISE));
    argos_cli_selection_apply_legacy(&cli, ARGOS_LEGACY_CATEGORY_TLS, 0);
    assert(argos_cli_legacy_category_rate_limited(&cli, ARGOS_LEGACY_CATEGORY_TLS));
    assert(!argos_cli_legacy_category_rate_limited(&cli, ARGOS_LEGACY_CATEGORY_DNS));

    puts("Canonical config catalog/bitmap contracts: PASS");
    return 0;
}
