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

    assert((argos_protocol_catalog[ARGOS_PROTOCOL_LLDP_MED].status &
            (ARGOS_PROTOCOL_STATUS_PRODUCTION | ARGOS_PROTOCOL_STATUS_STAGING)) ==
           (ARGOS_PROTOCOL_STATUS_PRODUCTION | ARGOS_PROTOCOL_STATUS_STAGING));
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
    assert(!argos_protocol_selection_apply_protocol(&selection, ARGOS_PROTOCOL_RIP, 1));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_RIP));

    argos_protocol_set_t routing;
    argos_group_protocol_mask(ARGOS_GROUP_ROUTING, &routing);
    argos_protocol_selection_apply_mask(&selection, &routing, 1);
    assert(argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_BGP));
    assert(argos_protocol_set_has(&selection.unrated, ARGOS_PROTOCOL_OSPF));
    assert(!argos_protocol_set_has(&selection.enabled, ARGOS_PROTOCOL_RIP));

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

    puts("Canonical config catalog/bitmap contracts: PASS");
    return 0;
}
