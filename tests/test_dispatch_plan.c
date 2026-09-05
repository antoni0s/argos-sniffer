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
    assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_RIP));
    assert(argos_dispatch_l2_enabled(&plan, ARGOS_DISPATCH_L2_LLC));
    assert(argos_dispatch_l3_enabled(&plan, ARGOS_DISPATCH_L3_OSPF));
    assert(argos_dispatch_l4_enabled(&plan, ARGOS_DISPATCH_L4_TCP));

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
    }

    memset(&plan, 0xa5, sizeof(plan));
    argos_dispatch_plan_compile(&plan, NULL);
    assert(!argos_dispatch_protocol_enabled(&plan, ARGOS_PROTOCOL_DNS));
    assert(plan.l2_routes == 0U && plan.l3_routes == 0U && plan.l4_routes == 0U);

    puts("Startup dispatch plan and disabled-engine gates: PASS");
    return 0;
}
