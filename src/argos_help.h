#ifndef ARGOS_HELP_H
#define ARGOS_HELP_H

#include <stdio.h>
#include <string.h>

#include "argos_config.h"

#define ARGOS_PRODUCT_NAME "argos-sniffer v6.0"
#define ARGOS_PRODUCT_DESCRIPTION "Passive network fingerprinting & telemetry engine"

typedef enum {
    ARGOS_HELP_BASE = 0,
    ARGOS_HELP_PROFILES,
    ARGOS_HELP_NETWORK,
    ARGOS_HELP_APPLICATION,
    ARGOS_HELP_ENTERPRISE,
    ARGOS_HELP_INDUSTRIAL,
    ARGOS_HELP_IOT,
    ARGOS_HELP_VPN,
    ARGOS_HELP_CAPTURE,
    ARGOS_HELP_OUTPUT,
    ARGOS_HELP_RATE,
    ARGOS_HELP_IDENTITY,
    ARGOS_HELP_PERFORMANCE
} argos_help_topic_t;

typedef struct {
    const char *option;
    argos_help_topic_t topic;
} argos_help_option_t;

static const argos_help_option_t argos_help_options[] = {
    {"--help", ARGOS_HELP_BASE},
    {"--help-profiles", ARGOS_HELP_PROFILES},
    {"--help-network", ARGOS_HELP_NETWORK},
    {"--help-application", ARGOS_HELP_APPLICATION},
    {"--help-enterprise", ARGOS_HELP_ENTERPRISE},
    {"--help-industrial", ARGOS_HELP_INDUSTRIAL},
    {"--help-iot", ARGOS_HELP_IOT},
    {"--help-vpn", ARGOS_HELP_VPN},
    {"--help-capture", ARGOS_HELP_CAPTURE},
    {"--help-output", ARGOS_HELP_OUTPUT},
    {"--help-rate", ARGOS_HELP_RATE},
    {"--help-identity", ARGOS_HELP_IDENTITY},
    {"--help-performance", ARGOS_HELP_PERFORMANCE}
};

static inline void argos_help_print_base(FILE *out, const char *program,
                                         const char *version) {
    fprintf(out,
        ARGOS_PRODUCT_NAME "\n" ARGOS_PRODUCT_DESCRIPTION "\nBuild: %s\n\n"
        "USAGE\n  %s [capture/output options] [selectors]\n\n"
        "QUICK START\n"
        "  -a / -A                 all legacy vectors, limited / unlimited\n"
        "  --profile NAME          core, standard, full, home, enterprise, sensor\n"
        "  --super-group NAME      network, application, industrial, iot, vpn\n"
        "  --super-group enterprise   canonical enterprise groups\n"
        "  --group NAME            canonical group (use --group identity)\n"
        "  --protocol NAME         lowercase limited; UPPERCASE unlimited\n"
        "  Canonical selectors activate production entries; staged * entries stay unavailable.\n\n"
        "CAPTURE\n"
        "  -i IFACE  -r MAC  -R MAC  -x EXPR  -z EXPR  -Z EXPR  -p  -c COUNT\n\n"
        "OUTPUT\n"
        "  -o PATH   -u HOST:PORT   -U HOST:PORT   -f SECONDS\n\n"
        "MODES\n"
        "  --sensor --sensor-name NAME [--inside CIDR]\n"
        "  --enterprise | --enterprise-verbose     v6 compatibility bundle\n"
        "  --identity[=hash|raw]  -E  -W  --wireguard-port PORT\n\n"
        "MORE HELP\n"
        "  --help-profiles  --help-network  --help-application  --help-enterprise\n"
        "  --help-industrial --help-iot --help-vpn --help-capture --help-output\n"
        "  --help-rate --help-identity --help-performance --version\n",
        version, program);
}

static inline void argos_help_print_protocols(FILE *out,
                                               const argos_protocol_set_t *mask) {
    int first = 1;
    size_t column = 4U;
    fputs("    ", out);
    for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p) {
        if (!argos_protocol_set_has(mask, (argos_protocol_id_t)p)) continue;
        const char *name = argos_protocol_catalog[p].name;
        size_t item_length = strlen(name) +
            (argos_protocol_is_production((argos_protocol_id_t)p) ? 0U : 1U);
        if (!first && column + 2U + item_length > 78U) {
            fputs(",\n    ", out);
            column = 4U;
        } else if (!first) {
            fputs(", ", out);
            column += 2U;
        }
        fprintf(out, "%s%s", name,
                argos_protocol_is_production((argos_protocol_id_t)p) ? "" : "*");
        column += item_length;
        first = 0;
    }
    fputc('\n', out);
}

static inline void argos_help_print_super_group(FILE *out,
                                                 argos_super_group_id_t super_group) {
    fprintf(out, "%s\n  Canonical catalog; runtime adoption follows the C4 gate.\n\n"
                 "  --super-group %s\n",
            argos_super_group_catalog[super_group].name,
            argos_super_group_catalog[super_group].name);
    for (unsigned g = 0; g < ARGOS_GROUP_COUNT; ++g) {
        if (argos_group_catalog[g].super_group != super_group) continue;
        argos_protocol_set_t mask;
        argos_group_protocol_mask((argos_group_id_t)g, &mask);
        fprintf(out, "\n  --group %s\n", argos_group_catalog[g].name);
        argos_help_print_protocols(out, &mask);
    }
    fputs("\n  * staged/HOLD: listed for taxonomy only; not runtime-enabled\n", out);
}

static inline void argos_help_print_profiles(FILE *out) {
    fputs("PROFILES\n  Canonical catalog; runtime adoption follows the C4 gate.\n\n", out);
    for (unsigned p = 0; p < ARGOS_PROFILE_COUNT; ++p) {
        argos_protocol_selection_t protocols;
        argos_feature_selection_t features;
        (void)argos_profile_selection((argos_profile_id_t)p, &protocols, &features);
        fprintf(out, "  --profile %s\n", argos_profile_names[p]);
        argos_help_print_protocols(out, &protocols.enabled);
        fputs("    features:", out);
        if (argos_feature_selection_has(&features, ARGOS_FEATURE_TCP_SYN)) fputs(" syn", out);
        if (argos_feature_selection_has(&features, ARGOS_FEATURE_IPV6)) fputs(" ipv6", out);
        if (argos_feature_selection_has(&features, ARGOS_FEATURE_EXTENDED_METRICS))
            fputs(" extended-metrics", out);
        fputs("\n\n", out);
    }
    fputs("Profiles never imply identity mode, stateful QUIC, sensor deployment,\n"
          "or staging/HOLD protocol activation.\n", out);
}

static inline void argos_help_print_topic(FILE *out, argos_help_topic_t topic,
                                           const char *program, const char *version) {
    switch (topic) {
        case ARGOS_HELP_BASE: argos_help_print_base(out, program, version); break;
        case ARGOS_HELP_PROFILES: argos_help_print_profiles(out); break;
        case ARGOS_HELP_NETWORK:
            argos_help_print_super_group(out, ARGOS_SUPER_GROUP_NETWORK); break;
        case ARGOS_HELP_APPLICATION:
            argos_help_print_super_group(out, ARGOS_SUPER_GROUP_APPLICATION); break;
        case ARGOS_HELP_ENTERPRISE:
            argos_help_print_super_group(out, ARGOS_SUPER_GROUP_ENTERPRISE);
            fputs("\n--enterprise and --enterprise-verbose are broader v6 compatibility bundles.\n", out);
            break;
        case ARGOS_HELP_INDUSTRIAL:
            argos_help_print_super_group(out, ARGOS_SUPER_GROUP_INDUSTRIAL); break;
        case ARGOS_HELP_IOT:
            argos_help_print_super_group(out, ARGOS_SUPER_GROUP_IOT); break;
        case ARGOS_HELP_VPN:
            argos_help_print_super_group(out, ARGOS_SUPER_GROUP_VPN); break;
        case ARGOS_HELP_CAPTURE:
            fputs("CAPTURE\n\n"
                  "  -i IFACE       interface/list (default any); explicit interface for --sensor\n"
                  "  -r MAC         soft/router exclusion; DNS responses may remain visible\n"
                  "  -R MAC         hard outbound source-MAC exclusion\n"
                  "  -x EXPR        exclude filter before parsing\n"
                  "  -z EXPR        live inspector filter; implies promiscuous mode\n"
                  "  -Z EXPR        telemetry target filter\n"
                  "  -p             promiscuous mode\n"
                  "  -c COUNT       live-inspector packet limit; 0 is unlimited\n"
                  "  --sensor --sensor-name NAME [--inside CIDR ...]\n"
                  "VLAN/QinQ/PPPoE are bounded by normalized declared frame lengths.\n", out);
            break;
        case ARGOS_HELP_OUTPUT:
            fputs("OUTPUT\n\n"
                  "  -o PATH        Unix datagram sink\n"
                  "  -u HOST:PORT   remote UDP only\n"
                  "  -U HOST:PORT   remote UDP plus stdout\n"
                  "UDP telemetry is plaintext; use only a trusted path.\n"
                  "Gateway records retain the legacy grammar; sensor mode wraps OBS|... .\n"
                  "JSONL/canonical-schema output is not enabled before the C7 contract.\n", out);
            break;
        case ARGOS_HELP_RATE:
            fprintf(out,
                    "RATE\n\n"
                    "  lowercase protocol   limited/deduplicated output\n"
                    "  UPPERCASE protocol   same protocol, unrated output\n"
                    "  -f SECONDS           dedup window (compiled default: %d)\n"
                    "  --no-rate-limit=TARGET   enabled all/super-group/group only\n"
                    "Inspection packet/byte/state ceilings always remain active.\n",
                    ARGOS_DEFAULT_RATE_LIMIT_SECONDS);
            break;
        case ARGOS_HELP_IDENTITY:
            fputs("IDENTITY / PRIVACY\n\n"
                  "  --identity[=hash|raw] observed handshake identity; hash is default\n"
                  "  --identity-raw        compatibility alias; explicit privacy opt-in\n"
                  "  --group identity      canonical protocol group, not a privacy mode\n"
                  "Allowed: username/principal, realm/domain, machine/workstation, identity class.\n"
                  "Never emitted: passwords, auth responses/blobs, tickets, session/shared secrets, keys.\n"
                  "Current identity observation requires the v6 --enterprise compatibility mode.\n", out);
            break;
        case ARGOS_HELP_PERFORMANCE:
            fputs("PERFORMANCE\n\n"
                  "  -E   extended metrics; prepares bounded SYN/DNS state before capture\n"
                  "  -W   stateful QUIC; opt-in bounded 64-session reassembly\n"
                  "Default QUIC uses one enabled-only reusable workspace; packet handling allocates nothing.\n"
                  "Flow-shape remains experimental and is not a runtime option.\n", out);
            break;
        default: break;
    }
}

/* Return 0 when normal option parsing should continue, 1 after successful
 * help/version output, and -1 for an unknown thematic help option. Scanning
 * happens before all runtime owner/sink initialization, so argument order cannot
 * make informational commands allocate state or open descriptors. */
static inline int argos_help_preflight(int argc, char *const argv[],
                                       const char *version, FILE *out, FILE *err) {
    if (!argv || argc < 1 || !version || !out || !err) return -1;
    if (argc == 1) {
        argos_help_print_topic(out, ARGOS_HELP_BASE, argv[0], version);
        return 1;
    }
    for (int a = 1; a < argc; ++a) {
        if (strcmp(argv[a], "--version") == 0) {
            fprintf(out, ARGOS_PRODUCT_NAME " (build %s)\n", version);
            return 1;
        }
        for (size_t h = 0; h < sizeof(argos_help_options) / sizeof(argos_help_options[0]); ++h)
            if (strcmp(argv[a], argos_help_options[h].option) == 0) {
                argos_help_print_topic(out, argos_help_options[h].topic, argv[0], version);
                return 1;
            }
        if (strncmp(argv[a], "--help-", 7U) == 0) {
            fprintf(err, "Error: unknown help topic: %.80s\n", argv[a]);
            return -1;
        }
    }
    return 0;
}

#endif
