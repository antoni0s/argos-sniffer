#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_help.h"

static size_t render_topic(argos_help_topic_t topic, char *buffer, size_t capacity) {
    FILE *stream = tmpfile();
    assert(stream);
    argos_help_print_topic(stream, topic, "argos-sniffer", "test");
    assert(fflush(stream) == 0);
    long length = ftell(stream);
    assert(length >= 0 && (size_t)length < capacity);
    rewind(stream);
    assert(fread(buffer, 1U, (size_t)length, stream) == (size_t)length);
    buffer[length] = '\0';
    assert(fclose(stream) == 0);
    return (size_t)length;
}

static int output_has_protocol(const char *begin, const char *end, const char *name) {
    size_t length = strlen(name);
    const char *found = begin;
    while ((found = strstr(found, name)) != NULL && found < end) {
        char before = found == begin ? '\0' : found[-1];
        char after = found + length < end ? found[length] : '\0';
        if ((before == ' ' || before == ',') &&
            (after == ',' || after == '*' || after == '\n')) return 1;
        ++found;
    }
    return 0;
}

static int protocol_in_super_group(argos_protocol_id_t protocol,
                                   argos_super_group_id_t super_group) {
    for (size_t i = 0; i < ARGOS_GROUP_MEMBERSHIP_COUNT; ++i) {
        argos_group_id_t group = argos_group_memberships[i].group;
        if (argos_group_memberships[i].protocol == protocol &&
            argos_group_catalog[group].super_group == super_group) return 1;
    }
    return 0;
}

int main(void) {
    char output[32768];
    size_t length = render_topic(ARGOS_HELP_BASE, output, sizeof(output));
    unsigned lines = 0;
    for (size_t i = 0; i < length; ++i) lines += output[i] == '\n';
    assert(lines <= 40U);
    assert(length <= 2048U);
    assert(strstr(output, "--help-profiles"));
    assert(strstr(output, "--super-group enterprise"));
    assert(strstr(output, "staged * entries stay unavailable"));
    assert(!strstr(output, "--help-protocols"));

    static const argos_help_topic_t topics[ARGOS_SUPER_GROUP_COUNT] = {
        ARGOS_HELP_NETWORK, ARGOS_HELP_APPLICATION, ARGOS_HELP_ENTERPRISE,
        ARGOS_HELP_INDUSTRIAL, ARGOS_HELP_IOT, ARGOS_HELP_VPN
    };
    for (unsigned s = 0; s < ARGOS_SUPER_GROUP_COUNT; ++s) {
        length = render_topic(topics[s], output, sizeof(output));
        const char *end = output + length;
        for (unsigned g = 0; g < ARGOS_GROUP_COUNT; ++g) {
            char option[64];
            snprintf(option, sizeof(option), "--group %s\n", argos_group_catalog[g].name);
            assert((strstr(output, option) != NULL) ==
                   (argos_group_catalog[g].super_group == (argos_super_group_id_t)s));
        }
        for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p)
            assert(output_has_protocol(output, end, argos_protocol_catalog[p].name) ==
                   protocol_in_super_group((argos_protocol_id_t)p,
                                           (argos_super_group_id_t)s));
    }
    render_topic(ARGOS_HELP_NETWORK, output, sizeof(output));
    assert(strstr(output, "llmnr*"));
    assert(output_has_protocol(output, output + strlen(output), "rip"));
    assert(!strstr(output, "rip*"));
    assert(output_has_protocol(output, output + strlen(output), "ptp"));
    assert(!strstr(output, "ptp*"));
    render_topic(ARGOS_HELP_ENTERPRISE, output, sizeof(output));
    render_topic(ARGOS_HELP_APPLICATION, output, sizeof(output));
    assert(output_has_protocol(output, output + strlen(output), "lpd"));
    assert(!strstr(output, "lpd*"));
    assert(output_has_protocol(output, output + strlen(output), "http-proxy"));
    assert(!strstr(output, "http-proxy*"));
    assert(strstr(output, "vnc*")); /* Remaining group scope is still staged. */
    render_topic(ARGOS_HELP_ENTERPRISE, output, sizeof(output));
    for (const char *name = "syslog"; name; name = !strcmp(name, "syslog") ? "netflow" :
         !strcmp(name, "netflow") ? "ipfix" : !strcmp(name, "ipfix") ? "sflow" : NULL) {
        assert(output_has_protocol(output, output + strlen(output), name));
        char staged[24];
        snprintf(staged, sizeof(staged), "%s*", name);
        assert(!strstr(output, staged));
    }

    length = render_topic(ARGOS_HELP_PROFILES, output, sizeof(output));
    for (unsigned profile = 0; profile < ARGOS_PROFILE_COUNT; ++profile) {
        char heading[64];
        snprintf(heading, sizeof(heading), "--profile %s\n", argos_profile_names[profile]);
        const char *begin = strstr(output, heading);
        assert(begin);
        begin += strlen(heading);
        const char *end = profile + 1U < ARGOS_PROFILE_COUNT
            ? strstr(begin, "  --profile ") : strstr(begin, "Profiles never imply");
        assert(end);
        argos_protocol_selection_t protocols;
        argos_feature_selection_t features;
        assert(argos_profile_selection((argos_profile_id_t)profile, &protocols, &features));
        for (unsigned p = 0; p < ARGOS_PROTOCOL_COUNT; ++p)
            assert(output_has_protocol(begin, end, argos_protocol_catalog[p].name) ==
                   argos_protocol_set_has(&protocols.enabled, (argos_protocol_id_t)p));
    }
    assert(strstr(output, "staging/HOLD protocol activation"));

    length = render_topic(ARGOS_HELP_RATE, output, sizeof(output));
    assert(length < sizeof(output));
    char default_rate[32];
    snprintf(default_rate, sizeof(default_rate), "default: %d", ARGOS_DEFAULT_RATE_LIMIT_SECONDS);
    assert(strstr(output, default_rate));

    char *normal_argv[] = {"argos-sniffer", "-a"};
    assert(argos_help_preflight(2, normal_argv, "test", stdout, stderr) == 0);
    char unknown[160] = "--help-";
    memset(unknown + 7, 'x', 140U);
    unknown[147] = '\0';
    char *bad_argv[] = {"argos-sniffer", unknown};
    FILE *error_stream = tmpfile();
    assert(error_stream);
    assert(argos_help_preflight(2, bad_argv, "test", stdout, error_stream) == -1);
    assert(fflush(error_stream) == 0);
    long error_length = ftell(error_stream);
    assert(error_length > 0 && error_length <= 120);
    assert(fclose(error_stream) == 0);

    puts("Generated bounded help contracts: PASS");
    return 0;
}
