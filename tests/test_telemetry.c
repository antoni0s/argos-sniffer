#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static char captured_record[1400];
static size_t captured_length;

static ssize_t telemetry_test_sendto(int fd, const void *buffer, size_t length,
                                     int flags, const struct sockaddr *address,
                                     socklen_t address_length) {
    (void)fd;
    (void)flags;
    (void)address;
    (void)address_length;
    if (length >= sizeof(captured_record)) return -1;
    memcpy(captured_record, buffer, length);
    captured_record[length] = '\0';
    captured_length = length;
    return (ssize_t)length;
}

#define sendto telemetry_test_sendto
#include "../src/argos_telemetry.h"
#undef sendto

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void) {
    struct sockaddr_storage parsed;
    socklen_t parsed_len = 0;
    check(parse_host_port("127.0.0.1:5514", &parsed, &parsed_len) == 0,
          "IPv4 remote endpoint parses");
    check(parsed.ss_family == AF_INET && parsed_len == sizeof(struct sockaddr_in),
          "IPv4 endpoint family and length");

    ipc_sock = 7;
    use_ipc = 1;
    use_remote = 0;

    emit_telemetry("DNS|02:00:00:00:00:01|192.0.2.10|example.test\n");
    check(captured_length > 0U, "plain telemetry captured");
    check(strcmp(captured_record, "DNS|02:00:00:00:00:01|192.0.2.10|example.test\n") == 0,
          "gateway wire format preserved byte-for-byte");

    opt_sensor_mode = 1;
    snprintf(sensor_name, sizeof(sensor_name), "%s", "span-a");
    argos_telemetry_capture_context("eth1", 100U, 200U, 0, 0U);
    captured_length = 0U;
    emit_telemetry("LACP|02:00:00:00:00:02|-|-|version=1 actor_state=0x01\n");
    check(captured_length > 0U, "sensor telemetry captured");
    check(strcmp(captured_record,
                 "OBS|span-a|eth1|100/200|LACP|02:00:00:00:00:02|-|-|version=1 actor_state=0x01\n") == 0,
          "sensor envelope preserved byte-for-byte");
    const uint16_t ids[] = {0, 1, 100, 200, 4095};
    for (unsigned a = 0; a < 5; ++a) for (unsigned b = 0; b < 5; ++b)
    for (unsigned c = 0; c < 5; ++c) for (int valid = 0; valid < 2; ++valid) {
        unsigned outer = ids[a], inner = ids[b];
        if (valid) {
            if (outer == 0) outer = ids[c];
            else if (ids[c] != outer) { inner = outer; outer = ids[c]; }
        }
        char iface[] = "eth-test", vlan[24], expected[200];
        argos_telemetry_capture_context(iface, ids[a], ids[b], valid, ids[c]);
        iface[0] = 'X'; /* The emitter must not retain borrowed storage. */
        if (inner) snprintf(vlan, sizeof(vlan), "%u/%u", outer, inner);
        else snprintf(vlan, sizeof(vlan), "%u", outer);
        snprintf(expected, sizeof(expected), "OBS|span-a|eth-test|%s|DNS|test\n", vlan);
        emit_telemetry("DNS|test\n");
        check(strcmp(captured_record, expected) == 0, "legacy VLAN projection and owned iface");
    }
    argos_telemetry_capture_context("", 0, 0, 0, 0);
    emit_telemetry("DNS|test\n");
    check(strcmp(captured_record, "OBS|span-a|unknown|0|DNS|test\n") == 0,
          "no stale VLAN/interface context on next packet");
    puts("Telemetry engine fixtures: PASS");
    return 0;
}
