#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "../src/argos_dispatch.h"
#include "../src/argos_enterprise_ports.h"

#define ITERATIONS 12000000U

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int frozen_tcp_port(uint16_t sport, uint16_t dport)
{
    for (size_t i = 0; i < ARGOS_ENTERPRISE_TCP_PORT_COUNT; ++i)
        if (sport == ARGOS_ENTERPRISE_TCP_PORTS[i] ||
            dport == ARGOS_ENTERPRISE_TCP_PORTS[i])
            return 1;
    return 0;
}

static int frozen_udp_port(uint16_t sport, uint16_t dport)
{
    for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i)
        if (sport == ARGOS_ENTERPRISE_UDP_PORTS[i] ||
            dport == ARGOS_ENTERPRISE_UDP_PORTS[i])
            return 1;
    return 0;
}

static uint64_t run_frozen(const uint16_t *ports, size_t count)
{
    volatile unsigned hits = 0;
    uint64_t start = now_ns();
    for (unsigned i = 0; i < ITERATIONS; ++i)
        hits += (unsigned)frozen_tcp_port(50000U, ports[i % count]);
    uint64_t elapsed = now_ns() - start;
    if (hits == 0U) return 0U;
    return elapsed;
}

static uint64_t run_plan(const argos_dispatch_plan_t *plan,
                         const uint16_t *ports, size_t count)
{
    volatile unsigned hits = 0;
    uint64_t start = now_ns();
    for (unsigned i = 0; i < ITERATIONS; ++i)
        hits += argos_dispatch_tcp_port_engine(plan, 50000U, ports[i % count]) <
                ARGOS_PROTOCOL_COUNT;
    uint64_t elapsed = now_ns() - start;
    if (plan->transport_routes != 0U && hits == 0U) return 0U;
    return elapsed;
}

static uint64_t run_frozen_udp(const uint16_t *ports, size_t count)
{
    volatile unsigned hits = 0;
    uint64_t start = now_ns();
    for (unsigned i = 0; i < ITERATIONS; ++i)
        hits += (unsigned)frozen_udp_port(50000U, ports[i % count]);
    uint64_t elapsed = now_ns() - start;
    if (hits == 0U) return 0U;
    return elapsed;
}

static uint64_t run_plan_udp(const argos_dispatch_plan_t *plan,
                             const uint16_t *ports, size_t count)
{
    volatile unsigned hits = 0;
    uint64_t start = now_ns();
    for (unsigned i = 0; i < ITERATIONS; ++i)
        hits += argos_dispatch_udp_port_engine(plan, 50000U, ports[i % count]) <
                ARGOS_PROTOCOL_COUNT;
    uint64_t elapsed = now_ns() - start;
    if (plan->transport_routes != 0U && hits == 0U) return 0U;
    return elapsed;
}

int main(void)
{
    static const uint16_t ports[] = {
        22U, 88U, 111U, 179U, 445U, 502U, 631U, 1433U, 1521U,
        1883U, 2000U, 2049U, 3260U, 3306U, 3389U, 5060U, 5432U,
        9100U, 44818U, 53U, 443U, 8080U, 65535U
    };
    static const uint16_t udp_ports[] = {
        88U, 111U, 123U, 161U, 162U, 389U, 427U, 623U, 1812U,
        1813U, 1985U, 2049U, 3478U, 5060U, 5678U, 5683U, 44818U,
        47808U, 53U, 67U, 443U, 5353U, 65535U
    };
    argos_cli_selection_t cli;
    argos_dispatch_plan_t enabled, disabled;
    argos_cli_selection_init(&cli);
    argos_cli_selection_apply_legacy(
        &cli, ARGOS_LEGACY_CATEGORY_ENTERPRISE, 0);
    argos_dispatch_plan_compile(&enabled, &cli);
    argos_cli_selection_init(&cli);
    argos_dispatch_plan_compile(&disabled, &cli);

    uint64_t frozen = run_frozen(ports, sizeof(ports) / sizeof(ports[0]));
    uint64_t active = run_plan(&enabled, ports, sizeof(ports) / sizeof(ports[0]));
    uint64_t off = run_plan(&disabled, ports, sizeof(ports) / sizeof(ports[0]));
    uint64_t frozen_udp = run_frozen_udp(
        udp_ports, sizeof(udp_ports) / sizeof(udp_ports[0]));
    uint64_t active_udp = run_plan_udp(
        &enabled, udp_ports, sizeof(udp_ports) / sizeof(udp_ports[0]));
    uint64_t off_udp = run_plan_udp(
        &disabled, udp_ports, sizeof(udp_ports) / sizeof(udp_ports[0]));
    if (!frozen || !active || !off || !frozen_udp || !active_udp || !off_udp)
        return 1;
    printf("Transport dispatch benchmark: frozen=%.3f active=%.3f disabled=%.3f ns/call; active/frozen=%.3f disabled/frozen=%.3f\n",
           (double)frozen / ITERATIONS, (double)active / ITERATIONS,
           (double)off / ITERATIONS, (double)active / frozen,
           (double)off / frozen);
    printf("UDP transport dispatch benchmark: frozen=%.3f active=%.3f disabled=%.3f ns/call; active/frozen=%.3f disabled/frozen=%.3f\n",
           (double)frozen_udp / ITERATIONS, (double)active_udp / ITERATIONS,
           (double)off_udp / ITERATIONS, (double)active_udp / frozen_udp,
           (double)off_udp / frozen_udp);
    return 0;
}
