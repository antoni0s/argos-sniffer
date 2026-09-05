#include <errno.h>
#include <unistd.h>
#define main argos_dynamic_bpf_main
#include "test_dynamic_bpf.c"
#undef main
#include "reference_bpf.h"

static unsigned long compared, executed_old, executed_new;
static unsigned fixture_mask;
static uint16_t fixture_wireguard;

static void compare(const argos_bpf_program_t *now, const legacy_bpf_program_t *old,
                    const unsigned char *frame, size_t length) {
    unsigned a, b;
    uint32_t new_result = run_bpf_code(now->code, now->len, frame, length, &a);
    uint32_t old_result = run_bpf_code(old->code, old->len, frame, length, &b);
    if (new_result != old_result)
        fprintf(stderr, "BPF mismatch: mask=%u wireguard=%u old=%u new=%u length=%zu sport=%u dport=%u\n",
                fixture_mask, fixture_wireguard, old_result, new_result, length,
                length >= 38U ? (unsigned)be16(frame + 34) : 0U,
                length >= 38U ? (unsigned)be16(frame + 36) : 0U);
    expect(new_result == old_result, "legacy filter equivalence");
    if (a > b) {
        fprintf(stderr, "BPF work regression: mask=%u wireguard=%u old=%u new=%u length=%zu\n",
                fixture_mask, fixture_wireguard, b, a, length);
        fprintf(stderr, "old_len=%u new_len=%u sport=%u dport=%u\n", old->len,
                now->len, (unsigned)be16(frame + 34), (unsigned)be16(frame + 36));
    }
    expect(a <= b, "no additional interpreted instructions per packet");
    ++compared; executed_new += a; executed_old += b;
}

static void flags(unsigned mask, argos_bpf_config_t *c, legacy_bpf_config_t *r) {
    memset(r, 0, sizeof(*r));
#define FLAG(name,bit) r->name = (uint8_t)((mask >> bit) & 1U)
    FLAG(syn,0); FLAG(multi,1); FLAG(dhcp,2); FLAG(netbios,3); FLAG(dns,4);
    FLAG(http,5); FLAG(tls,6); FLAG(enterprise,9);
#undef FLAG
    r->l2 = (uint8_t)((mask >> 7) & 1U);
    r->ipv6 = (uint8_t)((mask >> 8) & 1U);
    legacy_bpf_config(mask, 0U, c);
}

static void kernel_check(int sockets[2], const argos_bpf_program_t *p,
                         const unsigned char *frame, size_t n) {
    unsigned char got[2048];
    expect(send(sockets[0], frame, n, 0) == (ssize_t)n, "local fixture send");
    ssize_t count = recv(sockets[1], got, sizeof(got), MSG_DONTWAIT);
    if (run_bpf(p, frame, n))
        expect(count == (ssize_t)n && !memcmp(frame, got, n), "kernel accepts exact frame");
    else expect(count == -1 && (errno == EAGAIN || errno == EWOULDBLOCK), "kernel rejects frame");
}

static void kernel_matrix(void) {
    int sockets[2]; unsigned char frame[2048];
    expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0, "local kernel fixture socketpair");
    for (unsigned mask = 0; mask < 1024U; ++mask) {
        argos_bpf_config_t cfg; legacy_bpf_config_t unused; argos_bpf_program_t p;
        flags(mask, &cfg, &unused); cfg.wireguard_port = 51820;
        expect(argos_bpf_build(&cfg, &p), "kernel matrix build");
        expect(argos_bpf_attach(sockets[1], &cfg) == 0, "kernel verifier accepts every configuration");
        size_t n = udp4(frame, 50000, 53, 16); kernel_check(sockets, &p, frame, n);
        n = udp4(frame, 50000, 3478, 32); put16(frame + 42, 0x0016);
        kernel_check(sockets, &p, frame, n);
        put16(frame + 42, 0x0001); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 50000, 443, 0x10, 0); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 50000, 443, 0x18, 16); kernel_check(sockets, &p, frame, n);
        for (size_t cut = 0; cut < n; ++cut) kernel_check(sockets, &p, frame, cut);
        n = udp4(frame, 50000, 3478, 32); put16(frame + 42, 1);
        for (size_t cut = 0; cut < n; ++cut) kernel_check(sockets, &p, frame, cut);
        n = eth(frame, 0x8100); kernel_check(sockets, &p, frame, n);
        for (size_t cut = 0; cut < 14U; ++cut) kernel_check(sockets, &p, frame, cut);
    }
    for (unsigned selection = 0; selection < 6; ++selection) {
        argos_cli_selection_t cli; argos_dispatch_plan_t plan;
        argos_bpf_config_t cfg; argos_bpf_program_t p;
        argos_cli_selection_init(&cli);
        expect(argos_cli_selection_apply_named(&cli, selection == 1 ? ARGOS_CLI_SELECTOR_PROFILE : ARGOS_CLI_SELECTOR_PROTOCOL,
            selection == 1 ? "full" : selection == 2 ? "telnet" : selection == 4 ? "vnc" : "http-proxy"), "canonical selected SYN engines");
        if (selection == 3 || selection == 5)
            expect(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "telnet"), "combined proxy/Telnet");
        if (selection == 5)
            expect(argos_cli_selection_apply_named(&cli, ARGOS_CLI_SELECTOR_PROTOCOL, "vnc"), "combined VNC");
        argos_dispatch_plan_compile(&plan, &cli);
        argos_bpf_config_compile(&cfg, &plan, 0);
        expect(argos_bpf_build(&cfg, &p), "proxy/full fits instruction budget");
        expect(argos_bpf_attach(sockets[1], &cfg) == 0, "kernel accepts proxy/full filter");
        for (unsigned i = 0; i < sizeof(ARGOS_HTTP_PROXY_TCP_PORTS) / sizeof(ARGOS_HTTP_PROXY_TCP_PORTS[0]); ++i) {
            uint16_t port = ARGOS_HTTP_PROXY_TCP_PORTS[i];
            size_t n = tcp4(frame, 50000, port, 0x02, 0); kernel_check(sockets, &p, frame, n);
            n = tcp4(frame, port, 50000, 0x12, 0); kernel_check(sockets, &p, frame, n);
            n = tcp4(frame, 50000, port, 0x18, 20); kernel_check(sockets, &p, frame, n);
            n = tcp4(frame, 50000, port, 0x10, 0); kernel_check(sockets, &p, frame, n);
        }
        size_t n = tcp4(frame, 50000, 23, 0x02, 0); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 23, 50000, 0x18, 3); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 50000, 5900, 0x02, 0); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 5999, 50000, 0x18, 12); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 50000, 6000, 0x18, 12); kernel_check(sockets, &p, frame, n);
        n = tcp4(frame, 50000, 65000, 0x02, 0); kernel_check(sockets, &p, frame, n);
    }
    /* Prove this exercises the verifier, not merely a successful syscall mock. */
    struct sock_filter invalid[] = {{BPF_JMP | BPF_JA, 0, 0, 5}, {BPF_RET | BPF_K, 0, 0, 0}};
    struct sock_fprog invalid_prog = {2, invalid};
    errno = 0;
    expect(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_FILTER, &invalid_prog, sizeof(invalid_prog)) == -1 &&
           errno == EINVAL, "kernel rejects an out-of-range jump");
    close(sockets[0]); close(sockets[1]);
    puts("Kernel verifier/attach/filter matrix: 1024 legacy + 6 proxy/Telnet/VNC/full configurations PASS (local datagrams, not AF_PACKET throughput)");
}

int main(void) {
    struct { argos_bpf_program_t p; uint64_t canary; } bounded;
    memset(&bounded, 0, sizeof(bounded)); bounded.canary = UINT64_C(0x123456789abcdef0);
    bounded.p.len = ARGOS_BPF_MAX_INSNS - 1U;
    expect(abpf_stmt(&bounded.p, BPF_RET | BPF_K, 0), "last instruction slot writable");
    expect(!abpf_stmt(&bounded.p, BPF_RET | BPF_K, 0) &&
           !abpf_jump(&bounded.p, BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0) &&
           bounded.canary == UINT64_C(0x123456789abcdef0), "capacity failure cannot overrun storage");
    errno = 0;
    expect(argos_bpf_attach(-1, NULL) == -1 && errno == EINVAL, "invalid config reports deterministic errno");
    const uint16_t wg[] = {0, 1, 53, 319, 3478, 51820, 65535};
    const uint16_t ports[] = {0, 22, 53, 67, 80, 88, 111, 123, 137, 161, 179,
        319, 320, 443, 445, 853, 1900, 2049, 3478, 3702, 5353, 5678, 5683,
        8883, 44818, 47808, 51820, 65535,
        514, 515, 2055, 4739, 6343, 9995, 9996, 3128, 8080, 8118, 8888, 23,
        5899, 5900, 5999, 6000};
    unsigned max_len = 0, max_reference = 0;
    unsigned char frame[2048];
    for (unsigned mask = 0; mask < 1024U; ++mask) for (size_t wi = 0; wi < sizeof(wg)/sizeof(wg[0]); ++wi) {
        fixture_mask = mask; fixture_wireguard = wg[wi];
        argos_bpf_config_t cfg; legacy_bpf_config_t refcfg;
        flags(mask, &cfg, &refcfg); cfg.wireguard_port = refcfg.wireguard_port = wg[wi];
        argos_bpf_program_t now; legacy_bpf_program_t old;
        expect(argos_bpf_build(&cfg, &now), "all masks/custom ports fit unchanged capacity");
        expect(legacy_bpf_build(&refcfg, &old), "test-only expanded legacy generator");
        if (now.len > max_len) max_len = now.len;
        if (old.len > max_reference) max_reference = old.len;
        for (size_t pi = 0; pi < sizeof(ports)/sizeof(ports[0]); ++pi) for (unsigned reverse = 0; reverse < 2; ++reverse) {
            uint16_t sport = reverse ? ports[pi] : 50000, dport = reverse ? 50000 : ports[pi];
            size_t n = udp4(frame, sport, dport, 32);
            const uint16_t messages[] = {0x0001, 0x0016, 0x0017, 0x4001};
            for (size_t mi = 0; mi < 4; ++mi) {
                put16(frame + 42, messages[mi]); compare(&now, &old, frame, n);
            }
            for (unsigned control = 0; control < 8U; ++control) {
                n = tcp4(frame, sport, dport, (uint8_t)(0x10 | control), control & 1U ? 0 : 16);
                compare(&now, &old, frame, n);
            }
        }
        for (unsigned proto = 0; proto < 256U; ++proto) {
            size_t n = proto4(frame, (uint8_t)proto);
            compare(&now, &old, frame, n);
        }
        const uint16_t types[] = {0, 100, 1500, 1501, 0x0806, 0x8100, 0x88a8, 0x8864, 0x86dd, 0x88cc, 0x88f7};
        for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); ++i) {
            size_t n = eth(frame, types[i]); compare(&now, &old, frame, n);
        }
        size_t n = tcp4(frame, 443, 50000, 0x18, 16);
        for (size_t cut = 0; cut <= n; ++cut) compare(&now, &old, frame, cut);
    }
    printf("BPF capacity/equivalence: %lu packets PASS; max instructions %u -> %u; executed %lu -> %lu\n",
           compared, max_reference, max_len, executed_old, executed_new);
    kernel_matrix();
    return 0;
}
