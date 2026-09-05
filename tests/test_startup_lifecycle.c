#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Real CLI/main and resource owners, fake kernel/resolver: no privileges,
 * interfaces, DNS queries or telemetry traffic. One clean process per case. */
enum { NONE, UNIX_FAIL, UDP_FAIL, RESOLVE_FAIL, EPOLL_FAIL, LIST_FAIL,
       PACKET_FAIL, PACKET_BIND_FAIL, PACKET_CTL_FAIL, NETLINK_FAIL,
       NETLINK_BIND_FAIL, NETLINK_CTL_FAIL, SYN_FAIL, DNS_FAIL,
       UNIX_REPLACE_FAIL, UDP_REPLACE_FAIL, RESOLVE_REPLACE_FAIL };
static int fault, next_fd = 10, live_fd[64], domains[64], allocations, live_heap;
static int capture_attempts, waits;
static int unix_calls, udp_calls, resolve_calls;
static int dedup_expected = -1, dedup_fail;
static int network_expected = -1, allocation_fail_at;
static void check_dedup_packet(void);
static void check_network_packet(void);
static void *owned[8];
static int fake_close(int fd) {
    assert(fd >= 0 && fd < 64 && live_fd[fd]);
    live_fd[fd] = 0; return 0;
}
static int new_fd(int domain) {
    assert(next_fd < 64); live_fd[next_fd] = 1; domains[next_fd] = domain;
    return next_fd++;
}
static int fake_socket(int domain, int type, int protocol) {
    (void)type; (void)protocol;
    if (domain == AF_UNIX) ++unix_calls;
    if (domain == AF_INET) ++udp_calls;
    if ((fault == UNIX_REPLACE_FAIL && domain == AF_UNIX && unix_calls == 2) ||
        (fault == UDP_REPLACE_FAIL && domain == AF_INET && udp_calls == 2)) {
        errno = EMFILE; return -1;
    }
    if ((domain == AF_UNIX && fault == UNIX_FAIL) ||
        (domain == AF_INET && fault == UDP_FAIL) ||
        (domain == AF_PACKET && fault == PACKET_FAIL) ||
        (domain == AF_NETLINK && fault == NETLINK_FAIL)) { errno = EMFILE; return -1; }
    assert(domain == AF_UNIX || domain == AF_INET || domain == AF_PACKET || domain == AF_NETLINK);
    return new_fd(domain);
}
static int fake_epoll(int flags) {
    (void)flags; ++capture_attempts;
    if (fault == EPOLL_FAIL) { errno = EMFILE; return -1; }
    return new_fd(0);
}
static int fake_bind(int fd, const struct sockaddr *addr, socklen_t n) {
    (void)addr; (void)n; assert(live_fd[fd]);
    if ((domains[fd] == AF_PACKET && fault == PACKET_BIND_FAIL) ||
        (domains[fd] == AF_NETLINK && fault == NETLINK_BIND_FAIL)) { errno = EINVAL; return -1; }
    return 0;
}
static int fake_ctl(int ep, int op, int fd, struct epoll_event *ev) {
    assert(live_fd[ep] && live_fd[fd] && op == EPOLL_CTL_ADD && ev);
    if ((domains[fd] == AF_PACKET && fault == PACKET_CTL_FAIL) ||
        (domains[fd] == AF_NETLINK && fault == NETLINK_CTL_FAIL)) { errno = EINVAL; return -1; }
    return 0;
}
static int fake_wait(int ep, struct epoll_event *ev, int n, int timeout) {
    (void)ev; (void)n; (void)timeout; assert(live_fd[ep]); ++waits;
    check_dedup_packet();
    check_network_packet();
    assert(raise(SIGTERM) == 0); errno = EINTR; return -1;
}
static int fake_setopt(int fd, int level, int opt, const void *p, socklen_t n) {
    (void)level; (void)opt; (void)p; (void)n; assert(live_fd[fd]); return 0;
}
static int fake_getopt(int fd, int level, int opt, void *p, socklen_t *n) {
    (void)level; (void)opt; assert(live_fd[fd]); memset(p, 0, *n); return 0;
}
static int fake_ifaddrs(struct ifaddrs **p) { *p = NULL; errno = EIO; return -1; }
static char *fake_strdup(const char *s) { return fault == LIST_FAIL ? NULL : strdup(s); }
static int fake_resolve(const char *host, const char *port,
                        const struct addrinfo *hints, struct addrinfo **out) {
    (void)host; (void)port; (void)hints;
    static struct sockaddr_in addr;
    static struct addrinfo result;
    ++resolve_calls;
    if (fault == RESOLVE_FAIL || (fault == RESOLVE_REPLACE_FAIL && resolve_calls == 2)) {
        *out = NULL; return EAI_FAIL;
    }
    memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET;
    memset(&result, 0, sizeof(result)); result.ai_addr = (struct sockaddr *)&addr;
    result.ai_addrlen = sizeof(addr); *out = &result; return 0;
}
static void fake_freeaddr(struct addrinfo *p) { (void)p; }
static void *fake_calloc(size_t n, size_t s) {
    ++allocations;
    if ((dedup_fail && n == 2048U && s == 24U) || /* frozen dedup owner */
        allocations == allocation_fail_at) return NULL;
    if ((fault == SYN_FAIL && allocations == 1) ||
        (fault == DNS_FAIL && allocations == 2)) return NULL;
    void *p = calloc(n, s); assert(p);
    for (unsigned i = 0; i < 8; ++i) if (!owned[i]) {
        owned[i] = p; ++live_heap; return p;
    }
    abort();
}
static void fake_free(void *p) {
    for (unsigned i = 0; i < 8; ++i) if (p && owned[i] == p) {
        owned[i] = NULL; --live_heap; break;
    }
    free(p); /* Includes the real strdup allocation. ASan checks double frees. */
}
#define ARGOS_QUIC_STUB
#define main argos_program_main
#define socket fake_socket
#define close fake_close
#define epoll_create1 fake_epoll
#define epoll_ctl fake_ctl
#define epoll_wait fake_wait
#define bind fake_bind
#define setsockopt fake_setopt
#define getsockopt fake_getopt
#define getifaddrs fake_ifaddrs
#define strdup fake_strdup
#define getaddrinfo fake_resolve
#define freeaddrinfo fake_freeaddr
#define calloc fake_calloc
#define free fake_free
#include "../src/argos-sniffer.c"
#undef main
#undef free

static void check_dedup_packet(void) {
    if (dedup_expected < 0) return;
    assert((runtime_state.dedup.table != NULL) == (dedup_expected && !dedup_fail));
    int before = allocations;
    assert(!dedup_should_suppress_for("aa", "TLS", "x", 1, 35, 1));
    assert(dedup_should_suppress_for("aa", "TLS", "x", 1, 35, 1) ==
           (dedup_expected && !dedup_fail));
    assert(allocations == before);
}

static void check_network_packet(void) {
    if (network_expected < 0) return;
    assert((network_state.owner4 != NULL) == ((network_expected & 1) != 0));
    assert((network_state.owner6 != NULL) == ((network_expected & 2) != 0));
    const uint8_t mac[6] = {0x02,1,2,3,4,5};
    uint32_t ip4 = htonl(0x0a000001U);
    struct in6_addr ip6 = IN6ADDR_LOOPBACK_INIT;
    int before = allocations;
    argos_network_owner4_note(&network_state, ip4, mac);
    argos_network_owner6_note(&network_state, &ip6, mac);
    assert(allocations == before); /* Missing/failed families never retry here. */
}

static void dedup_policy(void) {
    const struct { int need, owner_allocations; const char *args[8]; } cases[] = {
        {1, 0, {"-i", "any"}}, {1, 2, {"any"}}, {1, 2, {"-a"}}, {0, 2, {"-A"}},
        {1, 2, {"-A", "-s"}}, {0, 2, {"-s", "-A"}}, {0, 0, {"-s", "-S"}},
        {1, 0, {"-S", "-s"}}, {0, 2, {"-a", "-f", "0"}},
        {1, 2, {"-a", "-f", "0", "-f", "35"}},
        {1, 0, {"--enterprise"}}, {0, 0, {"--enterprise-verbose"}},
        {1, 0, {"--enterprise-verbose", "-t"}},
        {0, 0, {"--enterprise", "--enterprise-verbose"}},
        {1, 0, {"--enterprise-verbose", "--enterprise"}},
        {0, 0, {"-z", "192.0.2.0/24", "-a", "--enterprise"}},
        {1, 2, {"-Z", "192.0.2.0/24", "-a"}}, {1, 0, {"-W"}}, {1, 0, {"-v"}},
        {1, 0, {"--protocol", "dns"}}, {0, 0, {"--protocol", "DNS"}},
        {1, 0, {"--protocol", "ptp"}},
        {1, 0, {"--profile", "core"}},
        {1, 0, {"--group", "identity"}},
        {1, 1, {"--super-group", "application"}},
        {1, 1, {"--protocol", "vnc"}},
        {0, 0, {"--protocol", "dns", "--no-rate-limit", "all"}},
        {1, 0, {"--no-rate-limit", "all", "--protocol", "dns"}}
    };
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
    for (int fail = 0; fail <= cases[i].need; ++fail) {
        fflush(NULL); pid_t child = fork(); assert(child >= 0);
        if (!child) {
            dedup_expected = cases[i].need; dedup_fail = fail;
            char *argv[10] = {"argos"}; int argc = 1;
            for (unsigned j = 0; cases[i].args[j]; ++j) argv[argc++] = (char *)cases[i].args[j];
            assert(argos_program_main(argc, argv) == 0);
            assert(allocations == cases[i].need + cases[i].owner_allocations &&
                   !live_heap && waits == 1);
            assert(!runtime_state.dedup.table);
            for (unsigned j = 0; j < 64; ++j) assert(!live_fd[j]);
            exit(0);
        }
        int status; assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}

static void vnc_context_failure(void) {
    fflush(NULL); pid_t child = fork(); assert(child >= 0);
    if (!child) {
        allocation_fail_at = 1;
        char *argv[] = {"argos", "--protocol", "vnc", NULL};
        assert(argos_program_main(3, argv) == 1);
        assert(allocations == 1 && !live_heap && !capture_attempts && !waits);
        assert(!runtime_state.application.context);
        exit(0);
    }
    int status; assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void network_policy(void) {
    const struct { int dedup, requested, ready, fail_at; const char *args[5]; } cases[] = {
        {0, 1, 1, 0, {"-L"}},
        {1, 1, 1, 0, {"-l"}},
        {0, 3, 3, 0, {"-L", "-V"}},
        {0, 3, 3, 0, {"-A"}},
        {1, 3, 3, 0, {"-a"}},
        {1, 0, 0, 0, {"-v"}},
        {1, 0, 0, 0, {"--enterprise"}},
        {0, 0, 0, 0, {"-z", "192.0.2.0/24", "-a"}},
        {0, 3, 2, 1, {"-L", "-V"}}, /* IPv4 allocation fails. */
        {0, 3, 1, 2, {"-L", "-V"}}  /* IPv6 allocation fails. */
    };
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        fflush(NULL); pid_t child = fork(); assert(child >= 0);
        if (!child) {
            dedup_expected = cases[i].dedup;
            network_expected = cases[i].ready;
            allocation_fail_at = cases[i].fail_at;
            char *argv[8] = {"argos"}; int argc = 1;
            for (unsigned j = 0; cases[i].args[j]; ++j)
                argv[argc++] = (char *)cases[i].args[j];
            assert(argos_program_main(argc, argv) == 0);
            int owner_allocations = !!(cases[i].requested & 1) + !!(cases[i].requested & 2);
            assert(allocations == cases[i].dedup + owner_allocations);
            assert(!live_heap && !network_state.owner4 && !network_state.owner6);
            for (unsigned j = 0; j < 64; ++j) assert(!live_fd[j]);
            exit(0);
        }
        int status; assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}

static void check_case(int f, const char *option, const char *value,
                       int expected, int capture, int loop, int fd_zero) {
    fflush(NULL);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        fault = f; if (fd_zero) next_fd = 0;
        char *argv[16] = {"argos", "-o", "/unused", "-u", "127.0.0.1:9", "-E"};
        int metrics = !option || strcmp(option, "-S");
        if (!metrics) argv[5] = "-S";
        int argc = 6;
        if (option) { argv[argc++] = (char *)option; if (value) argv[argc++] = (char *)value; }
        argv[argc] = NULL;
        assert(argos_program_main(argc, argv) == expected);
        assert(capture_attempts == capture && waits == loop && !live_heap);
        if (!metrics) assert(!allocations);
        for (unsigned i = 0; i < 64; ++i) assert(!live_fd[i]);
        argos_telemetry_close(); /* Closed sinks must not be closed twice. */
        assert(ipc_sock == -1 && remote_sock == -1 && !use_ipc && !use_remote && !udp_only);
        assert(!runtime_state.syn_track && !runtime_state.dns_track);
        exit(0);
    }
    int status; assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void informational_paths(void) {
    const struct { int expected; const char *args[5]; } cases[] = {
        {0, {"-o", "/unused", "--help"}},
        {0, {"-u", "127.0.0.1:9", "--version"}},
        {1, {"-o", "/unused", "--help-protocols"}}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fflush(NULL);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            char *argv[8] = {"argos"}; int argc = 1;
            for (unsigned j = 0; cases[i].args[j]; ++j)
                argv[argc++] = (char *)cases[i].args[j];
            assert(argos_program_main(argc, argv) == cases[i].expected);
            assert(!capture_attempts && !unix_calls && !udp_calls && !resolve_calls);
            assert(!allocations && !live_heap);
            for (unsigned j = 0; j < 64; ++j) assert(!live_fd[j]);
            exit(0);
        }
        int status; assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
}
int main(void) {
    informational_paths();
    dedup_policy();
    vnc_context_failure();
    network_policy();
    const char *invalid[][2] = {
        {"--sensor-name", "bad|name"}, {"--inside", "invalid"},
        {"--identity=bad", NULL}, {"--wireguard-port", "0"},
        {"-R", "invalid"}, {"-r", "invalid"}, {"-x", "("},
        {"-z", "("}, {"-Z", "("}, {"-c", "-1"}, {"-f", "-1"},
        {"--unknown", NULL}, {"eth0", "extra"}, {"--sensor-name", "valid"},
        {"--sensor", NULL}, {"--sensor", "--sensor-name=valid"},
        {"--wireguard-port", "51820"},
        {"--profile", "invalid"}, {"--super-group", "invalid"},
        {"--group", "invalid"}, {"--protocol", "invalid"},
        {"--protocol", "Rip"}, {"--protocol", "llmnr"},
        {"--no-rate-limit", "invalid"},
        {"-u", "invalid"}, {"-U", "invalid"}
    };
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        check_case(NONE, invalid[i][0], invalid[i][1], 1, 0, 0, 0);
    for (int f = UNIX_FAIL; f <= DNS_FAIL; ++f) {
        int reached = f >= EPOLL_FAIL && f <= NETLINK_CTL_FAIL;
        int loop = f >= NETLINK_FAIL && f <= NETLINK_CTL_FAIL;
        check_case(f, NULL, NULL, !loop, reached, loop, 0);
    }
    check_case(NONE, "-o", "/replacement", 0, 1, 1, 0);
    check_case(NONE, "-u", "127.0.0.1:10", 0, 1, 1, 0);
    check_case(NONE, "-U", "127.0.0.1:10", 0, 1, 1, 0);
    check_case(UNIX_REPLACE_FAIL, "-o", "/replacement", 1, 0, 0, 0);
    check_case(UDP_REPLACE_FAIL, "-u", "127.0.0.1:10", 1, 0, 0, 0);
    check_case(UDP_REPLACE_FAIL, "-U", "127.0.0.1:10", 1, 0, 0, 0);
    check_case(RESOLVE_REPLACE_FAIL, "-u", "fixture.invalid:9", 1, 0, 0, 0);
    check_case(RESOLVE_REPLACE_FAIL, "-U", "fixture.invalid:9", 1, 0, 0, 0);
    check_case(NONE, "-S", NULL, 0, 1, 1, 0);
    check_case(NONE, NULL, NULL, 0, 1, 1, 1); /* An owned fd 0 is valid. */
    puts("Process startup failures/repeated sinks/normal shutdown: PASS");
    return 0;
}
