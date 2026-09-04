#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
static int fake_opt(int fd, int level, int opt, const void *p, socklen_t n);
#define setsockopt fake_opt
#include "../src/argos_bpf.h"
#undef setsockopt

static int fault, closes[128], next_fd, recv_mode;
static int filter_calls, filter_failure;
static unsigned short recv_hatype = ARPHRD_ETHER;
static int fake_close(int fd) { assert(fd >= 0 && fd < 128); ++closes[fd]; return 0; }
static int fake_epoll(int flags) { (void)flags; if (fault == 1) { errno = EMFILE; return -1; } return 90; }
static char *fake_strdup(const char *s) { return fault == 2 ? NULL : strdup(s); }
static int fake_socket(int domain, int type, int protocol) {
    assert(domain == AF_PACKET && type == SOCK_RAW && protocol == htons(ETH_P_ALL));
    return fault == 3 ? -1 : next_fd++;
}
static int fake_ioctl(int fd, unsigned long request, ...) {
    (void)fd; va_list ap; va_start(ap, request); struct ifreq *p = va_arg(ap, struct ifreq *); va_end(ap);
    if (request == SIOCGIFINDEX) { if (fault == 4) return -1; p->ifr_ifindex = 7; }
    else { assert(request == SIOCGIFHWADDR); if (fault == 5) return -1;
           p->ifr_hwaddr.sa_family = fault == 6 ? 0xffff : fault == 11 ? ARPHRD_PPP : ARPHRD_ETHER; }
    return 0;
}
static int fake_bind(int fd, const struct sockaddr *addr, socklen_t n) {
    (void)addr; assert(n == sizeof(struct sockaddr_ll));
    return fault == 7 || (fault == 10 && fd == 21) ? -1 : 0;
}
static int fake_ctl(int ep, int op, int fd, struct epoll_event *e) {
    (void)fd; assert(ep == 90 && op == EPOLL_CTL_ADD && e->events == EPOLLIN);
    return fault == 8 ? -1 : 0;
}
static int fake_opt(int fd, int level, int opt, const void *p, socklen_t n) {
    (void)fd;
    if (level == SOL_SOCKET && opt == SO_ATTACH_FILTER) {
        ++filter_calls;
        assert(n == sizeof(struct sock_fprog));
        const struct sock_fprog *prog = p;
        assert(prog->len > 0 && prog->len <= ARGOS_BPF_MAX_INSNS);
        if (filter_failure) { errno = EPERM; return -1; }
    }
    return fault == 9 ? -1 : 0;
}
static ssize_t fake_recv(int fd, struct msghdr *m, int flags) {
    (void)fd; assert(flags == MSG_TRUNC);
    if (recv_mode == 1) { errno = EINTR; return -1; }
    if (recv_mode == 2) { errno = EAGAIN; return -1; }
    if (recv_mode == 3) return 0;
    struct sockaddr_ll *from = m->msg_name;
    from->sll_ifindex = 12; from->sll_hatype = recv_mode == 4 ? 0xffff : recv_hatype;
    memset(m->msg_iov[0].iov_base, 0x45, m->msg_iov[0].iov_len);
    memset(m->msg_control, 0, m->msg_controllen);
    struct cmsghdr *c = m->msg_control;
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SO_TIMESTAMPNS;
    c->cmsg_len = CMSG_LEN(sizeof(struct timespec));
    struct timespec ts = {.tv_sec = 123, .tv_nsec = 456789000};
    memcpy(CMSG_DATA(c), &ts, sizeof(ts));
    if (recv_mode == 5) { c->cmsg_len = CMSG_LEN(0); m->msg_controllen = CMSG_LEN(0); }
    else if (recv_mode == 6) { c->cmsg_len = m->msg_controllen + 1; }
    else {
        c = (struct cmsghdr *)((unsigned char *)m->msg_control + CMSG_SPACE(sizeof(ts)));
        c->cmsg_level = SOL_PACKET; c->cmsg_type = PACKET_AUXDATA;
        c->cmsg_len = CMSG_LEN(sizeof(struct tpacket_auxdata));
        struct tpacket_auxdata a = {0}; a.tp_status = TP_STATUS_VLAN_VALID;
        a.tp_vlan_tci = recv_mode == 7 ? 0 : 0xa123;
        if (recv_mode == 8) a.tp_status = 0;
        memcpy(CMSG_DATA(c), &a, sizeof(a));
        if (recv_mode == 9) { c->cmsg_len = CMSG_LEN(1); m->msg_flags |= MSG_CTRUNC;
            m->msg_controllen = CMSG_SPACE(sizeof(ts)) + CMSG_LEN(1); }
        if (recv_mode == 10) m->msg_controllen = 0;
    }
    return 64;
}

#define close fake_close
#define epoll_create1 fake_epoll
#define strdup fake_strdup
#define socket fake_socket
#define ioctl fake_ioctl
#define bind fake_bind
#define epoll_ctl fake_ctl
#define setsockopt fake_opt
#define recvmsg fake_recv
#include "../src/argos_capture.h"
#undef close
#undef epoll_create1
#undef strdup
#undef socket
#undef ioctl
#undef bind
#undef epoll_ctl
#undef setsockopt
#undef recvmsg

static void lifecycle(void) {
    argos_bpf_config_t bpf = {0};
    for (fault = 0; fault <= 10; ++fault) {
        memset(closes, 0, sizeof(closes)); next_fd = 20;
        argos_capture_state_t s;
        int n = argos_capture_open(&s, "eth0,eth1", 1, 1, &bpf);
        assert(n == (fault == 0 || fault == 9 ? 2 : fault == 10 ? 1 : fault < 3 ? -1 : 0));
        if (fault == 2) { assert(errno == ENOMEM); assert(s.epoll_fd == -1 && closes[90] == 1); }
        argos_capture_close(&s);
        int saved[128]; memcpy(saved, closes, sizeof(saved));
        argos_capture_close(&s);
        assert(memcmp(saved, closes, sizeof(saved)) == 0);
        assert(s.count == 0 && s.epoll_fd == -1);
        assert(closes[90] == (fault == 1 ? 0 : 1));
        for (int fd = 20; fd < next_fd; ++fd) assert(closes[fd] == 1);
    }
    fault = 0; next_fd = 20; memset(closes, 0, sizeof(closes));
    argos_capture_state_t s;
    assert(argos_capture_open(&s, "a,b,c,d,e,f,g,h,i", 0, 1, &bpf) == ARGOS_CAPTURE_MAX_INTERFACES);
    argos_capture_close(&s); assert(next_fd == 28);
    for (int fd = 20; fd < next_fd; ++fd) assert(closes[fd] == 1);
}
static void metadata(void) {
    unsigned char buffer[16]; argos_capture_packet_t p;
    argos_capture_iface_t iface = {.fd = 20, .ifindex = 0, .type = LINK_PER_PACKET};
    for (recv_mode = 0; recv_mode <= 10; ++recv_mode) {
        int ok = argos_capture_receive(&iface, buffer, sizeof(buffer), &p);
        if (recv_mode >= 1 && recv_mode <= 3) { assert(!ok); continue; }
        assert(ok && p.len == 16 && p.packet_ifindex == 12);
        assert(p.type == (recv_mode == 4 ? LINK_UNSUPPORTED : LINK_ETHERNET));
        assert(p.timestamp_usec == (recv_mode == 5 || recv_mode == 6 || recv_mode == 10 ? 0 : 123456789));
        int valid = recv_mode != 5 && recv_mode != 6 && recv_mode != 8 && recv_mode != 9 && recv_mode != 10;
        assert(p.aux_vlan_valid == valid);
        if (valid) assert(p.aux_vlan == (recv_mode == 7 ? 0 : 0x123));
    }
    recv_mode = 0; iface.ifindex = 7; iface.type = LINK_RAW_IP;
    assert(argos_capture_receive(&iface, buffer, sizeof(buffer), &p));
    assert(p.type == LINK_RAW_IP && p.packet_ifindex == 7);
}
static void link_ownership(void) {
    const unsigned short types[] = {ARPHRD_ETHER, ARPHRD_IEEE802, ARPHRD_NONE,
        ARPHRD_PPP, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, ARPHRD_SIT, ARPHRD_IPGRE,
        ARPHRD_LOOPBACK, ARPHRD_IEEE802154, 0xffff};
    const link_type_t fixed[] = {LINK_PER_PACKET, LINK_ETHERNET, LINK_RAW_IP};
    unsigned char buffer[16]; argos_capture_packet_t p;
    recv_mode = 0;
    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); ++i)
    for (size_t j = 0; j < sizeof(fixed)/sizeof(fixed[0]); ++j) {
        recv_hatype = types[i];
        argos_capture_iface_t iface = {.fd = 20, .ifindex = j ? 7 : 0, .type = fixed[j]};
        assert(argos_capture_receive(&iface, buffer, sizeof(buffer), &p));
        assert(p.type == (j ? fixed[j] : argos_capture_hatype(types[i])));
        assert(p.packet_ifindex == (j ? 7 : 12));
        assert(p.type != LINK_COOKED && p.type != LINK_PER_PACKET);
    }
    recv_hatype = ARPHRD_ETHER;
}

static void filter_lifecycle(void) {
    argos_bpf_config_t bpf = {0};
    bpf.syn = bpf.multi = bpf.dhcp = bpf.netbios = bpf.dns = 1;
    bpf.http = bpf.tls = bpf.l2 = bpf.ipv6 = bpf.enterprise = 1;
    bpf.wireguard_port = 51820;
    for (int mode = 0; mode < 6; ++mode) {
        fault = mode == 4 ? 11 : 0; filter_calls = 0;
        filter_failure = mode == 1;
        next_fd = 20; memset(closes, 0, sizeof(closes));
        argos_capture_state_t s;
        /* Existing policy: syscall/build failure warns but retains capture.
         * any/raw/live inspector intentionally bypass Ethernet-only BPF. */
        assert(argos_capture_open(&s, mode == 3 ? "any" : "eth0", 0,
                                  mode == 2, mode == 5 ? NULL : &bpf) == 1);
        assert(filter_calls == (mode < 2 ? 1 : 0));
        if (mode == 5) assert(errno == EINVAL);
        argos_capture_close(&s); argos_capture_close(&s);
        assert(closes[20] == 1 && closes[90] == 1);
    }
    filter_failure = 0; fault = 0;
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc == 1) metadata();
    link_ownership(); lifecycle(); filter_lifecycle();
    puts("Capture metadata/lifecycle contracts: PASS");
    return 0;
}
