#ifndef ARGOS_CAPTURE_H
#define ARGOS_CAPTURE_H

#ifndef ARGOS_PORTABLE_TEST

#include <errno.h>
#include <stdint.h>
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

#include "argos_packet.h"
#include "argos_bpf.h"

#define ARGOS_CAPTURE_MAX_INTERFACES 8
#define ARGOS_CAPTURE_MAX_EVENTS 16
#define ARGOS_CAPTURE_BUFFER_SIZE 65535

typedef struct {
    int fd;
    int ifindex;
    link_type_t type;
    char name[IFNAMSIZ];
    uint64_t total_packets;
    uint64_t total_drops;
} argos_capture_iface_t;

typedef struct {
    int epoll_fd;
    argos_capture_iface_t ifaces[ARGOS_CAPTURE_MAX_INTERFACES];
    int count;
} argos_capture_state_t;

typedef struct {
    ssize_t len;
    uint64_t timestamp_usec;
    uint16_t aux_vlan;
    int aux_vlan_valid;
    int packet_ifindex;
    link_type_t type;
} argos_capture_packet_t;

static inline link_type_t argos_capture_hatype(unsigned short hatype) {
    switch (hatype) {
        case ARPHRD_ETHER:
#ifdef ARPHRD_IEEE802
        case ARPHRD_IEEE802:
#endif
            return LINK_ETHERNET;
        case ARPHRD_NONE:
        case ARPHRD_PPP:
#ifdef ARPHRD_TUNNEL
        case ARPHRD_TUNNEL:
#endif
#ifdef ARPHRD_TUNNEL6
        case ARPHRD_TUNNEL6:
#endif
#ifdef ARPHRD_SIT
        case ARPHRD_SIT:
#endif
#ifdef ARPHRD_IPGRE
        case ARPHRD_IPGRE:
#endif
            return LINK_RAW_IP;
        default:
            return LINK_UNSUPPORTED;
    }
}

static inline int argos_capture_open(argos_capture_state_t *state,
                                     const char *interface_list,
                                     int promiscuous, int userspace_live_filter,
                                     const argos_bpf_config_t *bpf) {
    memset(state, 0, sizeof(*state));
    state->epoll_fd = epoll_create1(0);
    if (state->epoll_fd < 0) return -1;
    char *list = strdup(interface_list);
    if (!list) { errno = ENOMEM; return -1; }

    for (char *token = strtok(list, ","); token && state->count < ARGOS_CAPTURE_MAX_INTERFACES;
         token = strtok(NULL, ",")) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) continue;
        argos_capture_iface_t *iface = &state->ifaces[state->count];
        iface->fd = sock;
        strncpy(iface->name, token, IFNAMSIZ - 1);
        iface->name[IFNAMSIZ - 1] = '\0';

        struct sockaddr_ll sll; memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET; sll.sll_protocol = htons(ETH_P_ALL);
        if (strcasecmp(token, "any") == 0) {
            if (state->count > 0) {
                fprintf(stderr, "warning: 'any' should not be combined with explicit interfaces; skipping '%s'\n", token);
                close(sock); continue;
            }
            iface->ifindex = 0; iface->type = LINK_PER_PACKET; sll.sll_ifindex = 0;
        } else {
            struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, token, IFNAMSIZ - 1);
            if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { close(sock); continue; }
            iface->ifindex = ifr.ifr_ifindex; sll.sll_ifindex = ifr.ifr_ifindex;
            iface->type = ioctl(sock, SIOCGIFHWADDR, &ifr) == 0 ?
                          argos_capture_hatype((unsigned short)ifr.ifr_hwaddr.sa_family) :
                          LINK_UNSUPPORTED;
            if (iface->type == LINK_UNSUPPORTED) {
                fprintf(stderr, "warning: unsupported link-layer type on %s; skipping\n", token);
                close(sock); continue;
            }
        }
        if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) { close(sock); continue; }
        if (iface->type == LINK_ETHERNET && !userspace_live_filter && argos_bpf_attach(sock, bpf) < 0)
            fprintf(stderr, "warning: unable to attach vector-aware AF_PACKET prefilter on %s: %s\n",
                    token, strerror(errno));
        if (promiscuous && iface->type == LINK_ETHERNET) {
            struct packet_mreq mr; memset(&mr, 0, sizeof(mr));
            mr.mr_ifindex = iface->ifindex; mr.mr_type = PACKET_MR_PROMISC;
            setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
        }
        int rcvbuf = 2 * 1024 * 1024, one = 1;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one));
#ifdef SO_TIMESTAMPNS
        setsockopt(sock, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof(one));
#endif
        struct epoll_event ev; memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN; ev.data.ptr = iface;
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
            perror("epoll_ctl"); close(sock); continue;
        }
        state->count++;
    }
    free(list);
    return state->count;
}

static inline int argos_capture_add_external(argos_capture_state_t *state,
                                              int fd, void *tag) {
    struct epoll_event ev; memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN; ev.data.ptr = tag;
    return epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int argos_capture_receive(argos_capture_iface_t *iface,
                                        unsigned char *buffer, size_t capacity,
                                        argos_capture_packet_t *packet) {
    struct sockaddr_ll from; memset(&from, 0, sizeof(from));
    struct iovec iov = {.iov_base = buffer, .iov_len = capacity};
    char control[CMSG_SPACE(sizeof(struct tpacket_auxdata)) + CMSG_SPACE(sizeof(struct timespec))];
    struct msghdr msg; memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from; msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control; msg.msg_controllen = sizeof(control);
    ssize_t len = recvmsg(iface->fd, &msg, MSG_TRUNC);
    if (len <= 0) return 0;
    if ((size_t)len > capacity) len = (ssize_t)capacity;
    memset(packet, 0, sizeof(*packet)); packet->len = len;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
#ifdef SO_TIMESTAMPNS
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMPNS) {
            struct timespec ts; memcpy(&ts, CMSG_DATA(c), sizeof(ts));
            packet->timestamp_usec = (uint64_t)ts.tv_sec * 1000000ULL +
                                     (uint64_t)ts.tv_nsec / 1000ULL;
        }
#endif
        if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA &&
            c->cmsg_len >= CMSG_LEN(sizeof(struct tpacket_auxdata))) {
            struct tpacket_auxdata aux; memcpy(&aux, CMSG_DATA(c), sizeof(aux));
            if (aux.tp_status & TP_STATUS_VLAN_VALID) {
                packet->aux_vlan = (uint16_t)(aux.tp_vlan_tci & 0x0fffU);
                packet->aux_vlan_valid = 1;
            }
        }
    }
    packet->type = iface->type == LINK_PER_PACKET ?
                   argos_capture_hatype(from.sll_hatype) : iface->type;
    packet->packet_ifindex = iface->ifindex > 0 ? iface->ifindex : from.sll_ifindex;
    return 1;
}

static inline void argos_capture_report_stats(argos_capture_state_t *state,
                                               int include_loop, uint64_t max_loop_usec) {
    for (int i = 0; i < state->count; ++i) {
        struct tpacket_stats st; memset(&st, 0, sizeof(st));
        socklen_t sl = sizeof(st);
        if (getsockopt(state->ifaces[i].fd, SOL_PACKET, PACKET_STATISTICS, &st, &sl) == 0) {
            state->ifaces[i].total_packets += st.tp_packets;
            state->ifaces[i].total_drops += st.tp_drops;
            if (st.tp_drops) {
                double pct = st.tp_packets ? 100.0 * (double)st.tp_drops / (double)st.tp_packets : 0.0;
                fprintf(stderr, "argos: %s pkts=%u drops=%u drop=%.2f%% total_pkts=%llu total_drops=%llu",
                        state->ifaces[i].name, st.tp_packets, st.tp_drops, pct,
                        (unsigned long long)state->ifaces[i].total_packets,
                        (unsigned long long)state->ifaces[i].total_drops);
                if (include_loop) fprintf(stderr, " max_loop_us=%llu", (unsigned long long)max_loop_usec);
                fputc('\n', stderr);
            }
        }
    }
}

static inline void argos_capture_close(argos_capture_state_t *state) {
    for (int i = 0; i < state->count; ++i) close(state->ifaces[i].fd);
    if (state->epoll_fd >= 0) close(state->epoll_fd);
    state->epoll_fd = -1;
}

#endif /* !ARGOS_PORTABLE_TEST */
#endif /* ARGOS_CAPTURE_H */
