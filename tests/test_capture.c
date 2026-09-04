#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/argos_capture.h"

int main(void) {
    assert(argos_capture_hatype(ARPHRD_ETHER) == LINK_ETHERNET);
    assert(argos_capture_hatype(ARPHRD_PPP) == LINK_RAW_IP);
    assert(argos_capture_hatype(0xffffU) == LINK_UNSUPPORTED);

    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) == 0);
    int timestamp = 1;
    assert(setsockopt(fd[1], SOL_SOCKET, SO_TIMESTAMPNS, &timestamp, sizeof(timestamp)) == 0);
    unsigned char sent[64], received[16];
    memset(sent, 0xa5, sizeof(sent));
    assert(send(fd[0], sent, sizeof(sent), 0) == (ssize_t)sizeof(sent));

    argos_capture_iface_t iface;
    memset(&iface, 0, sizeof(iface));
    iface.fd = fd[1]; iface.ifindex = 7; iface.type = LINK_RAW_IP;
    argos_capture_packet_t packet;
    assert(argos_capture_receive(&iface, received, sizeof(received), &packet));
    assert(packet.len == (ssize_t)sizeof(received));
    assert(packet.type == LINK_RAW_IP);
    assert(packet.packet_ifindex == 7);
    assert(packet.timestamp_usec > 0);
    for (size_t i = 0; i < sizeof(received); ++i) assert(received[i] == 0xa5U);

    close(fd[0]); close(fd[1]);
    puts("capture plane fixtures: PASS");
    return 0;
}
