#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BENCH_PACKETS 120000U
#define BENCH_PAYLOAD 256U
#define BENCH_MAX_BATCH 32U
#define CTRL_BYTES 128U

static double elapsed_s(const struct timespec *a, const struct timespec *b) {
    return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1000000000.0;
}

static int set_socket_buffers(int fd) {
    int bytes = 4 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) < 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) < 0) return -1;
#ifdef SO_TIMESTAMPNS
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof(one)) < 0) return -1;
#endif
    return 0;
}

static void sender_loop(int fd) {
    unsigned char payload[BENCH_PAYLOAD];
    memset(payload, 0xa5, sizeof(payload));
    for (uint32_t i = 0; i < BENCH_PACKETS; ++i) {
        ssize_t n;
        do { n = send(fd, payload, sizeof(payload), 0); } while (n < 0 && errno == EINTR);
        if (n != (ssize_t)sizeof(payload)) _exit(2);
    }
    _exit(0);
}

static int start_pair(int sv[2], pid_t *child) {
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    if (set_socket_buffers(sv[0]) < 0 || set_socket_buffers(sv[1]) < 0) {
        close(sv[0]); close(sv[1]); return -1;
    }
    pid_t pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); return -1; }
    if (pid == 0) {
        close(sv[0]);
        sender_loop(sv[1]);
    }
    close(sv[1]);
    *child = pid;
    return 0;
}

static int finish_pair(int fd, pid_t child) {
    close(fd);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int bench_recvmsg(double *seconds, uint64_t *syscalls) {
    int sv[2]; pid_t child;
    if (start_pair(sv, &child) < 0) return -1;

    unsigned char payload[BENCH_PAYLOAD];
    unsigned char control[CTRL_BYTES];
    struct iovec iov;
    struct msghdr msg;
    struct timespec t0, t1;
    uint32_t received = 0;
    uint64_t calls = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (received < BENCH_PACKETS) {
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = payload;
        iov.iov_len = sizeof(payload);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        ssize_t n;
        do { n = recvmsg(sv[0], &msg, MSG_TRUNC); } while (n < 0 && errno == EINTR);
        if (n < 0) { kill(child, SIGKILL); finish_pair(sv[0], child); return -1; }
        ++received;
        ++calls;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (finish_pair(sv[0], child) < 0) return -1;
    *seconds = elapsed_s(&t0, &t1);
    *syscalls = calls;
    return 0;
}

static int bench_recvmmsg(unsigned batch, double *seconds, uint64_t *syscalls) {
    if (batch == 0U || batch > BENCH_MAX_BATCH) return -1;
    int sv[2]; pid_t child;
    if (start_pair(sv, &child) < 0) return -1;

    struct mmsghdr msgs[BENCH_MAX_BATCH];
    struct iovec iov[BENCH_MAX_BATCH];
    unsigned char payload[BENCH_MAX_BATCH][BENCH_PAYLOAD];
    unsigned char control[BENCH_MAX_BATCH][CTRL_BYTES];
    struct timespec t0, t1;
    uint32_t received = 0;
    uint64_t calls = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (received < BENCH_PACKETS) {
        unsigned want = batch;
        if (BENCH_PACKETS - received < want) want = BENCH_PACKETS - received;
        memset(msgs, 0, sizeof(msgs));
        for (unsigned i = 0; i < want; ++i) {
            iov[i].iov_base = payload[i];
            iov[i].iov_len = sizeof(payload[i]);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = control[i];
            msgs[i].msg_hdr.msg_controllen = sizeof(control[i]);
        }
        int n;
        do { n = recvmmsg(sv[0], msgs, want, MSG_TRUNC, NULL); } while (n < 0 && errno == EINTR);
        if (n <= 0) { kill(child, SIGKILL); finish_pair(sv[0], child); return -1; }
        received += (uint32_t)n;
        ++calls;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (finish_pair(sv[0], child) < 0) return -1;
    *seconds = elapsed_s(&t0, &t1);
    *syscalls = calls;
    return 0;
}

static void print_result(const char *name, unsigned run, double seconds, uint64_t calls) {
    double pps = (double)BENCH_PACKETS / seconds;
    double ns_per_packet = seconds * 1000000000.0 / (double)BENCH_PACKETS;
    double packets_per_call = (double)BENCH_PACKETS / (double)calls;
    printf("%s,%u,%u,%.6f,%.0f,%.1f,%" PRIu64 ",%.2f\n",
           name, run, BENCH_PACKETS, seconds, pps, ns_per_packet, calls, packets_per_call);
}

int main(void) {
    static const unsigned batches[] = {4U, 8U, 16U, 32U};
    puts("method,run,packets,seconds,packets_per_sec,ns_per_packet,recv_syscalls,packets_per_syscall");
    for (unsigned run = 1; run <= 5; ++run) {
        double seconds = 0.0;
        uint64_t calls = 0;
        if (bench_recvmsg(&seconds, &calls) < 0) { perror("recvmsg benchmark"); return 1; }
        print_result("recvmsg", run, seconds, calls);

        for (size_t i = 0; i < sizeof(batches)/sizeof(batches[0]); ++i) {
            unsigned batch = batches[i];
            char name[32];
            if (bench_recvmmsg(batch, &seconds, &calls) < 0) { perror("recvmmsg benchmark"); return 1; }
            snprintf(name, sizeof(name), "recvmmsg%u", batch);
            print_result(name, run, seconds, calls);
        }
    }
    return 0;
}
