#ifndef ARGOS_TLS_PORTS_H
#define ARGOS_TLS_PORTS_H

#include <stddef.h>
#include <stdint.h>

static const uint16_t ARGOS_TLS_TCP_PORTS[] = {
    443U,   /* HTTPS */
    465U,   /* implicit TLS SMTP / submissions */
    853U,   /* DNS over TLS */
    993U,   /* IMAPS */
    995U,   /* POP3S */
    8443U   /* common alternate HTTPS */
};
#define ARGOS_TLS_TCP_PORT_COUNT (sizeof(ARGOS_TLS_TCP_PORTS) / sizeof(ARGOS_TLS_TCP_PORTS[0]))
#define ARGOS_QUIC_UDP_PORT 443U

static inline int argos_tls_tcp_port(uint16_t port) {
    for (size_t i = 0; i < ARGOS_TLS_TCP_PORT_COUNT; ++i)
        if (ARGOS_TLS_TCP_PORTS[i] == port) return 1;
    return 0;
}

#endif /* ARGOS_TLS_PORTS_H */
