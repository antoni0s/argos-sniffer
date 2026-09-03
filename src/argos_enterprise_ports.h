#ifndef ARGOS_ENTERPRISE_PORTS_H
#define ARGOS_ENTERPRISE_PORTS_H

#include <stddef.h>
#include <stdint.h>

/* Single source of truth shared by the enterprise parser admission checks and
 * the vector-aware kernel BPF builder. Keep these lists limited to protocols
 * for which Argos has a bounded parser. */
static const uint16_t ARGOS_ENTERPRISE_TCP_PORTS[] = {
    22, 88, 111, 179, 445, 502, 631, 1433, 1521, 2000, 2049,
    3260, 3306, 3389, 5060, 5432, 9100, 44818
};
static const uint16_t ARGOS_ENTERPRISE_UDP_PORTS[] = {
    88, 111, 161, 162, 389, 427, 623, 1812, 1813, 1985, 2049, 5060, 5678, 47808, 44818
};
#define ARGOS_ENTERPRISE_TCP_PORT_COUNT (sizeof(ARGOS_ENTERPRISE_TCP_PORTS) / sizeof(ARGOS_ENTERPRISE_TCP_PORTS[0]))
#define ARGOS_ENTERPRISE_UDP_PORT_COUNT (sizeof(ARGOS_ENTERPRISE_UDP_PORTS) / sizeof(ARGOS_ENTERPRISE_UDP_PORTS[0]))

#endif /* ARGOS_ENTERPRISE_PORTS_H */
