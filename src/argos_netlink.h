#ifndef ARGOS_NETLINK_H
#define ARGOS_NETLINK_H

#include <stdint.h>
#include <linux/rtnetlink.h>

/* Address changes are the only route-netlink notifications that invalidate
 * the connected-prefix snapshot used by Argos classification. Link-state
 * churn by itself does not require an expensive getifaddrs() rescan. */
static inline int argos_netlink_prefix_event_type(uint16_t type) {
    return type == RTM_NEWADDR || type == RTM_DELADDR;
}

#endif /* ARGOS_NETLINK_H */
