#include <stdio.h>
#include "../src/argos_network.h"

int main(void) {
    if (!argos_network_netlink_prefix_event(RTM_NEWADDR)) return 1;
    if (!argos_network_netlink_prefix_event(RTM_DELADDR)) return 2;
    if (argos_network_netlink_prefix_event(RTM_NEWLINK)) return 3;
    if (argos_network_netlink_prefix_event(RTM_DELLINK)) return 4;
    if (argos_network_netlink_prefix_event(NLMSG_NOOP)) return 5;
    puts("netlink prefix event classifier: PASS");
    return 0;
}
