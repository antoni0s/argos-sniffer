#include <stdio.h>
#include "../src/argos_netlink.h"

int main(void) {
    if (!argos_netlink_prefix_event_type(RTM_NEWADDR)) return 1;
    if (!argos_netlink_prefix_event_type(RTM_DELADDR)) return 2;
    if (argos_netlink_prefix_event_type(RTM_NEWLINK)) return 3;
    if (argos_netlink_prefix_event_type(RTM_DELLINK)) return 4;
    if (argos_netlink_prefix_event_type(NLMSG_NOOP)) return 5;
    puts("netlink prefix event classifier: PASS");
    return 0;
}
