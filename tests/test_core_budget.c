#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdio.h>

#include "../src/argos_capture.h"
#include "../src/argos_config.h"
#include "../src/argos_dispatch.h"
#include "../src/argos_filter.h"

_Static_assert(sizeof(argos_capture_iface_t) == 48U, "capture interface budget changed");
_Static_assert(sizeof(argos_capture_state_t) == 400U, "capture state budget changed");
_Static_assert(sizeof(argos_capture_packet_t) == 32U, "capture result budget changed");
_Static_assert(sizeof(argos_runtime_config_t) == 20U, "runtime config budget changed");
_Static_assert(sizeof(argos_dispatch_plan_t) == 48U, "dispatch plan budget changed");
_Static_assert(sizeof(argos_bpf_config_t) == 12U, "BPF config budget changed");
_Static_assert(sizeof(argos_bpf_program_t) == 2052U, "BPF program budget changed");
_Static_assert(sizeof(argos_filter_program_t) == 2312U, "filter program budget changed");

int main(void) {
    argos_filter_program_t filter = {0};
    assert(argos_filter_compile("192.0.2.0/24", &filter) == 0);
    assert(ARGOS_CAPTURE_MAX_INTERFACES == 8);
    assert(ARGOS_CAPTURE_MAX_EVENTS == 16);
    assert(ARGOS_CAPTURE_BUFFER_SIZE == 65535);
    assert(ARGOS_BPF_MAX_INSNS == 256U);
    assert(ARGOS_FILTER_MAX_TOKENS == 64);
    printf("Core control/scratch budgets: PASS; capture=%zu iface=%zu packet=%zu "
           "config=%zu dispatch=%zu bpf_config=%zu bpf_program=%zu filter_program=%zu\n",
           sizeof(argos_capture_state_t), sizeof(argos_capture_iface_t),
           sizeof(argos_capture_packet_t), sizeof(argos_runtime_config_t),
           sizeof(argos_dispatch_plan_t),
           sizeof(argos_bpf_config_t), sizeof(argos_bpf_program_t),
           sizeof(argos_filter_program_t));
    return 0;
}
