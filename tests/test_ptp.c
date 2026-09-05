#include <assert.h>
#include <string.h>

#include "../src/argos_network.h"

int main(void) {
    unsigned char p[42] = {0};
    p[0] = 0x2b; p[1] = 2; p[3] = 34; p[4] = 7;
    p[6] = 0x02; p[7] = 0x01; p[20] = 0x02; p[27] = 0x01;
    p[29] = 3; p[31] = 9; p[32] = 5; p[33] = 0xff;
    argos_network_ptp_result_t r;
    assert(argos_network_ptp_parse(p, 34U, &r));
    assert(r.transport_specific == 2U && r.message_type == 11U);
    assert(r.version == 2U && r.domain_number == 7U && r.flags == 0x0201U);
    assert(r.source_port_number == 3U && r.sequence_id == 9U);
    assert(r.control_field == 5U && r.log_message_interval == -1);
    assert(!strcmp(r.detail,
        "version=2 message=announce domain=7 sequence=9 transport_specific=2 "
        "two_step=1 clock_identity=020000.0000.000001"));
    assert(!argos_network_ptp_parse(NULL, 34U, &r));
    assert(!argos_network_ptp_parse(p, 33U, &r));
    p[1] = 1; assert(!argos_network_ptp_parse(p, 34U, &r));
    p[1] = 2; p[3] = 33; assert(!argos_network_ptp_parse(p, 34U, &r));
    p[3] = 35; assert(!argos_network_ptp_parse(p, 34U, &r));
    p[3] = 42; assert(argos_network_ptp_parse(p, sizeof(p), &r));
    return 0;
}
