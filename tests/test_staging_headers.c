#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/argos_ah.h"
#include "../src/argos_airplay.h"
#include "../src/argos_cast.h"
#include "../src/argos_dlna.h"
#include "../src/argos_dnp3.h"
#include "../src/argos_esp.h"
#include "../src/argos_ftp.h"
#include "../src/argos_http_proxy.h"
#include "../src/argos_ike.h"
#include "../src/argos_ipfix.h"
#include "../src/argos_knx.h"
#include "../src/argos_ldap.h"
#include "../src/argos_ldaps.h"
#include "../src/argos_lpd.h"
#include "../src/argos_matter.h"
#include "../src/argos_mongodb.h"
#include "../src/argos_netflow.h"
#include "../src/argos_nvmeof.h"
#include "../src/argos_opcua.h"
#include "../src/argos_openvpn.h"
#include "../src/argos_redis.h"
#include "../src/argos_rip.h"
#include "../src/argos_rtcp.h"
#include "../src/argos_rtp.h"
#include "../src/argos_rtsp.h"
#include "../src/argos_s7.h"
#include "../src/argos_sflow.h"
#include "../src/argos_syslog.h"
#include "../src/argos_tacacs.h"
#include "../src/argos_telnet.h"
#include "../src/argos_thread.h"
#include "../src/argos_vnc.h"
#include "../src/argos_winrm.h"

static void test_netflow_bounds(void) {
    unsigned char p[24] = {0};
    argos_netflow_result_t r;

    p[1] = 5;
    assert(argos_netflow_parse(p, 19U, &r) == 0);
    assert(argos_netflow_parse(p, 23U, &r) == 0);
    assert(argos_netflow_parse(p, 24U, &r) == 1);

    memset(p, 0, sizeof(p));
    p[1] = 9;
    assert(argos_netflow_parse(p, 19U, &r) == 0);
    assert(argos_netflow_parse(p, 20U, &r) == 1);
}

static void test_ipfix_bounds(void) {
    unsigned char p[16] = {0};
    argos_ipfix_result_t r;
    p[1] = 10;
    p[3] = 16;
    assert(argos_ipfix_parse(p, 15U, &r) == 0);
    assert(argos_ipfix_parse(p, 16U, &r) == 1);
    p[3] = 17;
    assert(argos_ipfix_parse(p, 16U, &r) == 0);
}

static void test_sflow_bounds(void) {
    unsigned char p[40] = {0};
    argos_sflow_result_t r;
    p[3] = 5;
    p[7] = 1;
    assert(argos_sflow_parse(p, 27U, &r) == 0);
    assert(argos_sflow_parse(p, 28U, &r) == 1);

    memset(p, 0, sizeof(p));
    p[3] = 5;
    p[7] = 2;
    assert(argos_sflow_parse(p, 39U, &r) == 0);
    assert(argos_sflow_parse(p, 40U, &r) == 1);
}

static void test_knx_bounds(void) {
    unsigned char p[6] = {0x06, 0x10, 0x02, 0x01, 0x00, 0x06};
    argos_knx_result_t r;
    assert(argos_knx_parse(p, 5U, &r) == 0);
    assert(argos_knx_parse(p, 6U, &r) == 1);
    p[5] = 7;
    assert(argos_knx_parse(p, 6U, &r) == 0);
}

static void test_s7_bounds(void) {
    unsigned char p[12] = {0x32, 0x01, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    argos_s7_result_t r;
    assert(argos_s7_parse(p, 9U, &r) == 0);
    assert(argos_s7_parse(p, 10U, &r) == 1);

    p[1] = 0x03;
    assert(argos_s7_parse(p, 11U, &r) == 0);
    assert(argos_s7_parse(p, 12U, &r) == 1);
}

static void test_opcua_bounds(void) {
    unsigned char p[8] = {'H','E','L','F',8,0,0,0};
    argos_opcua_result_t r;
    assert(argos_opcua_parse(p, 7U, &r) == 0);
    assert(argos_opcua_parse(p, 8U, &r) == 1);
    p[4] = 9;
    assert(argos_opcua_parse(p, 8U, &r) == 0);
}

static void test_dnp3_minimum(void) {
    unsigned char p[10] = {0x05,0x64,0x05,0x00,0,0,0,0,0,0};
    argos_dnp3_result_t r;
    assert(argos_dnp3_parse(p, 9U, &r) == 0);
    assert(argos_dnp3_parse(p, 10U, &r) == 1);
    p[2] = 4;
    assert(argos_dnp3_parse(p, 10U, &r) == 0);
}

static void test_syslog_minimum(void) {
    static const unsigned char ok[] = "<13>1 x";
    static const unsigned char bad[] = "<192>x";
    argos_syslog_result_t r;
    assert(argos_syslog_parse(ok, sizeof(ok) - 1U, &r) == 1);
    assert(r.pri == 13 && r.facility == 1 && r.severity == 5 && r.rfc5424 == 1);
    assert(argos_syslog_parse(bad, sizeof(bad) - 1U, &r) == 0);
}

int main(void) {
    test_netflow_bounds();
    test_ipfix_bounds();
    test_sflow_bounds();
    test_knx_bounds();
    test_s7_bounds();
    test_opcua_bounds();
    test_dnp3_minimum();
    test_syslog_minimum();
    return 0;
}
