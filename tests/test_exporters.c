#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../src/argos_enterprise.h"

static void put16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}

static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}

static void test_syslog(void) {
    static const unsigned char rfc5424[] =
        "<165>1 2003-10-11T22:14:15.003Z host.example app 8710 ID47 "
        "[example@32473 iut=\"3\"] secret-message-body";
    static const unsigned char rfc3164[] =
        "<13>Feb  5 17:32:18 router-1 sshd[10]: private message";
    static const unsigned char bad_pri[] = "<192>bad";
    static const unsigned char bad_sd[] =
        "<13>1 2026-01-01T00:00:00Z host app - - [broken";
    unsigned char oversized[4097] = "<13>host app: body";
    argos_enterprise_result_t r;

    assert(ae_syslog(rfc5424, (int)sizeof(rfc5424) - 1, &r));
    assert(!strcmp(r.proto, "syslog"));
    assert(!strcmp(r.detail,
        "format=rfc5424 facility=20 severity=5 version=1 hostname=host.example appname=app structured_data=1"));
    assert(strstr(r.detail, "secret") == NULL);

    assert(ae_syslog(rfc3164, (int)sizeof(rfc3164) - 1, &r));
    assert(!strcmp(r.detail,
        "format=rfc3164 facility=1 severity=5 version=- hostname=router-1 appname=sshd structured_data=0"));
    assert(strstr(r.detail, "private") == NULL);
    assert(!ae_syslog(bad_pri, (int)sizeof(bad_pri) - 1, &r));
    assert(!ae_syslog(bad_sd, (int)sizeof(bad_sd) - 1, &r));
    assert(!ae_syslog(oversized, (int)sizeof(oversized), &r));
}

static void test_netflow(void) {
    unsigned char p[24] = {0};
    unsigned char oversized[4097] = {0};
    argos_enterprise_result_t r;

    put16(p, 5); put16(p + 2, 7); put32(p + 4, 1234);
    put32(p + 16, 99); p[20] = 2; p[21] = 3;
    assert(!ae_netflow(p, 23, &r));
    assert(ae_netflow(p, 24, &r));
    assert(!strcmp(r.detail,
        "version=5 count=7 sequence=99 engine_type=2 engine_id=3 source_id=- uptime=1234"));

    put16(p, 7); p[20] = 9; p[21] = 9;
    assert(ae_netflow(p, 24, &r));
    assert(!strcmp(r.detail,
        "version=7 count=7 sequence=99 engine_type=- engine_id=- source_id=- uptime=1234"));

    memset(p, 0, sizeof(p));
    put16(p, 9); put16(p + 2, 4); put32(p + 4, 88);
    put32(p + 12, 77); put32(p + 16, 66);
    assert(!ae_netflow(p, 19, &r));
    assert(ae_netflow(p, 20, &r));
    assert(!strcmp(r.detail,
        "version=9 count=4 sequence=77 engine_type=- engine_id=- source_id=66 uptime=88"));
    put16(oversized, 9);
    assert(!ae_netflow(oversized, (int)sizeof(oversized), &r));
}

static void test_ipfix(void) {
    unsigned char p[24] = {0};
    argos_enterprise_result_t r;

    put16(p, 10); put16(p + 2, 24); put32(p + 4, 11);
    put32(p + 8, 22); put32(p + 12, 33);
    put16(p + 16, 256); put16(p + 18, 8);
    assert(!ae_ipfix(p, 23, &r));
    assert(ae_ipfix(p, 24, &r));
    assert(!strcmp(r.detail,
        "version=10 length=24 sequence=22 observation_domain=33 export_time=11 sets=1"));
    put16(p + 18, 3);
    assert(!ae_ipfix(p, 24, &r));
}

static void test_sflow(void) {
    unsigned char p[40] = {0};
    argos_enterprise_result_t r;

    put32(p, 5); put32(p + 4, 1); p[8] = 192; p[9] = 0; p[10] = 2; p[11] = 5;
    put32(p + 12, 6); put32(p + 16, 7); put32(p + 24, 8);
    assert(!ae_sflow(p, 27, &r));
    assert(ae_sflow(p, 28, &r));
    assert(!strcmp(r.detail,
        "version=5 agent_type=ipv4 agent=192.0.2.5 sub_agent=6 sequence=7 samples=8"));

    memset(p, 0, sizeof(p));
    put32(p, 5); put32(p + 4, 2); p[8] = 0x20; p[9] = 0x01; p[23] = 1;
    put32(p + 24, 9); put32(p + 28, 10); put32(p + 36, 11);
    assert(!ae_sflow(p, 39, &r));
    assert(ae_sflow(p, 40, &r));
    assert(!strcmp(r.detail,
        "version=5 agent_type=ipv6 agent=2001:0000:0000:0000:0000:0000:0000:0001 sub_agent=9 sequence=10 samples=11"));
}

static void test_canonical_port_entrypoints(void) {
    static const unsigned char syslog[] =
        "<13>1 2026-01-01T00:00:00Z host app - - - message";
    unsigned char netflow[24] = {0}, ipfix[16] = {0}, sflow[28] = {0};
    argos_enterprise_result_t r;
    put16(netflow, 5);
    put16(ipfix, 10); put16(ipfix + 2, 16);
    put32(sflow, 5); put32(sflow + 4, 1);

    assert(argos_enterprise_parse_tcp(50000, 514, syslog,
                                      (int)sizeof(syslog) - 1, &r));
    assert(argos_enterprise_parse_tcp(50000, 4739, ipfix, 16, &r));
    assert(argos_enterprise_parse_udp(50000, 514, syslog,
                                      (int)sizeof(syslog) - 1, &r));
    assert(argos_enterprise_parse_udp(50000, 2055, netflow, 24, &r));
    assert(argos_enterprise_parse_udp(50000, 9995, netflow, 24, &r));
    assert(argos_enterprise_parse_udp(50000, 9996, netflow, 24, &r));
    assert(argos_enterprise_parse_udp(50000, 4739, ipfix, 16, &r));
    assert(argos_enterprise_parse_udp(50000, 6343, sflow, 28, &r));
}

int main(void) {
    test_syslog();
    test_netflow();
    test_ipfix();
    test_sflow();
    test_canonical_port_entrypoints();
    return 0;
}
