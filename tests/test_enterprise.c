#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGOS_PORTABLE_TEST 1
#include "../src/argos_enterprise.h"

static void put_le32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffU);
    p[1] = (unsigned char)((v >> 8) & 0xffU);
    p[2] = (unsigned char)((v >> 16) & 0xffU);
    p[3] = (unsigned char)((v >> 24) & 0xffU);
}

static void put_be16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xffU);
}

static void put_be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)((v >> 16) & 0xffU);
    p[2] = (unsigned char)((v >> 8) & 0xffU);
    p[3] = (unsigned char)(v & 0xffU);
}

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", what);
        exit(1);
    }
}

static void test_sccp(void) {
    unsigned char p[48] = {0};
    argos_enterprise_result_t r;
    put_le32(p, 40U);
    put_le32(p + 8, 1U);
    memcpy(p + 12, "SEP001122334455", 15);
    put_le32(p + 40, 30016U);
    put_le32(p + 44, 4U);
    check(argos_enterprise_parse_tcp(43000, 2000, p, (int)sizeof(p), &r) == 1, "SCCP Register parsed");
    check(r.emit && r.complete, "SCCP Register completes flow fingerprint");
    check(strcmp(r.proto, "sccp") == 0, "SCCP protocol label");
    check(strstr(r.detail, "SEP001122334455") != NULL, "SCCP device name extracted");
}

static void test_kerberos_tcp(void) {
    unsigned char p[16] = {0};
    argos_enterprise_result_t r;
    put_be32(p, 12U);
    p[4] = 0x6aU; /* AS-REQ application tag */
    memcpy(p + 5, "EXAMPLE.COM", 11);
    check(argos_enterprise_parse_tcp(50000, 88, p, (int)sizeof(p), &r) == 1, "Kerberos TCP parsed");
    check(strcmp(r.proto, "kerberos") == 0, "Kerberos protocol label");
    check(strstr(r.detail, "AS-REQ") != NULL, "Kerberos AS-REQ identified");
}

static void test_ospf(void) {
    unsigned char p[44] = {0};
    argos_enterprise_result_t r;
    p[0] = 2; p[1] = 1;
    p[4] = 10; p[5] = 0; p[6] = 0; p[7] = 1;
    p[8] = 0; p[9] = 0; p[10] = 0; p[11] = 0;
    put_be16(p + 28, 10U);
    p[30] = 0x12U;
    put_be32(p + 32, 40U);
    check(argos_enterprise_parse_ipproto(89, p, (int)sizeof(p), &r) == 1, "OSPF Hello parsed");
    check(strstr(r.detail, "hello=10") != NULL, "OSPF Hello interval offset");
    check(strstr(r.detail, "dead=40") != NULL, "OSPF dead interval offset");
    check(strstr(r.detail, "options=0x12") != NULL, "OSPF options offset");
}

static void test_isis(void) {
    unsigned char p[20] = {0};
    argos_enterprise_result_t r;
    p[0] = 0x83U; p[1] = 20U; p[2] = 1U; p[3] = 6U; p[4] = 15U; p[5] = 1U;
    p[8] = 3U;
    p[9] = 0x00; p[10] = 0x11; p[11] = 0x22; p[12] = 0x33; p[13] = 0x44; p[14] = 0x55;
    put_be16(p + 15, 30U); put_be16(p + 17, 20U); p[19] = 64U;
    check(argos_enterprise_parse_l2(0x00feU, p, (int)sizeof(p), &r) == 1, "IS-IS IIH parsed");
    check(strcmp(r.proto, "isis") == 0, "IS-IS protocol label");
    check(strstr(r.detail, "L1-LAN") != NULL && strstr(r.detail, "hold=30") != NULL, "IS-IS Hello fields");
}

static void test_edp(void) {
    unsigned char p[64] = {0};
    argos_enterprise_result_t r;
    int pos = 16;
    p[0] = 2U;
    p[pos] = 0x99U; p[pos + 1] = 1U; put_be16(p + pos + 2, 11U); memcpy(p + pos + 4, "X440-G2", 7); pos += 11;
    p[pos] = 0x99U; p[pos + 1] = 2U; put_be16(p + pos + 2, 20U);
    put_be16(p + pos + 4, 0U); put_be16(p + pos + 6, 23U);
    p[pos + 16] = 32U; p[pos + 17] = 7U; p[pos + 18] = 1U; p[pos + 19] = 4U; pos += 20;
    put_be16(p + 2, (uint16_t)pos);
    check(argos_enterprise_parse_l2(0x00bbU, p, pos, &r) == 1, "EDP parsed");
    check(strcmp(r.proto, "edp") == 0, "EDP protocol label");
    check(strstr(r.detail, "X440-G2") != NULL && strstr(r.detail, "32.7.1.4") != NULL, "EDP model/release evidence");
}

static void test_fdp(void) {
    unsigned char p[96] = {0};
    argos_enterprise_result_t r;
    int pos = 4;
    p[0] = 1U; p[1] = 180U;
    put_be16(p + pos, 1U); put_be16(p + pos + 2, 12U); memcpy(p + pos + 4, "sw-core1", 8); pos += 12;
    put_be16(p + pos, 5U); put_be16(p + pos + 2, 12U); memcpy(p + pos + 4, "08.0.95a", 8); pos += 12;
    put_be16(p + pos, 6U); put_be16(p + pos + 2, 14U); memcpy(p + pos + 4, "ICX-7250", 8); pos += 14;
    check(argos_enterprise_parse_l2(0xf200U, p, pos, &r) == 1, "FDP parsed");
    check(strcmp(r.proto, "fdp") == 0, "FDP protocol label");
    check(strstr(r.detail, "sw-core1") != NULL && strstr(r.detail, "ICX-7250") != NULL, "FDP device/model evidence");
}

static void test_cip_tcp(void) {
    unsigned char p[24] = {0};
    argos_enterprise_result_t r;
    p[0] = 0x63U; p[1] = 0x00U; /* ListIdentity command 0x0063 LE */
    check(argos_enterprise_tcp_port(40000, 44818) == 1, "EtherNet/IP TCP port admitted");
    check(argos_enterprise_parse_tcp(40000, 44818, p, (int)sizeof(p), &r) == 1, "EtherNet/IP TCP ListIdentity parsed");
    check(strcmp(r.proto, "ethernet-ip") == 0, "EtherNet/IP TCP protocol label");
}

static void test_rdp_privacy(void) {
    static const char secret[] = "alice.enterprise.secret";
    unsigned char p[96] = {0};
    argos_enterprise_result_t r;
    const char prefix[] = "Cookie: mstshash=";
    const size_t off = 11U;
    p[0] = 0x03U; p[1] = 0x00U; p[5] = 0xe0U;
    memcpy(p + off, prefix, sizeof(prefix) - 1U);
    memcpy(p + off + sizeof(prefix) - 1U, secret, sizeof(secret) - 1U);
    memcpy(p + off + sizeof(prefix) - 1U + sizeof(secret) - 1U, "\r\n", 2U);
    int len = (int)(off + sizeof(prefix) - 1U + sizeof(secret) - 1U + 2U);

    check(argos_enterprise_parse_tcp(51000, 3389, p, len, &r) == 1, "RDP X.224 parsed");
    check(r.emit && r.complete && strcmp(r.proto, "rdp") == 0, "RDP fingerprint emitted/completed");
    check(strstr(r.detail, "cookie_present=1") != NULL, "RDP cookie presence retained");
    check(strstr(r.detail, "cookie_len=23") != NULL, "RDP cookie bounded length retained");
    check(strstr(r.detail, "cookie_hash=") != NULL, "RDP cookie hash retained");
    check(strstr(r.detail, secret) == NULL, "RDP raw mstshash never emitted");
    check(strstr(r.detail, "cookie=alice") == NULL, "RDP legacy raw cookie field removed");
}

static void test_elephant_fast_drop(void) {
    unsigned char iscsi[48] = {0};
    argos_enterprise_result_t r;
    iscsi[0] = 0x01U; /* SCSI Command: never inspect the data flow further. */
    check(argos_enterprise_parse_tcp(45000, 3260, iscsi, (int)sizeof(iscsi), &r) == 1, "iSCSI data opcode recognized");
    check(!r.emit && r.complete, "iSCSI data opcode fast-drop completion");
}

int main(void) {
    test_sccp();
    test_kerberos_tcp();
    test_ospf();
    test_isis();
    test_edp();
    test_fdp();
    test_cip_tcp();
    test_rdp_privacy();
    test_elephant_fast_drop();
    puts("enterprise parser fixtures: PASS");
    return 0;
}
