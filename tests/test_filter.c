#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/argos_filter.h"

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static uint32_t ipv4(const char *text) {
    struct in_addr addr;
    check(inet_pton(AF_INET, text, &addr) == 1, "fixture IPv4 valid");
    return addr.s_addr;
}

static struct in6_addr ipv6(const char *text) {
    struct in6_addr addr;
    check(inet_pton(AF_INET6, text, &addr) == 1, "fixture IPv6 valid");
    return addr;
}

static int match(const argos_filter_program_t *program,
                 const uint8_t src_mac[6], const uint8_t dst_mac[6],
                 const char *src4, const char *dst4,
                 const struct in6_addr *src6, const struct in6_addr *dst6) {
    return argos_filter_match(program, src_mac, dst_mac,
                              src4 ? ipv4(src4) : 0U, dst4 ? ipv4(dst4) : 0U,
                              src6, dst6);
}

static void test_literals(void) {
    const uint8_t src_mac[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t dst_mac[6] = {0x02, 0, 0, 0, 0, 2};
    argos_filter_program_t program = {0};

    check(argos_filter_compile(NULL, &program) == 0 && !program.is_active,
          "NULL expression is inactive");
    check(match(&program, src_mac, dst_mac, "192.0.2.1", "198.51.100.2", NULL, NULL),
          "inactive filter admits packet");

    check(argos_filter_compile("02:00:00:00:00:02", &program) == 0,
          "MAC expression compiles");
    check(match(&program, src_mac, dst_mac, NULL, NULL, NULL, NULL),
          "destination MAC matches");
    check(!match(&program, src_mac, src_mac, NULL, NULL, NULL, NULL),
          "different MAC does not match");

    check(argos_filter_compile("192.0.2.0/24", &program) == 0,
          "IPv4 CIDR compiles");
    check(match(&program, src_mac, dst_mac, "10.0.0.1", "192.0.2.200", NULL, NULL),
          "IPv4 destination CIDR matches");
    check(!match(&program, src_mac, dst_mac, "10.0.0.1", "198.51.100.2", NULL, NULL),
          "IPv4 outside CIDR does not match");

    struct in6_addr inside = ipv6("2001:db8:1::42");
    struct in6_addr outside = ipv6("2001:db8:2::42");
    check(argos_filter_compile("2001:db8:1::/64", &program) == 0,
          "IPv6 CIDR compiles");
    check(match(&program, src_mac, dst_mac, NULL, NULL, &inside, NULL),
          "IPv6 source CIDR matches");
    check(!match(&program, src_mac, dst_mac, NULL, NULL, &outside, NULL),
          "IPv6 outside CIDR does not match");
    check(!match(&program, src_mac, dst_mac, "192.0.2.1", "192.0.2.2", NULL, NULL),
          "IPv6 token safely rejects non-IPv6 packet");
}

static void test_boolean_semantics(void) {
    const uint8_t a[6] = {0x02, 0, 0, 0, 0, 1};
    const uint8_t b[6] = {0x02, 0, 0, 0, 0, 2};
    argos_filter_program_t program = {0};

    check(argos_filter_compile("192.0.2.1 or 198.51.100.0/24 and 02:00:00:00:00:02",
                               &program) == 0,
          "precedence expression compiles");
    check(match(&program, a, a, "192.0.2.1", "203.0.113.1", NULL, NULL),
          "OR left operand matches independently");
    check(!match(&program, a, a, "198.51.100.9", "203.0.113.1", NULL, NULL),
          "AND binds tighter than OR");
    check(match(&program, a, b, "198.51.100.9", "203.0.113.1", NULL, NULL),
          "AND branch matches both operands");

    check(argos_filter_compile("(192.0.2.1 or 198.51.100.9) and not 02:00:00:00:00:02",
                               &program) == 0,
          "parenthesized NOT expression compiles");
    check(match(&program, a, a, "198.51.100.9", "203.0.113.1", NULL, NULL),
          "parentheses and word NOT preserved");
    check(!match(&program, a, b, "198.51.100.9", "203.0.113.1", NULL, NULL),
          "NOT rejects matching MAC");

    check(argos_filter_compile("!!192.0.2.1", &program) == 0,
          "right-associative repeated NOT compiles");
    check(match(&program, a, b, "192.0.2.1", "203.0.113.1", NULL, NULL),
          "double NOT preserves match");

    check(argos_filter_compile("192.0.2.1 && !198.51.100.1", &program) == 0,
          "symbolic operators compile");
    check(match(&program, a, b, "192.0.2.1", "203.0.113.1", NULL, NULL),
          "symbolic AND/NOT evaluate");
}

static void test_validation(void) {
    argos_filter_program_t program = {0};
    uint8_t mac[6];
    int bits = -1;
    char long_expression[513];

    check(argos_filter_parse_mac("aa:bb:cc:dd:ee:ff", mac), "strict MAC parser accepts canonical MAC");
    check(!argos_filter_parse_mac("aa:bb:cc:dd:ee:ff:00", mac), "strict MAC parser rejects suffix");
    check(!argos_filter_parse_mac("aa:bb:cc:dd:ee", mac), "strict MAC parser rejects short MAC");
    check(argos_filter_parse_cidr_bits("0", 32, &bits) && bits == 0, "CIDR zero accepted");
    check(argos_filter_parse_cidr_bits("128", 128, &bits) && bits == 128, "IPv6 /128 accepted");
    check(!argos_filter_parse_cidr_bits("33", 32, &bits), "IPv4 CIDR overflow rejected");
    check(!argos_filter_parse_cidr_bits("24x", 32, &bits), "CIDR suffix rejected");

    check(argos_filter_compile("192.0.2.1 198.51.100.1", &program) < 0,
          "missing operator rejected");
    check(argos_filter_compile("192.0.2.1 and", &program) < 0,
          "trailing operator rejected");
    check(argos_filter_compile("(192.0.2.1", &program) < 0,
          "unmatched open parenthesis rejected");
    check(argos_filter_compile("192.0.2.1)", &program) < 0,
          "unmatched close parenthesis rejected");
    check(argos_filter_compile("192.0.2.0/33", &program) < 0,
          "invalid IPv4 prefix rejected");
    check(argos_filter_compile("2001:db8::/129", &program) < 0,
          "invalid IPv6 prefix rejected");
    check(argos_filter_compile("hostname", &program) < 0,
          "unknown literal rejected");
    check(argos_filter_compile("and 192.0.2.1", &program) < 0,
          "leading binary operator rejected");

    memset(long_expression, '1', sizeof(long_expression) - 1U);
    long_expression[sizeof(long_expression) - 1U] = '\0';
    check(argos_filter_compile(long_expression, &program) < 0,
          "overlong expression rejected before copy");
}

int main(void) {
    check(sizeof(argos_filter_program_t) <= 4096U, "compiled filter remains bounded");
    test_literals();
    test_boolean_semantics();
    test_validation();
    puts("filter engine fixtures: PASS");
    return 0;
}
