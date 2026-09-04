#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_x509_leaf_staging.h"

static void test_name_cn(void)
{
    /* Name ::= SET { SEQUENCE { OID commonName, UTF8String "router.local" } } */
    const uint8_t name[] = {
        0x31,0x12,
          0x30,0x10,
            0x06,0x03,0x55,0x04,0x03,
            0x0c,0x09,'r','o','u','t','e','r','.','l','o'
    };
    char out[ARGOS_X509_NAME_MAX];
    argos_x509_parse_name_cn(name, sizeof(name), out, sizeof(out));
    assert(strcmp(out, "router.lo") == 0);
}

static void test_san_dns(void)
{
    const uint8_t san_der[] = {
        0x30,0x17,
          0x82,0x09,'n','a','s','.','l','o','c','a','l',
          0x82,0x0a,'c','a','m','e','r','a','.','l','a','n'
    };
    argos_x509_leaf_staging_result_t out;
    memset(&out, 0, sizeof(out));
    argos_x509_parse_san_octet(san_der, sizeof(san_der), &out);
    assert(out.has_san == 1U);
    assert(out.san_count == 2U);
    assert(strcmp(out.san_dns[0], "nas.local") == 0);
    assert(strcmp(out.san_dns[1], "camera.lan") == 0);
}

static void test_malformed_der_rejected(void)
{
    const uint8_t bad[] = {0x30,0x82,0x01,0x00,0x30,0x01,0x00};
    argos_x509_leaf_staging_result_t out;
    assert(argos_x509_leaf_staging_parse(bad, sizeof(bad), &out) == 0);
}

static void test_printable_sanitizer(void)
{
    const uint8_t in[] = {'a','|','b',0x01,'c'};
    char out[16];
    argos_x509_copy_printable(in, sizeof(in), out, sizeof(out));
    assert(strcmp(out, "a_b_c") == 0);
}

int main(void)
{
    test_name_cn();
    test_san_dns();
    test_malformed_der_rejected();
    test_printable_sanitizer();
    puts("test_x509_leaf_staging: ok");
    return 0;
}
