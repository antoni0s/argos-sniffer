#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/argos_tls_certificate_staging.h"

static void test_tls12_single_certificate(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x0d,
        0x0b,0x00,0x00,0x09,
        0x00,0x00,0x06,
        0x00,0x00,0x03,0x30,0x01,0x00
    };
    argos_tls_certificate_staging_result_t out;
    assert(argos_tls_certificate_staging_parse(record,sizeof(record),0,&out)==1);
    assert(out.tls13_format==0U);
    assert(out.has_leaf==1U);
    assert(out.certificate_count==1U);
    assert(out.leaf_length==3U);
    assert(record[out.leaf_offset]==0x30U);
}

static void test_tls13_single_certificate(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x10,
        0x0b,0x00,0x00,0x0c,
        0x00,
        0x00,0x00,0x08,
        0x00,0x00,0x03,0x30,0x01,0x00,
        0x00,0x00
    };
    argos_tls_certificate_staging_result_t out;
    assert(argos_tls_certificate_staging_parse(record,sizeof(record),1,&out)==1);
    assert(out.tls13_format==1U);
    assert(out.has_leaf==1U);
    assert(out.certificate_count==1U);
    assert(out.leaf_length==3U);
}

static void test_truncated_certificate_rejected(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x0c,
        0x0b,0x00,0x00,0x08,
        0x00,0x00,0x05,
        0x00,0x00,0x04,0x30,0x01
    };
    argos_tls_certificate_staging_result_t out;
    assert(argos_tls_certificate_staging_parse(record,sizeof(record),0,&out)==0);
}

static void test_not_certificate_rejected(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x07,
        0x02,0x00,0x00,0x03,0,0,0
    };
    argos_tls_certificate_staging_result_t out;
    assert(argos_tls_certificate_staging_parse(record,sizeof(record),0,&out)==0);
}

int main(void)
{
    test_tls12_single_certificate();
    test_tls13_single_certificate();
    test_truncated_certificate_rejected();
    test_not_certificate_rejected();
    puts("test_tls_certificate_staging: ok");
    return 0;
}
