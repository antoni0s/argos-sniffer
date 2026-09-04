#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/argos_tls_client_enrichment_staging.h"

static void test_tls13_enrichment_flags(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x01,0x00,0x50,
        0x01,0x00,0x00,0x4c,
        0x03,0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x00,0x02, 0x13,0x01,
        0x01,0x00,
        0x00,0x21,
        0x00,0x2b,0x00,0x05, 0x04,0x03,0x04,0x03,0x03,
        0x00,0x2d,0x00,0x02, 0x01,0x01,
        0x00,0x29,0x00,0x00,
        0x00,0x2a,0x00,0x00,
        0xfe,0x0d,0x00,0x00
    };

    argos_tls_client_enrichment_staging_result_t out;
    assert(argos_tls_client_enrichment_parse(record, sizeof(record), &out) == 1);
    assert(out.legacy_version == 0x0303U);
    assert(out.has_supported_versions == 1U);
    assert(out.supported_version_count == 2U);
    assert(out.supported_versions[0] == 0x0304U);
    assert(out.supported_versions[1] == 0x0303U);
    assert(out.has_psk_key_exchange_modes == 1U);
    assert(out.has_pre_shared_key == 1U);
    assert(out.has_early_data == 1U);
    assert(out.has_ech == 1U);
}

static void test_truncated_extensions_rejected(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x01,0x00,0x2e,
        0x01,0x00,0x00,0x2a,
        0x03,0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x00,0x02,0x13,0x01,
        0x01,0x00,
        0x00,0x04,
        0xfe,0x0d,0x00
    };

    argos_tls_client_enrichment_staging_result_t out;
    assert(argos_tls_client_enrichment_parse(record, sizeof(record), &out) == 0);
}

int main(void)
{
    test_tls13_enrichment_flags();
    test_truncated_extensions_rejected();
    puts("test_tls_client_enrichment_staging: ok");
    return 0;
}
