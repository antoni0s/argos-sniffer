#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_tls_server_staging.h"

static void test_tls13_serverhello(void)
{
    /* Minimal synthetic TLS 1.3 ServerHello with supported_versions + key_share. */
    const uint8_t record[] = {
        0x16, 0x03, 0x03, 0x00, 0x3a,
        0x02, 0x00, 0x00, 0x36,
        0x03, 0x03,
        /* random */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,             /* session id length */
        0x13, 0x01,       /* TLS_AES_128_GCM_SHA256 */
        0x00,             /* compression */
        0x00, 0x0e,       /* extensions length */
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        0x00, 0x33, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x00
    };

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 1);
    assert(out.legacy_version == 0x0303U);
    assert(out.negotiated_version == 0x0304U);
    assert(out.cipher_suite == 0x1301U);
    assert(out.has_supported_versions == 1U);
    assert(out.has_key_share == 1U);
    assert(out.extension_count == 2U);
    assert(out.extensions[0] == 0x002bU);
    assert(out.extensions[1] == 0x0033U);
}

static void test_grease_is_not_fingerprint_input(void)
{
    const uint8_t record[] = {
        0x16, 0x03, 0x03, 0x00, 0x36,
        0x02, 0x00, 0x00, 0x32,
        0x03, 0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x13, 0x02,
        0x00,
        0x00, 0x0a,
        0x0a, 0x0a, 0x00, 0x00,
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04
    };

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 1);
    assert(out.extension_count == 1U);
    assert(out.extensions[0] == 0x002bU);
}

static void test_truncated_record_rejected(void)
{
    const uint8_t record[] = {
        0x16, 0x03, 0x03, 0x00, 0x20,
        0x02, 0x00, 0x00, 0x1c
    };

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 0);
}

static void test_not_serverhello_rejected(void)
{
    uint8_t record[64];
    memset(record, 0, sizeof(record));
    record[0] = 0x16;
    record[3] = 0x00;
    record[4] = 0x3b;
    record[5] = 0x01; /* ClientHello, not ServerHello */

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 0);
}

int main(void)
{
    test_tls13_serverhello();
    test_grease_is_not_fingerprint_input();
    test_truncated_record_rejected();
    test_not_serverhello_rejected();

    puts("test_tls_server_staging: ok");
    return 0;
}
