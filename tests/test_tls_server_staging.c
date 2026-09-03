#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_tls_server_staging.h"

static void test_tls13_serverhello(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x3a,
        0x02,0x00,0x00,0x36,
        0x03,0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x13,0x01,
        0x00,
        0x00,0x0e,
        0x00,0x2b,0x00,0x02,0x03,0x04,
        0x00,0x33,0x00,0x04,0x00,0x1d,0x00,0x00
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
    assert(out.is_hello_retry_request == 0U);

    {
        char ver[3], alpn[3], cipher[5], exts[ARGOS_TLS_SERVER_RAW_EXT_MAX];
        assert(argos_tls_server_staging_raw_components(&out, 't', ver, alpn, cipher, exts) == 1);
        assert(strcmp(ver, "13") == 0);
        assert(strcmp(alpn, "00") == 0);
        assert(strcmp(cipher, "1301") == 0);
        assert(strcmp(exts, "002b,0033") == 0);
    }
}

static void test_hello_retry_request(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x34,
        0x02,0x00,0x00,0x30,
        0x03,0x03,
        0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
        0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
        0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
        0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c,
        0x00,
        0x13,0x01,
        0x00,
        0x00,0x08,
        0x00,0x2b,0x00,0x02,0x03,0x04,
        0x00,0x33,0x00,0x00
    };

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 1);
    assert(out.is_hello_retry_request == 1U);
    assert(out.negotiated_version == 0x0304U);
}

static void test_alpn_and_session_flags(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x48,
        0x02,0x00,0x00,0x44,
        0x03,0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x13,0x02,
        0x00,
        0x00,0x1c,
        0x00,0x2b,0x00,0x02,0x03,0x04,
        0x00,0x10,0x00,0x05,0x00,0x03,0x02,'h','2',
        0x00,0x29,0x00,0x02,0x00,0x00,
        0x00,0x2a,0x00,0x00,
        0xfe,0x0d,0x00,0x00
    };

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 1);
    assert(out.has_alpn == 1U);
    assert(strcmp(out.alpn, "h2") == 0);
    assert(out.has_pre_shared_key == 1U);
    assert(out.has_early_data == 1U);
    assert(out.has_ech == 1U);

    {
        char ver[3], alpn[3], cipher[5], exts[ARGOS_TLS_SERVER_RAW_EXT_MAX];
        assert(argos_tls_server_staging_raw_components(&out, 't', ver, alpn, cipher, exts) == 1);
        assert(strcmp(alpn, "h2") == 0);
        assert(strcmp(cipher, "1302") == 0);
    }
}

static void test_grease_is_not_fingerprint_input(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x36,
        0x02,0x00,0x00,0x32,
        0x03,0x03,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,
        0x13,0x02,
        0x00,
        0x00,0x0a,
        0x0a,0x0a,0x00,0x00,
        0x00,0x2b,0x00,0x02,0x03,0x04
    };

    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 1);
    assert(out.extension_count == 1U);
    assert(out.extensions[0] == 0x002bU);
}

static void test_truncated_record_rejected(void)
{
    const uint8_t record[] = {
        0x16,0x03,0x03,0x00,0x20,
        0x02,0x00,0x00,0x1c
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
    record[5] = 0x01;
    argos_tls_server_staging_result_t out;
    assert(argos_tls_server_staging_parse(record, sizeof(record), &out) == 0);
}

int main(void)
{
    test_tls13_serverhello();
    test_hello_retry_request();
    test_alpn_and_session_flags();
    test_grease_is_not_fingerprint_input();
    test_truncated_record_rejected();
    test_not_serverhello_rejected();
    puts("test_tls_server_staging: ok");
    return 0;
}
