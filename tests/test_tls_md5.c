#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_tls.h"

static void expect_hash(const void *data, size_t len, const char *expected) {
    char out[33];
    atc_md5_hash((const uint8_t *)data, len, out);
    assert(strcmp(out, expected) == 0);
}

int main(void) {
    expect_hash("", 0, "d41d8cd98f00b204e9800998ecf8427e");
    expect_hash("a", 1, "0cc175b9c0f1b6a831c399e269772661");
    expect_hash("abc", 3, "900150983cd24fb0d6963f7d28e17f72");
    expect_hash("message digest", 14, "f96b697d7cb7938d525a2f31aaf161d0");
    expect_hash("abcdefghijklmnopqrstuvwxyz", 26, "c3fcd3d76192e4007dfb496cca67e13b");
    expect_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
                "d174ab98d277d9f5a5611c2c9f419d9f");
    expect_hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
                "57edf4a22be3c955ac49da2e2107b67a");

    uint8_t boundary[4095];
    for (size_t i = 0; i < sizeof(boundary); ++i) boundary[i] = (uint8_t)(i * 37U + 11U);
    expect_hash(boundary, 55, "d872aa0473a24da995ce4ac518ade767");
    expect_hash(boundary, 56, "e23567645846677c205de80f9779081b");
    expect_hash(boundary, 63, "4775b66278a8fc132ff80923378216cd");
    expect_hash(boundary, 64, "71e123b70c7aa64826fcfe472694cd1c");
    expect_hash(boundary, 65, "5949948f26e35203661075214faa3966");
    expect_hash(boundary, 2047, "2c019e975256c2c2f06f8b08a228aa35");
    expect_hash(boundary, sizeof(boundary), "4a34dfb19ddffddbdf55bb4663d578d5");
    puts("TLS streaming MD5/no-allocation vectors: PASS");
    return 0;
}
