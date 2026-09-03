#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_identity.h"

static void check(int ok, const char *msg) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); }
}

int main(void) {
    const unsigned char v[] = "alice|corp\\admin\n";
    argos_identity_result_t a, b, raw;
    check(argos_identity_build(&a, "rdp", "user", v, sizeof(v)-1U, 0), "hash identity builds");
    check(a.present && a.value_len == sizeof(v)-1U, "presence and bounded length");
    check(strstr(a.value, "hash=") == a.value, "default is hash-only");
    check(strstr(a.value, "alice") == NULL, "default never exposes raw identity");
    check(argos_identity_build(&b, "rdp", "user", v, sizeof(v)-1U, 0), "second hash builds");
    check(a.hash == b.hash && strcmp(a.value, b.value) == 0, "identity hash deterministic");
    check(argos_identity_build(&raw, "rdp", "user", v, sizeof(v)-1U, 1), "raw identity builds");
    check(strstr(raw.value, "alice/corp/admin") != NULL, "raw mode bounded and delimiter-cleaned");
    check(strchr(raw.value, '|') == NULL && strchr(raw.value, '\\') == NULL && strchr(raw.value, '\n') == NULL,
          "raw identity sanitizes telemetry delimiters/control bytes");
    check(!argos_identity_build(&a, "rdp", "user", NULL, 0, 0), "empty identity rejected");
    puts("identity framework fixtures: PASS");
    return 0;
}
