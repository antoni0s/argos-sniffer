# Staged-only patch applied and committed by the gated workflow after all checks pass.
from pathlib import Path

src = Path("src/argos_enterprise.h")
test = Path("tests/test_enterprise.c")

s = src.read_text()
old = r'''static inline int ae_rdp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 11 || p[0] != 0x03U || p[1] != 0x00U) return 0; /* TPKT */
    if (p[5] != 0xe0U && p[5] != 0xd0U) return 0;             /* X.224 CR/CC */
    char cookie[128] = {0};
    const unsigned char *c = ae_find_ci(p, len, "Cookie: mstshash=");
    if (c) {
        c += 16; const unsigned char *e = ae_find(c, (int)((p + len) - c), (const unsigned char *)"\r\n", 2);
        int n = e ? (int)(e - c) : 0; if (n > 120) n = 120; ae_clean(c, n, cookie, sizeof(cookie));
    }
    ae_set(r, "rdp", 1, "x224=%s cookie=%s", p[5] == 0xe0U ? "connection-request" : "connection-confirm",
           cookie[0] ? cookie : "-");
    return 1;
}
'''
new = r'''static inline int ae_rdp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 11 || p[0] != 0x03U || p[1] != 0x00U) return 0; /* TPKT */
    if (p[5] != 0xe0U && p[5] != 0xd0U) return 0;             /* X.224 CR/CC */

    /* mstshash is often derived from a login/user identifier. Enterprise mode
     * must never expose it verbatim. Keep only bounded presence/length/hash
     * metadata; explicit identity extraction is handled by a separate opt-in
     * vector rather than weakening the default ENT privacy contract. */
    unsigned cookie_present = 0U, cookie_len = 0U;
    uint32_t cookie_hash = 0U;
    const unsigned char *c = ae_find_ci(p, len, "Cookie: mstshash=");
    if (c) {
        c += 16;
        const unsigned char *e = ae_find(c, (int)((p + len) - c),
                                         (const unsigned char *)"\r\n", 2);
        if (e && e > c) {
            size_t n = (size_t)(e - c);
            if (n > 120U) n = 120U;
            cookie_present = 1U;
            cookie_len = (unsigned)n;
            cookie_hash = 2166136261U;
            for (size_t i = 0; i < n; ++i) {
                cookie_hash ^= c[i];
                cookie_hash *= 16777619U;
            }
        }
    }
    ae_set(r, "rdp", 1,
           "x224=%s cookie_present=%u cookie_len=%u cookie_hash=%08x",
           p[5] == 0xe0U ? "connection-request" : "connection-confirm",
           cookie_present, cookie_len, cookie_hash);
    return 1;
}
'''
if s.count(old) != 1:
    raise SystemExit(f"RDP source anchor count={s.count(old)}")
src.write_text(s.replace(old, new, 1))

t = test.read_text()
anchor = r'''static void test_elephant_fast_drop(void) {
'''
fixture = r'''static void test_rdp_privacy(void) {
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

'''
if t.count(anchor) != 1:
    raise SystemExit(f"test insertion anchor count={t.count(anchor)}")
t = t.replace(anchor, fixture + anchor, 1)
main_anchor = r'''    test_cip_tcp();
    test_elephant_fast_drop();
'''
main_new = r'''    test_cip_tcp();
    test_rdp_privacy();
    test_elephant_fast_drop();
'''
if t.count(main_anchor) != 1:
    raise SystemExit(f"test main anchor count={t.count(main_anchor)}")
test.write_text(t.replace(main_anchor, main_new, 1))

print("staged RDP privacy hardening")
