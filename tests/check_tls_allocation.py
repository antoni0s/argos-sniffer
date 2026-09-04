from pathlib import Path

tls = Path("src/argos_tls.h").read_text()
body = tls.split("static void atc_md5_hash(", 1)[1].split("\n}", 1)[0]

assert "malloc(" not in tls and "calloc(" not in tls and "realloc(" not in tls
assert "free(" not in body
assert "uint8_t tail[128]" in body
assert "ATC_MD5_STACK_BUF" not in tls
print("TLS fingerprint allocation/streaming invariants: PASS")
