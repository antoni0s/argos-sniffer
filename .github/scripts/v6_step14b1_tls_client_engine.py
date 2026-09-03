from pathlib import Path

main = Path('src/argos-sniffer.c')
tls = Path('src/argos_tls.h')

s = main.read_text()
if tls.exists():
    raise SystemExit('argos_tls.h already exists')

# Extract the existing MD5 implementation verbatim from the main file.
md5_start = s.index('/* ============================================================================\n * SECTION: Micro MD5 Implementation (For JA4 Fingerprinting)')
md5_end = s.index('/* ============================================================================\n * SECTION: Gateway/Routed Traffic Detection', md5_start)
md5 = s[md5_start:md5_end].rstrip()

# Extract the current ClientHello/JA4 parser and its two local helpers.
proto_marker = '/* ============================================================================\n * SECTION: Protocol Parsers'
proto_start = s.index(proto_marker)
cmp_start = s.index('static int cmp_uint16(', proto_start)
quic_marker = '/**\n * Parses QUIC initial packets and decrypts/inspects payloads (stateless or stateful).\n */'
client_end = s.index(quic_marker, cmp_start)
client = s[cmp_start:client_end].rstrip()

# Replace call-sites before declarations so names are prefixed exactly once.
client = client.replace('qsort(ext_arr, (size_t)ext_count, sizeof(uint16_t), cmp_uint16);',
                        'qsort(ext_arr, (size_t)ext_count, sizeof(uint16_t), atc_cmp_uint16);', 1)
client = client.replace('is_grease16(', 'atc_grease16(')
client = client.replace('static inline int atc_grease16(', 'static inline int atc_grease16(', 1)
client = client.replace('static int cmp_uint16(', 'static inline int atc_cmp_uint16(', 1)
old_sig = 'static void parse_tls_sni(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport, const char *routed_str, int rl_enabled) {'
new_sig = 'static inline int argos_tls_client_parse(const unsigned char *payload, int len, argos_tls_client_result_t *out) {'
if old_sig not in client:
    raise SystemExit('TLS ClientHello signature marker missing')
client = client.replace(old_sig, new_sig, 1)
client = client.replace('if (len < 44 || payload[0] != 0x16 || payload[5] != 0x01) return;',
                        'if (!payload || !out || len < 44 || payload[0] != 0x16 || payload[5] != 0x01) return 0;\n    memset(out, 0, sizeof(*out));', 1)
client = client.replace('read_be16(', 'atc_be16(')
client = client.replace('sanitize_field(', 'atc_sanitize_field(')
client = client.replace('md5_hash(', 'atc_md5_hash(')
# All remaining bare returns in this extracted parser are parse failures.
client = client.replace('return;', 'return 0;')

tail_start = client.index('    char fp_payload[512], fp_sig[640];')
tail_end = client.rfind('\n}')
replacement = '''    snprintf(out->sni, sizeof(out->sni), "%s", sni);\n    snprintf(out->alpn, sizeof(out->alpn), "%s", alpn);\n    snprintf(out->ja4, sizeof(out->ja4), "%s", ja4_full);\n    return 1;'''
client = client[:tail_start] + replacement + client[tail_end:]

# Namescope the MD5 helper using token-specific replacements that cannot
# recursively rename the generated names.
md5 = md5.replace('#define LEFTROTATE(x, c)', '#define ATC_LEFTROTATE(x, c)', 1)
md5 = md5.replace('#define MD5_STACK_BUF 8192', '#define ATC_MD5_STACK_BUF 8192', 1)
md5 = md5.replace('static const uint32_t MD5_K[64]', 'static const uint32_t ATC_MD5_K[64]', 1)
md5 = md5.replace('static const uint32_t MD5_S[16]', 'static const uint32_t ATC_MD5_S[16]', 1)
md5 = md5.replace('static void md5_hash(', 'static inline void atc_md5_hash(', 1)
md5 = md5.replace('uint8_t stackbuf[MD5_STACK_BUF];', 'uint8_t stackbuf[ATC_MD5_STACK_BUF];', 1)
md5 = md5.replace('MD5_K[i]', 'ATC_MD5_K[i]')
md5 = md5.replace('MD5_S[(i/16)*4 + (i%4)]', 'ATC_MD5_S[(i/16)*4 + (i%4)]')
md5 = md5.replace('LEFTROTATE((a + f + ATC_MD5_K[i] + w[g])', 'ATC_LEFTROTATE((a + f + ATC_MD5_K[i] + w[g])')

header = '''#ifndef ARGOS_TLS_H\n#define ARGOS_TLS_H\n\n#include <ctype.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n/* TLS ClientHello/JA4 engine. Parsing and fingerprint construction live here;\n * deduplication, routed attribution and telemetry sinks remain runtime concerns. */\ntypedef struct {\n    char sni[256];\n    char ja4[128];\n    char alpn[32];\n} argos_tls_client_result_t;\n\nstatic inline uint16_t atc_be16(const unsigned char *p) {\n    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);\n}\n\n/* Byte-compatible with the legacy main-file sanitizer used by TLS: values\n * outside printable ASCII and the telemetry delimiter become spaces. */\nstatic inline void atc_sanitize_field(const unsigned char *src, int len, char *dst, int dstsz, int lower) {\n    int o = 0;\n    if (!dst || dstsz <= 0) return;\n    if (!src || len <= 0) { dst[0] = '\\0'; return; }\n    for (int i = 0; i < len && o < dstsz - 1; ++i) {\n        unsigned char c = src[i];\n        if (c < 32U || c > 126U || c == '|') c = ' ';\n        else if (lower) c = (unsigned char)tolower(c);\n        dst[o++] = (char)c;\n    }\n    dst[o] = '\\0';\n}\n\n'''
header += md5 + '\n\n' + client + '\n\n#endif /* ARGOS_TLS_H */\n'

# Replace the extracted implementation with a small runtime adapter that preserves
# the existing wire format and keeps QUIC->TLS integration source-compatible.
wrapper = '''static void parse_tls_sni(const unsigned char *payload, int len, const char *mac, const char *src_ip, const char *dst_ip, uint16_t dport, const char *routed_str, int rl_enabled) {\n    argos_tls_client_result_t tls;\n    if (!argos_tls_client_parse(payload, len, &tls)) return;\n    char fp_payload[512], fp_sig[640];\n    snprintf(fp_payload, sizeof(fp_payload), "%s|%s", tls.sni, tls.ja4);\n    source_dedup_signature(fp_sig, sizeof(fp_sig), src_ip, fp_payload, routed_str);\n    if (!dedup_should_suppress(mac, "TLS", fp_sig, rl_enabled)) {\n        emit_telemetry("TLS|%s|%s|%s|%u|%s|%s|%s%s\\n", mac, src_ip, dst_ip, dport, tls.sni, tls.ja4, tls.alpn, routed_str);\n    }\n    if (dport == 853U && !dedup_should_suppress(mac, "DOT", fp_sig, rl_enabled)) {\n        emit_telemetry("DOT|%s|%s|%s|%s|%s|%s%s\\n", mac, src_ip, dst_ip, tls.sni, tls.ja4, tls.alpn, routed_str);\n    }\n}\n\n'''

s = s[:md5_start] + s[md5_end:]
# Re-find after the earlier deletion shifted offsets.
proto_start = s.index(proto_marker)
cmp_start = s.index('static int cmp_uint16(', proto_start)
client_end = s.index(quic_marker, cmp_start)
s = s[:cmp_start] + wrapper + s[client_end:]

include_marker = '#include "argos_tls_ports.h"\n'
if include_marker not in s:
    raise SystemExit('TLS ports include marker missing')
s = s.replace(include_marker, include_marker + '#include "argos_tls.h"\n', 1)

# Normalize only generated engine text; do not rewrite unrelated production lines.
header = '\n'.join(line.rstrip() for line in header.splitlines()) + '\n'
tls.write_text(header)
main.write_text(s)
