from pathlib import Path

main = Path("src/argos-sniffer.c").read_text()
quic = Path("src/argos_quic.h").read_text()

assert "malloc(" not in quic and "realloc(" not in quic
assert quic.count("calloc(") == 2
for name in ("decrypt_quic_sni", "decrypt_quic_sni_stateful"):
    body = quic.split(f"{name}(", 1)[1].split("\n}", 1)[0]
    assert "calloc(" not in body and "free(" not in body

startup = main.split("/* Compile canonical dedup demand once", 1)[1].split("argos_bpf_config_t bpf_cfg", 1)[0]
assert "!filter_mode1.is_active &&\n        argos_dispatch_protocol_enabled(&dispatch_plan, ARGOS_PROTOCOL_QUIC)" in startup
assert "argos_quic_prepare(&quic_state, opt_quic_heavy)" in startup
assert main.count("argos_quic_prepare(&quic_state") == 1
assert "uint8_t fake_tls_buf[8192]" not in main
assert "quic_success_cache" not in main
assert "argos_quic_success_recent(&quic_state" in main
assert "argos_quic_mark_success(&quic_state" in main
assert "decrypt_quic_sni(&quic_state" in main
assert "decrypt_quic_sni_stateful(&quic_state" in main
assert "quic_heavy_gc(&quic_state)" in main
assert "argos_quic_destroy(&quic_state);" in main
print("QUIC lifecycle adoption/allocation invariants: PASS")
