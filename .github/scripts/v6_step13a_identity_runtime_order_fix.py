from pathlib import Path

p=Path('src/argos-sniffer.c')
s=p.read_text()
anchor='''/* One wire-format boundary for all observed identity parsers. Protocol parsers\n * produce bounded evidence; this runtime helper owns MAC formatting, dedup and\n * IDENT serialization so those concerns cannot drift per protocol. */\nstatic void emit_identity_observation'''
if s.count(anchor)!=1:
    raise SystemExit(f'identity emitter anchor count={s.count(anchor)}')
replacement='''/* format_mac is implemented with the packet/flow helpers below; declare it\n * here because the telemetry runtime uses the same canonical formatter. */\nstatic void format_mac(const uint8_t mac[6], char out[18]);\n\n/* One wire-format boundary for all observed identity parsers. Protocol parsers\n * produce bounded evidence; this runtime helper owns MAC formatting, dedup and\n * IDENT serialization so those concerns cannot drift per protocol. */\nstatic void emit_identity_observation'''
p.write_text(s.replace(anchor,replacement,1))
print('staged identity runtime declaration ordering fix')
