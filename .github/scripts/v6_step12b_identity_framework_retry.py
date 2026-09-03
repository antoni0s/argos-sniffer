from pathlib import Path

p=Path('src/argos-sniffer.c')
s=p.read_text()

usage_new='"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose] [--wireguard-port port] [--identity [--identity-raw]]\\n"\n'
usage_old='"     [--sensor --sensor-name name [--inside CIDR ...]] [--enterprise|--enterprise-verbose] [--wireguard-port port]\\n"\n'
if s.count(usage_new) != 1:
    raise SystemExit(f'identity staged usage count={s.count(usage_new)}')
s=s.replace(usage_new,usage_old,1)

help_block='''"  --identity      Opt-in observed identity metadata from already-inspected handshake/control fields.\\n"\n"                  Requires --enterprise; values are pseudonymized/hash-only by default.\\n"\n"  --identity-raw  Explicit second opt-in allowing bounded readable identity values where supported.\\n"\n"                  Requires --identity; never exposes passwords, tickets, tokens or auth blobs.\\n"\n'''
if s.count(help_block) != 1:
    raise SystemExit(f'identity staged help block count={s.count(help_block)}')
s=s.replace(help_block,'',1)

ent_line='"  ENT|mac|src_ip|dst_ip|protocol|fingerprint[|routed]\\n\\n"\n'
insert='''"  ENT|mac|src_ip|dst_ip|protocol|fingerprint[|routed]\\n"\n"  IDENT|mac|src_ip|protocol|type|identity[|routed]  (--identity only)\\n\\n"\n"IDENTITY OPTIONS (explicit opt-in; no generic payload scanning):\\n"\n"  --identity      Observed identity metadata from already-inspected handshake/control fields.\\n"\n"                  Requires --enterprise; pseudonymized/hash-only by default.\\n"\n"  --identity-raw  Second opt-in for bounded readable identity values where supported.\\n"\n"                  Requires --identity; never passwords, tickets, tokens or auth blobs.\\n\\n"\n'''
if s.count(ent_line) != 1:
    raise SystemExit(f'identity output anchor count={s.count(ent_line)}')
s=s.replace(ent_line,insert,1)
p.write_text(s)
print('split identity help from legacy printf')
