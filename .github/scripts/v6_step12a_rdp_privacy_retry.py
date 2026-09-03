from pathlib import Path

p = Path("src/argos_enterprise.h")
s = p.read_text()
old = '''    if (c) {\n        c += 16;\n        const unsigned char *e = ae_find(c, (int)((p + len) - c),\n'''
new = '''    if (c) {\n        c += 17; /* strlen("Cookie: mstshash=") */\n        const unsigned char *e = ae_find(c, (int)((p + len) - c),\n'''
if s.count(old) != 1:
    raise SystemExit(f"RDP staged offset anchor count={s.count(old)}")
p.write_text(s.replace(old, new, 1))
print("corrected staged RDP mstshash offset")
