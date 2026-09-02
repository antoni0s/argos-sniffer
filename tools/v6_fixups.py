#!/usr/bin/env python3
from pathlib import Path

p = Path("src/argos_enterprise.h")
s = p.read_text(encoding="utf-8")
old = '            if (w < 0 || (size_t)w >= sizeof(value) - used) break; used += (size_t)w;\n'
new = ('            if (w < 0 || (size_t)w >= sizeof(value) - used) break;\n'
       '            used += (size_t)w;\n')
if s.count(old) != 1:
    raise SystemExit(f"SNMP indentation fix: expected one match, found {s.count(old)}")
s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8")
print("v6 parser fixups applied successfully")
