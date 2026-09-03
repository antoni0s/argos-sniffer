from pathlib import Path

ROOT = Path('.')
main = ROOT / 'src/argos-sniffer.c'
out = ROOT / 'src/argos_fhrp.h'
parts = [
    ('VRRP', ROOT / 'src/argos_vrrp.h'),
    ('HSRP', ROOT / 'src/argos_hsrp.h'),
]
tests = [
    (ROOT / 'tests/test_vrrp.c', 'argos_vrrp.h'),
    (ROOT / 'tests/test_hsrp1.c', 'argos_hsrp.h'),
    (ROOT / 'tests/test_hsrp2.c', 'argos_hsrp.h'),
]

if out.exists():
    raise SystemExit('src/argos_fhrp.h already exists')
for _, p in parts:
    if not p.exists():
        raise SystemExit(f'missing expected source header: {p}')


def body_of(path: Path) -> str:
    lines = path.read_text().splitlines()
    if len(lines) < 3 or not lines[0].startswith('#ifndef ARGOS_') or not lines[1].startswith('#define ARGOS_'):
        raise SystemExit(f'unexpected include guard in {path}')
    lines = lines[2:]
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines or not lines[-1].lstrip().startswith('#endif'):
        raise SystemExit(f'missing final endif in {path}')
    lines.pop()
    return '\n'.join(lines).strip() + '\n'

chunks = [
    '#ifndef ARGOS_FHRP_H\n#define ARGOS_FHRP_H\n',
    '\n/* Argos First-Hop Redundancy Protocol engine.  VRRP and HSRP share the\n'
    ' * same control-plane responsibility but retain independent parsers and\n'
    ' * wire-format validation.  Telemetry remains a runtime concern. */\n',
]
for title, path in parts:
    chunks += [
        '\n/* ========================================================================== */\n',
        f'/* {title:<74} */\n',
        '/* ========================================================================== */\n',
        body_of(path),
    ]
chunks.append('\n#endif /* ARGOS_FHRP_H */\n')
out.write_text(''.join(chunks))

s = main.read_text()
expected = '#include "argos_vrrp.h"\n#include "argos_hsrp.h"\n'
if expected not in s:
    raise SystemExit('expected contiguous FHRP includes missing from main')
main.write_text(s.replace(expected, '#include "argos_fhrp.h"\n', 1))

# Preserve every fixture byte except the include path.
for path, old_header in tests:
    text = path.read_text()
    old = f'#include "../src/{old_header}"'
    if text.count(old) != 1:
        raise SystemExit(f'expected exactly one include in {path}')
    path.write_text(text.replace(old, '#include "../src/argos_fhrp.h"', 1))

for _, path in parts:
    path.unlink()
