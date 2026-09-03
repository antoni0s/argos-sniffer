from pathlib import Path

ROOT = Path('.')
main = ROOT / 'src/argos-sniffer.c'
out = ROOT / 'src/argos_l2.h'
parts = [
    ('LLDP-MED', ROOT / 'src/argos_lldp_med.h'),
    ('LACP', ROOT / 'src/argos_lacp.h'),
    ('STP / RSTP / MSTP', ROOT / 'src/argos_stp.h'),
]
tests = [
    (ROOT / 'tests/test_lldp_med.c', 'argos_lldp_med.h'),
    (ROOT / 'tests/test_lacp.c', 'argos_lacp.h'),
    (ROOT / 'tests/test_stp.c', 'argos_stp.h'),
]

if out.exists():
    raise SystemExit('src/argos_l2.h already exists')
for _, p in parts:
    if not p.exists():
        raise SystemExit(f'missing expected source header: {p}')


def body_of(path: Path) -> str:
    lines = path.read_text().splitlines()
    # Remove only the outer include guard; retain includes and implementation.
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
    '#ifndef ARGOS_L2_H\n#define ARGOS_L2_H\n',
    '\n/* Argos infrastructure Layer-2 engine.  This module intentionally groups\n'
    ' * passive switching-control fingerprints that share the same L2 dispatch\n'
    ' * boundary.  Telemetry, deduplication and capture remain runtime concerns. */\n',
]
for title, path in parts:
    chunks.append('\n/* ========================================================================== */\n')
    chunks.append(f'/* {title:<74} */\n')
    chunks.append('/* ========================================================================== */\n')
    chunks.append(body_of(path))
chunks.append('\n#endif /* ARGOS_L2_H */\n')
out.write_text(''.join(chunks))

s = main.read_text()
expected = '#include "argos_lldp_med.h"\n#include "argos_lacp.h"\n#include "argos_stp.h"\n'
if expected not in s:
    raise SystemExit('expected contiguous L2 includes missing from main')
s = s.replace(expected, '#include "argos_l2.h"\n', 1)
main.write_text(s)

for path, old_header in tests:
    text = path.read_text()
    old = f'#include "../src/{old_header}"'
    if old not in text:
        raise SystemExit(f'expected include missing from {path}')
    path.write_text(text.replace(old, '#include "../src/argos_l2.h"', 1))

for _, path in parts:
    path.unlink()
