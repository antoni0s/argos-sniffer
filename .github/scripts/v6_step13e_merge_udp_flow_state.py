from pathlib import Path

flow = Path('src/argos_flow_state.h')
udp = Path('src/argos_udp_suppress.h')
main = Path('src/argos-sniffer.c')
test = Path('tests/test_udp_suppress.c')

f = flow.read_text()
u = udp.read_text()
s = main.read_text()
t = test.read_text()

if '#include "argos_udp_suppress.h"' not in s:
    raise SystemExit('expected UDP suppress include missing from main')
if '#include "../src/argos_udp_suppress.h"' not in t:
    raise SystemExit('expected UDP suppress include missing from test')
if 'ARGOS_UDP_SUPPRESS_SLOTS' in f:
    raise SystemExit('UDP suppression already merged into flow-state')

start = u.index('#define ARGOS_UDP_SUPPRESS_SLOTS')
end = u.rindex('#endif')
body = u[start:end]
body = body.replace('static inline uint64_t argos_udp_suppress_hash_update(uint64_t h, const void *buf, size_t len) {\n    const uint8_t *p = (const uint8_t *)buf;\n    for (size_t i = 0; i < len; ++i) { h ^= p[i]; h *= 1099511628211ULL; }\n    return h;\n}\n\n', '')
body = body.replace('argos_udp_suppress_hash_update', 'argos_flow_hash_update')

marker = '\n#endif\n'
if marker not in f:
    raise SystemExit('flow-state endif marker missing')
f = f.replace(marker, '\n/* Fixed, allocation-free UDP class suppression state. This shares only the\n * generic tuple hashing primitive with TCP state; TTL and refresh semantics\n * remain intentionally independent. */\n' + body + marker, 1)

s = s.replace('#include "argos_udp_suppress.h"\n', '', 1)
t = t.replace('#include "../src/argos_udp_suppress.h"\n', '#include "../src/argos_flow_state.h"\n', 1)

flow.write_text(f)
main.write_text(s)
test.write_text(t)
udp.unlink()
