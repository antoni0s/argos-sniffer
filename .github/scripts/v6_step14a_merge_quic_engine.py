from pathlib import Path

quic = Path('src/argos_quic.h')
heavy = Path('src/argos_quic_heavy.h')
main = Path('src/argos-sniffer.c')

q = quic.read_text()
h = heavy.read_text()
s = main.read_text()

if '#include "argos_quic_heavy.h"' not in s:
    raise SystemExit('expected argos_quic_heavy.h include missing from main')
if '#define QUIC_STATE_SLOTS 64' in q:
    raise SystemExit('stateful QUIC already merged')

start = h.index('#define QUIC_STATE_SLOTS 64')
end = h.rindex('#endif /* ARGOS_QUIC_HEAVY_H */')
stateful = h[start:end].rstrip()
# Header-only engine: GC is used by the main program but not by every standalone
# QUIC fixture that includes this header. Keep strict -Werror builds clean.
stateful = stateful.replace('static void quic_heavy_gc(void)',
                            'static inline void quic_heavy_gc(void)', 1)

if '#include <time.h>' not in q:
    marker = '#include <stdlib.h>\n'
    if marker not in q:
        raise SystemExit('stdlib include marker missing in argos_quic.h')
    q = q.replace(marker, marker + '#include <time.h>\n', 1)

end_marker = '#endif /* ARGOS_QUIC_H */'
if end_marker not in q:
    raise SystemExit('argos_quic.h final guard missing')

section = '''\n\n/* ========================================================================== */\n/* Stateful QUIC engine                                                       */\n/*\n * Optional runtime layer used by -W. It deliberately shares the stateless\n * Initial crypto/VarInt primitives above, while retaining lazy allocation so\n * the default gateway footprint is unchanged.\n * ========================================================================== */\n'''
q = q.replace(end_marker, section + stateful + '\n\n' + end_marker, 1)
s = s.replace('#include "argos_quic_heavy.h"\n', '', 1)

quic.write_text(q)
main.write_text(s)
heavy.unlink()
