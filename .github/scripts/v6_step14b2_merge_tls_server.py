from pathlib import Path

tls = Path('src/argos_tls.h')
server = Path('src/argos_tls_server.h')
main = Path('src/argos-sniffer.c')
test = Path('tests/test_tls_server.c')

t = tls.read_text()
srv = server.read_text()
s = main.read_text()
tst = test.read_text()

if '#include "argos_tls_server.h"' not in s:
    raise SystemExit('expected TLS server include missing from main')
if '#include "../src/argos_tls_server.h"' not in tst:
    raise SystemExit('expected TLS server include missing from fixture')
if 'argos_tls_server_result_t' in t:
    raise SystemExit('ServerHello engine already merged')

start = srv.index('typedef struct {')
end = srv.rindex('#endif /* ARGOS_TLS_SERVER_H */')
body = srv[start:end].rstrip()
body = '\n'.join(line.rstrip() for line in body.splitlines())

end_marker = '#endif /* ARGOS_TLS_H */'
if end_marker not in t:
    raise SystemExit('TLS engine guard missing')
section = '''\n\n/* ========================================================================== */\n/* TLS ServerHello / ATS1 engine                                              */\n/* ========================================================================== */\n'''
t = t.replace(end_marker, section + body + '\n\n' + end_marker, 1)
s = s.replace('#include "argos_tls_server.h"\n', '', 1)
tst = tst.replace('#include "../src/argos_tls_server.h"\n', '#include "../src/argos_tls.h"\n', 1)

tls.write_text(t)
main.write_text(s)
test.write_text(tst)
server.unlink()
