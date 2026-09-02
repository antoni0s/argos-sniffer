from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


# One shared policy for implicit/direct TLS ports. STARTTLS ports such as 587
# are intentionally excluded until protocol-upgrade state exists.
tls_ports = '''#ifndef ARGOS_TLS_PORTS_H
#define ARGOS_TLS_PORTS_H

#include <stddef.h>
#include <stdint.h>

static const uint16_t ARGOS_TLS_TCP_PORTS[] = {
    443U,   /* HTTPS */
    465U,   /* implicit TLS SMTP / submissions */
    853U,   /* DNS over TLS */
    993U,   /* IMAPS */
    995U,   /* POP3S */
    8443U   /* common alternate HTTPS */
};
#define ARGOS_TLS_TCP_PORT_COUNT (sizeof(ARGOS_TLS_TCP_PORTS) / sizeof(ARGOS_TLS_TCP_PORTS[0]))
#define ARGOS_QUIC_UDP_PORT 443U

static inline int argos_tls_tcp_port(uint16_t port) {
    for (size_t i = 0; i < ARGOS_TLS_TCP_PORT_COUNT; ++i)
        if (ARGOS_TLS_TCP_PORTS[i] == port) return 1;
    return 0;
}

#endif /* ARGOS_TLS_PORTS_H */
'''
Path('src/argos_tls_ports.h').write_text(tls_ports)

# Dynamic BPF uses the same policy as userspace.
p = Path('src/argos_bpf.h')
s = p.read_text()
s = replace_once(s,
    '#include "argos_enterprise_ports.h"\n',
    '#include "argos_enterprise_ports.h"\n#include "argos_tls_ports.h"\n',
    'BPF TLS include')
s = replace_once(s,
    '    if (cfg->tls)  { ADD(td, td_n, 443); ADD(ud, ud_n, 443); }\n',
    '    if (cfg->tls) {\n'
    '        for (size_t i = 0; i < ARGOS_TLS_TCP_PORT_COUNT; ++i) ADD(td, td_n, ARGOS_TLS_TCP_PORTS[i]);\n'
    '        ADD(ud, ud_n, ARGOS_QUIC_UDP_PORT);\n'
    '    }\n',
    'BPF TLS policy')
p.write_text(s)

# Userspace TCP admission, app-flow completion and parser dispatch share policy.
p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_enterprise.h"\n',
    '#include "argos_tls_ports.h"\n#include "argos_enterprise.h"\n',
    'sniffer TLS include')

s = replace_once(s,
    '    if (dport == 443U) {\n'
    '        if (payload_len < 9 || payload[0] != 0x16 || payload[5] != 0x01) return 0;\n',
    '    if (argos_tls_tcp_port(dport)) {\n'
    '        if (payload_len < 9 || payload[0] != 0x16 || payload[5] != 0x01) return 0;\n',
    'app-flow TLS completion')

s = replace_once(s,
    '                                   (opt_tls && dport == 443U) ||\n'
    '                                   (opt_enterprise && argos_enterprise_tcp_port(sport, dport));\n',
    '                                   (opt_tls && argos_tls_tcp_port(dport)) ||\n'
    '                                   (opt_enterprise && argos_enterprise_tcp_port(sport, dport));\n',
    'TCP relevance')

s = replace_once(s,
    '                                ((opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                 (opt_tls && dport == 443U) || enterprise_tcp);\n',
    '                                ((opt_http && (dport == 80U || dport == 8080U)) ||\n'
    '                                 (opt_tls && argos_tls_tcp_port(dport)) || enterprise_tcp);\n',
    'app tracking')

s = replace_once(s,
    '                else if (opt_tls && dport == 443 && payload_len > 44) {\n'
    '                    parse_tls_sni(buffer + payload_offset, payload_len, mac_str, src_ip_str, dst_ip_str, dport, routed_str, opt_tls_rl);\n'
    '                }\n',
    '                else if (opt_tls && argos_tls_tcp_port(dport) && payload_len > 44) {\n'
    '                    parse_tls_sni(buffer + payload_offset, payload_len, mac_str, src_ip_str, dst_ip_str, dport, routed_str, opt_tls_rl);\n'
    '                }\n',
    'TLS parser dispatch')

# Preserve the existing TLS wire format. DoT is an additive classification
# emitted only after a valid ClientHello has been parsed on TCP/853.
s = replace_once(s,
    '    if (!dedup_should_suppress(mac, "TLS", fp_sig, rl_enabled)) {\n'
    '        emit_telemetry("TLS|%s|%s|%s|%u|%s|%s|%s%s\\n", mac, src_ip, dst_ip, dport, sni, ja4_full, alpn, routed_str);\n'
    '    }\n',
    '    if (!dedup_should_suppress(mac, "TLS", fp_sig, rl_enabled)) {\n'
    '        emit_telemetry("TLS|%s|%s|%s|%u|%s|%s|%s%s\\n", mac, src_ip, dst_ip, dport, sni, ja4_full, alpn, routed_str);\n'
    '    }\n'
    '    if (dport == 853U && !dedup_should_suppress(mac, "DOT", fp_sig, rl_enabled)) {\n'
    '        emit_telemetry("DOT|%s|%s|%s|%s|%s|%s%s\\n", mac, src_ip, dst_ip, sni, ja4_full, alpn, routed_str);\n'
    '    }\n',
    'DoT telemetry')

s = replace_once(s,
    '"  -t / -T         TLS ClientHello (SNI, JA4, ALPN) & QUIC extraction (port 443)\\n"\n',
    '"  -t / -T         TLS ClientHello (443/465/853/993/995/8443) + QUIC UDP/443\\n"\n'
    '"                  TCP/853 also emits additive DNS-over-TLS (DOT) classification\\n"\n',
    'TLS help')

s = replace_once(s,
    '"  TLS|mac|src_ip|dst_ip|dst_port|sni|ja4_fingerprint|alpn[|routed]\\n"\n'
    '"  QUIC|mac|src_ip|dst_ip|dst_port|sni|version[|routed]\\n"\n',
    '"  TLS|mac|src_ip|dst_ip|dst_port|sni|ja4_fingerprint|alpn[|routed]\\n"\n'
    '"  DOT|mac|src_ip|dst_ip|sni|ja4_fingerprint|alpn[|routed]\\n"\n'
    '"  QUIC|mac|src_ip|dst_ip|dst_port|sni|version[|routed]\\n"\n',
    'DOT help')
p.write_text(s)

# Extend BPF regression matrix so only TCP implicit-TLS ports are broadened;
# QUIC stays UDP/443 and STARTTLS 587 remains out until stateful upgrade parsing.
p = Path('tests/test_dynamic_bpf.c')
s = p.read_text()
s = replace_once(s,
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 443, 0x18, 20)), "TLS ClientHello port passes");\n'
    '    expect(pass(&p, pkt, udp4(pkt, 50000, 443, 1200)), "QUIC destination 443 passes");\n'
    '    expect(!pass(&p, pkt, udp4(pkt, 443, 50000, 1200)), "QUIC server direction drops in client-only TLS mode");\n',
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 443, 0x18, 20)), "TLS HTTPS port passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 465, 0x18, 20)), "TLS SMTPS port passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 853, 0x18, 20)), "DNS-over-TLS port passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 993, 0x18, 20)), "TLS IMAPS port passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 995, 0x18, 20)), "TLS POP3S port passes");\n'
    '    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 0x18, 20)), "alternate HTTPS port passes");\n'
    '    expect(!pass(&p, pkt, tcp4(pkt, 50000, 587, 0x18, 20)), "STARTTLS 587 stays out of direct-TLS policy");\n'
    '    expect(pass(&p, pkt, udp4(pkt, 50000, 443, 1200)), "QUIC destination 443 passes");\n'
    '    expect(!pass(&p, pkt, udp4(pkt, 443, 50000, 1200)), "QUIC server direction drops in client-only TLS mode");\n'
    '    expect(!pass(&p, pkt, udp4(pkt, 50000, 853, 1200)), "DoT is TCP; UDP/853 drops in TLS mode");\n',
    'TLS BPF matrix')
p.write_text(s)

print('step5 multi-port TLS + DoT patch applied')
