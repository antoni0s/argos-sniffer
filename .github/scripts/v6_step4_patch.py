from pathlib import Path
import textwrap


def replace_once(s: str, old: str, new: str, label: str) -> str:
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected one match, found {n}")
    return s.replace(old, new, 1)


PORTS_HEADER = r'''#ifndef ARGOS_ENTERPRISE_PORTS_H
#define ARGOS_ENTERPRISE_PORTS_H

#include <stddef.h>
#include <stdint.h>

/* Single source of truth shared by the enterprise parser admission checks and
 * the vector-aware kernel BPF builder. Keep these lists limited to protocols
 * for which Argos has a bounded parser. */
static const uint16_t ARGOS_ENTERPRISE_TCP_PORTS[] = {
    22, 88, 111, 179, 445, 502, 631, 1433, 1521, 2000, 2049,
    3260, 3306, 3389, 5060, 5432, 9100, 44818
};
static const uint16_t ARGOS_ENTERPRISE_UDP_PORTS[] = {
    88, 111, 161, 162, 389, 427, 623, 2049, 5060, 5678, 47808, 44818
};
#define ARGOS_ENTERPRISE_TCP_PORT_COUNT (sizeof(ARGOS_ENTERPRISE_TCP_PORTS) / sizeof(ARGOS_ENTERPRISE_TCP_PORTS[0]))
#define ARGOS_ENTERPRISE_UDP_PORT_COUNT (sizeof(ARGOS_ENTERPRISE_UDP_PORTS) / sizeof(ARGOS_ENTERPRISE_UDP_PORTS[0]))

#endif /* ARGOS_ENTERPRISE_PORTS_H */
'''


BPF_HEADER = r'''#ifndef ARGOS_BPF_H
#define ARGOS_BPF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include "argos_enterprise_ports.h"

#define ARGOS_BPF_MAX_INSNS 256U
#define ARGOS_BPF_PASS 0x0000ffffU
#define ARGOS_BPF_DROP 0U
#define ARGOS_TCP_CONTROL_MASK 0x07U /* FIN|SYN|RST */

typedef struct {
    uint8_t syn, multi, dhcp, netbios, dns, http, tls, l2, ipv6, enterprise;
} argos_bpf_config_t;

typedef struct {
    struct sock_filter code[ARGOS_BPF_MAX_INSNS];
    unsigned short len;
} argos_bpf_program_t;

static inline int abpf_stmt(argos_bpf_program_t *p, unsigned short code, uint32_t k) {
    if (!p || p->len >= ARGOS_BPF_MAX_INSNS) return 0;
    p->code[p->len++] = (struct sock_filter){code, 0, 0, k};
    return 1;
}

static inline int abpf_jump(argos_bpf_program_t *p, unsigned short code, uint32_t k,
                            uint8_t jt, uint8_t jf) {
    if (!p || p->len >= ARGOS_BPF_MAX_INSNS) return 0;
    p->code[p->len++] = (struct sock_filter){code, jt, jf, k};
    return 1;
}

static inline int abpf_pass_ethertype(argos_bpf_program_t *p, uint16_t type) {
    return abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, type, 0, 1) &&
           abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS);
}

static inline int abpf_add_port(uint16_t *ports, size_t *count, size_t cap, uint16_t port) {
    if (!ports || !count) return 0;
    for (size_t i = 0; i < *count; ++i) if (ports[i] == port) return 1;
    if (*count >= cap) return 0;
    ports[(*count)++] = port;
    return 1;
}

static inline int argos_bpf_build(const argos_bpf_config_t *cfg, argos_bpf_program_t *p) {
    if (!cfg || !p) return 0;
    memset(p, 0, sizeof(*p));

    uint16_t td[64], ts[64], ud[64], us[64];
    size_t td_n = 0, ts_n = 0, ud_n = 0, us_n = 0;
#define ADD(set,n,val) do { if (!abpf_add_port((set), &(n), sizeof(set)/sizeof((set)[0]), (uint16_t)(val))) return 0; } while (0)
#define EMIT(x) do { if (!(x)) return 0; } while (0)

    if (cfg->http) { ADD(td, td_n, 80); ADD(td, td_n, 8080); }
    if (cfg->tls)  { ADD(td, td_n, 443); ADD(ud, ud_n, 443); }
    if (cfg->dhcp) { ADD(ud, ud_n, 67); ADD(us, us_n, 67); }
    if (cfg->netbios) { ADD(ud, ud_n, 137); ADD(us, us_n, 137); }
    if (cfg->dns) { ADD(ud, ud_n, 53); ADD(us, us_n, 53); }
    if (cfg->multi) {
        ADD(ud, ud_n, 1900); ADD(us, us_n, 1900);
        ADD(ud, ud_n, 3702); ADD(us, us_n, 3702);
        ADD(ud, ud_n, 5353); ADD(us, us_n, 5353);
    }
    if (cfg->enterprise) {
        for (size_t i = 0; i < ARGOS_ENTERPRISE_TCP_PORT_COUNT; ++i) {
            ADD(td, td_n, ARGOS_ENTERPRISE_TCP_PORTS[i]);
            ADD(ts, ts_n, ARGOS_ENTERPRISE_TCP_PORTS[i]);
        }
        for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i) {
            ADD(ud, ud_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);
            ADD(us, us_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);
        }
    }

    const int need_tcp = cfg->syn || td_n || ts_n;
    const int need_udp = ud_n || us_n;
    const int need_ipv4 = need_tcp || need_udp || cfg->enterprise;

    /* Tagged/PPPoE frames remain conservative pass-through because classic
     * BPF cannot cheaply follow arbitrary stacked encapsulation offsets. */
    EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_ABS, 12));
    if (cfg->l2) {
        EMIT(abpf_pass_ethertype(p, 0x0806)); /* ARP */
        EMIT(abpf_pass_ethertype(p, 0x88cc)); /* LLDP */
    }
    if (cfg->enterprise) {
        EMIT(abpf_pass_ethertype(p, 0x888e)); /* EAPoL */
        EMIT(abpf_pass_ethertype(p, 0x8892)); /* PROFINET */
    }
    EMIT(abpf_pass_ethertype(p, 0x8100)); /* VLAN */
    EMIT(abpf_pass_ethertype(p, 0x88a8)); /* QinQ */
    EMIT(abpf_pass_ethertype(p, 0x8864)); /* PPPoE session */
    if (cfg->ipv6) EMIT(abpf_pass_ethertype(p, 0x86dd));
    if (cfg->enterprise) {
        /* IEEE 802.3 length field <=1500: CDP/EDP/FDP/IS-IS LLC/SNAP. */
        EMIT(abpf_jump(p, BPF_JMP | BPF_JGT | BPF_K, 1500, 1, 0));
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
    }
    if (!need_ipv4) {
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
        return p->len > 0;
    }

    /* Untagged IPv4 only beyond this point. */
    EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 1, 0));
    EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
    EMIT(abpf_stmt(p, BPF_LD | BPF_B | BPF_ABS, 23));

    size_t tcp_ja = (size_t)-1, udp_ja = (size_t)-1;
    if (need_tcp) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 1));
        tcp_ja = p->len; EMIT(abpf_stmt(p, BPF_JMP | BPF_JA, 0));
    }
    if (need_udp) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 1));
        udp_ja = p->len; EMIT(abpf_stmt(p, BPF_JMP | BPF_JA, 0));
    }
    if (cfg->enterprise) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 89, 0, 1));
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
    }
    EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));

    if (need_tcp) {
        size_t tcp_start = p->len;
        p->code[tcp_ja].k = (uint32_t)(tcp_start - tcp_ja - 1U);
        EMIT(abpf_stmt(p, BPF_LDX | BPF_B | BPF_MSH, 14));
        if (cfg->syn) {
            EMIT(abpf_stmt(p, BPF_LD | BPF_B | BPF_IND, 27));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JSET | BPF_K, ARGOS_TCP_CONTROL_MASK, 0, 1));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
        }
        if (td_n || ts_n) {
            /* Reject zero-payload ACK/window-update traffic before port tests. */
            EMIT(abpf_stmt(p, BPF_STX, 0));
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_ABS, 16));
            EMIT(abpf_stmt(p, BPF_ST, 1));
            EMIT(abpf_stmt(p, BPF_LD | BPF_B | BPF_IND, 26));
            EMIT(abpf_stmt(p, BPF_ALU | BPF_AND | BPF_K, 0xf0));
            EMIT(abpf_stmt(p, BPF_ALU | BPF_RSH | BPF_K, 2));
            EMIT(abpf_stmt(p, BPF_MISC | BPF_TAX, 0));
            EMIT(abpf_stmt(p, BPF_LD | BPF_W | BPF_MEM, 0));
            EMIT(abpf_stmt(p, BPF_ALU | BPF_ADD | BPF_X, 0));
            EMIT(abpf_stmt(p, BPF_MISC | BPF_TAX, 0));
            EMIT(abpf_stmt(p, BPF_LD | BPF_W | BPF_MEM, 1));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JGT | BPF_X, 0, 1, 0));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
            EMIT(abpf_stmt(p, BPF_LDX | BPF_W | BPF_MEM, 0));
            if (td_n) {
                EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 16));
                for (size_t i = 0; i < td_n; ++i) {
                    EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, td[i], 0, 1));
                    EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
                }
            }
            if (ts_n) {
                EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 14));
                for (size_t i = 0; i < ts_n; ++i) {
                    EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ts[i], 0, 1));
                    EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
                }
            }
        }
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
    }

    if (need_udp) {
        size_t udp_start = p->len;
        p->code[udp_ja].k = (uint32_t)(udp_start - udp_ja - 1U);
        EMIT(abpf_stmt(p, BPF_LDX | BPF_B | BPF_MSH, 14));
        if (ud_n) {
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 16));
            for (size_t i = 0; i < ud_n; ++i) {
                EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ud[i], 0, 1));
                EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
            }
        }
        if (us_n) {
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 14));
            for (size_t i = 0; i < us_n; ++i) {
                EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, us[i], 0, 1));
                EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
            }
        }
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
    }

#undef ADD
#undef EMIT
    return p->len > 0 && p->len <= ARGOS_BPF_MAX_INSNS;
}

static inline int argos_bpf_attach(int sock, const argos_bpf_config_t *cfg) {
    argos_bpf_program_t built;
    if (!argos_bpf_build(cfg, &built)) return -1;
    struct sock_fprog prog;
    prog.len = built.len;
    prog.filter = built.code;
    return setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
}

#endif /* ARGOS_BPF_H */
'''


DYNAMIC_BPF_TEST = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_bpf.h"

static uint16_t be16(const unsigned char *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static uint32_t be32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint32_t load_n(const unsigned char *pkt, size_t len, size_t off, unsigned size) {
    if (off + size > len) return 0;
    if (size == 1U) return pkt[off];
    if (size == 2U) return be16(pkt + off);
    return be32(pkt + off);
}

static uint32_t run_bpf(const argos_bpf_program_t *p, const unsigned char *pkt, size_t len) {
    uint32_t A = 0, X = 0, M[16] = {0}; size_t pc = 0;
    while (p && pc < p->len) {
        struct sock_filter in = p->code[pc];
        unsigned cls = BPF_CLASS(in.code), mode = BPF_MODE(in.code), size = BPF_SIZE(in.code);
        unsigned bytes = size == BPF_B ? 1U : size == BPF_H ? 2U : 4U;
        if (cls == BPF_LD) {
            if (mode == BPF_ABS) A = load_n(pkt, len, in.k, bytes);
            else if (mode == BPF_IND) A = load_n(pkt, len, (size_t)X + in.k, bytes);
            else if (mode == BPF_MEM && in.k < 16U) A = M[in.k]; else return 0;
            ++pc; continue;
        }
        if (cls == BPF_LDX) {
            if (mode == BPF_MSH && size == BPF_B) X = 4U * (load_n(pkt, len, in.k, 1U) & 0x0fU);
            else if (mode == BPF_MEM && in.k < 16U) X = M[in.k]; else return 0;
            ++pc; continue;
        }
        if (cls == BPF_ST) { if (in.k >= 16U) return 0; M[in.k] = A; ++pc; continue; }
        if (cls == BPF_STX) { if (in.k >= 16U) return 0; M[in.k] = X; ++pc; continue; }
        if (cls == BPF_ALU) {
            unsigned op = BPF_OP(in.code); uint32_t rhs = BPF_SRC(in.code) == BPF_X ? X : in.k;
            if (op == BPF_ADD) A += rhs; else if (op == BPF_AND) A &= rhs; else if (op == BPF_RSH) A >>= rhs; else return 0;
            ++pc; continue;
        }
        if (cls == BPF_MISC) { if (in.code == (BPF_MISC | BPF_TAX)) X = A; else return 0; ++pc; continue; }
        if (cls == BPF_JMP) {
            unsigned op = BPF_OP(in.code);
            if (op == BPF_JA) { pc += (size_t)in.k + 1U; continue; }
            uint32_t rhs = BPF_SRC(in.code) == BPF_X ? X : in.k;
            int yes = op == BPF_JEQ ? A == rhs : op == BPF_JGT ? A > rhs : op == BPF_JSET ? (A & rhs) != 0U : 0;
            pc += (size_t)(yes ? in.jt : in.jf) + 1U; continue;
        }
        if (cls == BPF_RET) return BPF_RVAL(in.code) == BPF_A ? A : in.k;
        return 0;
    }
    return 0;
}

static void put16(unsigned char *p, uint16_t v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static size_t tcp4(unsigned char *p, uint16_t sport, uint16_t dport, uint8_t flags, unsigned payload) {
    size_t n = 14U + 20U + 20U + payload; memset(p, 0, n);
    put16(p + 12, 0x0800); p[14] = 0x45; put16(p + 16, (uint16_t)(40U + payload)); p[23] = 6;
    put16(p + 34, sport); put16(p + 36, dport); p[46] = 0x50; p[47] = flags; return n;
}
static size_t udp4(unsigned char *p, uint16_t sport, uint16_t dport, unsigned payload) {
    size_t n = 14U + 20U + 8U + payload; memset(p, 0, n);
    put16(p + 12, 0x0800); p[14] = 0x45; put16(p + 16, (uint16_t)(28U + payload)); p[23] = 17;
    put16(p + 34, sport); put16(p + 36, dport); put16(p + 38, (uint16_t)(8U + payload)); return n;
}
static size_t proto4(unsigned char *p, uint8_t proto) {
    memset(p, 0, 64); put16(p + 12, 0x0800); p[14] = 0x45; put16(p + 16, 20); p[23] = proto; return 34;
}
static size_t eth(unsigned char *p, uint16_t type) { memset(p, 0, 64); put16(p + 12, type); return 64; }
static void expect(int ok, const char *what) { if (!ok) { fprintf(stderr, "FAIL: %s\n", what); exit(1); } }
static int pass(const argos_bpf_program_t *p, const unsigned char *pkt, size_t n) { return run_bpf(p, pkt, n) != 0U; }

int main(void) {
    unsigned char pkt[256]; argos_bpf_program_t p; argos_bpf_config_t c;
    memset(&c, 0, sizeof(c)); c.dns = 1; expect(argos_bpf_build(&c, &p), "build DNS");
    expect(pass(&p, pkt, udp4(pkt, 50000, 53, 20)), "DNS query passes");
    expect(pass(&p, pkt, udp4(pkt, 53, 50000, 20)), "DNS response passes");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 5353, 20)), "mDNS drops in DNS-only mode");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 443, 0x10, 20)), "TLS drops in DNS-only mode");

    memset(&c, 0, sizeof(c)); c.http = 1; expect(argos_bpf_build(&c, &p), "build HTTP");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 80, 0x18, 20)), "HTTP payload passes");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 80, 0x10, 0)), "HTTP empty ACK drops");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 443, 0x18, 20)), "TLS port drops in HTTP-only mode");

    memset(&c, 0, sizeof(c)); c.syn = 1; expect(argos_bpf_build(&c, &p), "build SYN");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 65000, 0x02, 0)), "arbitrary TCP SYN passes");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 65000, 0x10, 20)), "non-control TCP drops in SYN-only mode");

    memset(&c, 0, sizeof(c)); c.l2 = 1; expect(argos_bpf_build(&c, &p), "build L2");
    expect(pass(&p, pkt, eth(pkt, 0x0806)), "ARP passes in L2 mode");
    expect(pass(&p, pkt, eth(pkt, 0x88cc)), "LLDP passes in L2 mode");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 53, 20)), "IPv4 DNS drops in L2-only mode");
    expect(pass(&p, pkt, eth(pkt, 0x8100)), "VLAN remains conservative pass-through");

    memset(&c, 0, sizeof(c)); c.tls = 1; expect(argos_bpf_build(&c, &p), "build TLS");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 443, 0x18, 20)), "TLS ClientHello port passes");
    expect(pass(&p, pkt, udp4(pkt, 50000, 443, 1200)), "QUIC destination 443 passes");
    expect(!pass(&p, pkt, udp4(pkt, 443, 50000, 1200)), "QUIC server direction drops in client-only TLS mode");

    memset(&c, 0, sizeof(c)); c.enterprise = 1; c.ipv6 = 1; expect(argos_bpf_build(&c, &p), "build enterprise");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 0x18, 24)), "EtherNet/IP TCP/44818 passes");
    expect(pass(&p, pkt, tcp4(pkt, 44818, 50000, 0x18, 24)), "EtherNet/IP TCP response passes");
    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");
    expect(pass(&p, pkt, proto4(pkt, 89)), "OSPF passes");
    expect(pass(&p, pkt, eth(pkt, 100)), "802.3 LLC enterprise discovery passes");
    expect(pass(&p, pkt, eth(pkt, 0x86dd)), "IPv6 passes when enabled");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 25, 0x18, 20)), "unparsed enterprise TCP port drops");

    puts("dynamic BPF functional matrix: PASS");
    return 0;
}
'''


Path('src/argos_enterprise_ports.h').write_text(PORTS_HEADER)
Path('src/argos_bpf.h').write_text(BPF_HEADER)
Path('tests/test_dynamic_bpf.c').write_text(DYNAMIC_BPF_TEST)

# Enterprise parser: one shared port source and the missing TCP/44818 CIP path.
p = Path('src/argos_enterprise.h')
s = p.read_text()
s = replace_once(s, '#define ARGOS_ENTERPRISE_H\n',
                 '#define ARGOS_ENTERPRISE_H\n\n#include "argos_enterprise_ports.h"\n', 'enterprise ports include')
h0 = s.index('static inline int argos_enterprise_tcp_port(')
h1 = s.index('\n\nstatic inline int ae_rpc(', h0)
helpers = '''static inline int argos_enterprise_tcp_port(uint16_t sport, uint16_t dport) {
    for (size_t i = 0; i < ARGOS_ENTERPRISE_TCP_PORT_COUNT; ++i)
        if (sport == ARGOS_ENTERPRISE_TCP_PORTS[i] || dport == ARGOS_ENTERPRISE_TCP_PORTS[i]) return 1;
    return 0;
}

static inline int argos_enterprise_udp_port(uint16_t sport, uint16_t dport) {
    for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i)
        if (sport == ARGOS_ENTERPRISE_UDP_PORTS[i] || dport == ARGOS_ENTERPRISE_UDP_PORTS[i]) return 1;
    return 0;
}'''
s = s[:h0] + helpers + s[h1:]
s = replace_once(s,
    'static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r);\n',
    'static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r);\n'
    'static inline int ae_cip(const unsigned char *p, int len, argos_enterprise_result_t *r);\n',
    'CIP forward declaration')
tcp_fn = s.index('static inline int argos_enterprise_parse_tcp(')
sel0 = s.index('    uint16_t port = dport;', tcp_fn)
sw = s.index('    switch (port) {', sel0)
s = s[:sel0] + '''    uint16_t port = dport;
    if (!argos_enterprise_tcp_port(sport, dport)) return 0;
    if (!argos_enterprise_tcp_port(0, port)) port = sport;

''' + s[sw:]
sw = s.index('    switch (port) {', tcp_fn)
default = s.index('        default: return 0;', sw)
s = s[:default] + '        case 44818: return ae_cip(p, len, r);\n' + s[default:]
filt = s.index('#ifndef ARGOS_PORTABLE_TEST\n/* Enterprise-mode kernel prefilter.')
s = s[:filt] + '#endif /* ARGOS_ENTERPRISE_H */\n'
p.write_text(s)

# Main source: replace both static prefilters with one vector-aware builder.
p = Path('src/argos-sniffer.c')
s = p.read_text()
s = replace_once(s,
    '#include "argos_enterprise.h"\n#ifndef ARGOS_PORTABLE_TEST\n#include "argos_netlink.h"\n#endif\n',
    '#include "argos_enterprise.h"\n#ifndef ARGOS_PORTABLE_TEST\n#include "argos_netlink.h"\n#include "argos_bpf.h"\n#endif\n',
    'BPF include')
f0 = s.index('/* ============================================================================\n * SECTION: Kernel AF_PACKET Prefilter')
m0 = s.index('#ifndef ARGOS_PORTABLE_TEST\nint main(int argc, char *argv[]) {', f0)
s = s[:f0] + '''/* ============================================================================
 * SECTION: Kernel AF_PACKET Prefilter
 * Vector-aware classic-BPF construction lives in argos_bpf.h so the generated
 * program can be regression-tested against synthetic packet fixtures.
 * ============================================================================ */
''' + s[m0:]
install = s.index('    install_signal_handlers();')
cfg = '''    argos_bpf_config_t bpf_cfg = {
        .syn = (uint8_t)(opt_syn != 0), .multi = (uint8_t)(opt_multi != 0),
        .dhcp = (uint8_t)(opt_dhcp != 0), .netbios = (uint8_t)(opt_netbios != 0),
        .dns = (uint8_t)(opt_dns != 0), .http = (uint8_t)(opt_http != 0),
        .tls = (uint8_t)(opt_tls != 0), .l2 = (uint8_t)(opt_l2 != 0),
        .ipv6 = (uint8_t)(opt_v6 != 0), .enterprise = (uint8_t)(opt_enterprise != 0)
    };

'''
s = s[:install] + cfg + s[install:]
a0 = s.index('        if (active_ifaces[num_ifaces].type == LINK_ETHERNET && !filter_mode1.is_active) {')
a1 = s.index('\n\n        if (opt_promisc && active_ifaces[num_ifaces].type == LINK_ETHERNET)', a0)
attach = '''        if (active_ifaces[num_ifaces].type == LINK_ETHERNET && !filter_mode1.is_active) {
            if (argos_bpf_attach(sock, &bpf_cfg) < 0) {
                fprintf(stderr, "warning: unable to attach vector-aware AF_PACKET prefilter on %s: %s\\n",
                        token, strerror(errno));
            }
        }'''
s = s[:a0] + attach + s[a1:]
p.write_text(s)

# Existing enterprise parser suite gains direct TCP/44818 regression coverage.
p = Path('tests/test_enterprise.c')
s = p.read_text()
marker = 'static void test_elephant_fast_drop(void) {\n'
cip_test = '''static void test_cip_tcp(void) {
    unsigned char p[24] = {0};
    argos_enterprise_result_t r;
    p[0] = 0x63U; p[1] = 0x00U; /* ListIdentity command 0x0063 LE */
    check(argos_enterprise_tcp_port(40000, 44818) == 1, "EtherNet/IP TCP port admitted");
    check(argos_enterprise_parse_tcp(40000, 44818, p, (int)sizeof(p), &r) == 1, "EtherNet/IP TCP ListIdentity parsed");
    check(strcmp(r.proto, "ethernet-ip") == 0, "EtherNet/IP TCP protocol label");
}

'''
s = replace_once(s, marker, cip_test + marker, 'CIP TCP fixture')
s = replace_once(s, '    test_fdp();\n    test_elephant_fast_drop();\n',
                 '    test_fdp();\n    test_cip_tcp();\n    test_elephant_fast_drop();\n',
                 'CIP TCP invocation')
p.write_text(s)

print('step4 patch applied')
