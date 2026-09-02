#ifndef ARGOS_BPF_H
#define ARGOS_BPF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/filter.h>

#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
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
