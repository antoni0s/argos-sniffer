#ifndef ARGOS_BPF_H
#define ARGOS_BPF_H

#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/filter.h>

#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
#include "argos_enterprise_ports.h"
#include "argos_dispatch.h"
#include "argos_tls_ports.h"

#define ARGOS_BPF_MAX_INSNS 256U
#define ARGOS_BPF_PASS 0x0000ffffU
#define ARGOS_BPF_DROP 0U
#define ARGOS_TCP_CONTROL_MASK 0x07U /* FIN|SYN|RST */

typedef struct {
    argos_protocol_set_t protocols;
    uint16_t wireguard_port;
    uint16_t l2_routes;
    uint16_t l3_routes;
    uint16_t l4_routes;
    uint16_t transport_routes;
    uint8_t syn;
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

/* Project only fixed canonical control data. The BPF builder consumes protocol
 * bits at startup to construct exact port lists; packet execution never scans
 * the catalog or this bitmap. */
static inline void argos_bpf_config_compile(argos_bpf_config_t *cfg,
                                            const argos_dispatch_plan_t *plan,
                                            uint16_t wireguard_port) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    if (!plan) return;
    cfg->protocols = plan->protocols.enabled;
    cfg->syn = (uint8_t)argos_feature_selection_has(
        &plan->features, ARGOS_FEATURE_TCP_SYN);
    cfg->wireguard_port = argos_dispatch_protocol_enabled(
        plan, ARGOS_PROTOCOL_WIREGUARD) ? wireguard_port : 0U;
    cfg->l2_routes = plan->l2_routes;
    cfg->l3_routes = plan->l3_routes;
    cfg->l4_routes = plan->l4_routes;
    cfg->transport_routes = plan->transport_routes;
}

static inline int argos_bpf_protocol_enabled(const argos_bpf_config_t *cfg,
                                             argos_protocol_id_t protocol) {
    return cfg && argos_protocol_set_has(&cfg->protocols, protocol);
}

static inline int argos_bpf_build(const argos_bpf_config_t *cfg, argos_bpf_program_t *p) {
    if (!cfg || !p) return 0;
    memset(p, 0, sizeof(*p));

    uint16_t td[64], ts[64], ud[64], us[64];
    size_t td_n = 0, ts_n = 0, ud_n = 0, us_n = 0;
#define ADD(set,n,val) do { if (!abpf_add_port((set), &(n), sizeof(set)/sizeof((set)[0]), (uint16_t)(val))) return 0; } while (0)
#define EMIT(x) do { if (!(x)) return 0; } while (0)

#define HAS(protocol) argos_bpf_protocol_enabled(cfg, ARGOS_PROTOCOL_##protocol)
    if (HAS(HTTP)) { ADD(td, td_n, 80); ADD(td, td_n, 8080); }
    if (HAS(HTTP_PROXY)) {
        for (unsigned i = 0; i < sizeof(ARGOS_HTTP_PROXY_TCP_PORTS) / sizeof(ARGOS_HTTP_PROXY_TCP_PORTS[0]); ++i) {
            ADD(td, td_n, ARGOS_HTTP_PROXY_TCP_PORTS[i]);
            ADD(ts, ts_n, ARGOS_HTTP_PROXY_TCP_PORTS[i]);
        }
    }
    if (HAS(TLS)) {
        for (size_t i = 0; i < ARGOS_TLS_TCP_PORT_COUNT; ++i) {
            ADD(td, td_n, ARGOS_TLS_TCP_PORTS[i]);
            ADD(ts, ts_n, ARGOS_TLS_TCP_PORTS[i]);
        }
    }
    if (HAS(DOT)) { ADD(td, td_n, 853); ADD(ts, ts_n, 853); }
    if (HAS(QUIC))
        ADD(ud, ud_n, ARGOS_QUIC_UDP_PORT);
    if (HAS(DHCP)) { ADD(ud, ud_n, 67); ADD(us, us_n, 67); }
    if (HAS(NBNS)) { ADD(ud, ud_n, 137); ADD(us, us_n, 137); }
    if (HAS(DNS)) { ADD(ud, ud_n, 53); ADD(us, us_n, 53); }
    if (HAS(SSDP) || HAS(UPNP)) {
        ADD(ud, ud_n, 1900); ADD(us, us_n, 1900);
    }
    if (HAS(WSD)) {
        ADD(ud, ud_n, 3702); ADD(us, us_n, 3702);
    }
    if (HAS(MDNS)) {
        ADD(ud, ud_n, 5353); ADD(us, us_n, 5353);
    }
    if (HAS(PTP)) {
        ADD(ud, ud_n, 319); ADD(us, us_n, 319);
        ADD(ud, ud_n, 320); ADD(us, us_n, 320);
    }
    if (HAS(RIP)) {
        ADD(ud, ud_n, 520); ADD(us, us_n, 520);
        ADD(ud, ud_n, 521); ADD(us, us_n, 521);
    }
    argos_dispatch_plan_t transport_plan;
    memset(&transport_plan, 0, sizeof(transport_plan));
    transport_plan.protocols.enabled = cfg->protocols;
    transport_plan.transport_routes = cfg->transport_routes;
    for (size_t i = 0; i < ARGOS_ENTERPRISE_TCP_PORT_COUNT; ++i) {
        if (argos_dispatch_tcp_port_engine(
                &transport_plan, 0U, ARGOS_ENTERPRISE_TCP_PORTS[i]) <
            ARGOS_PROTOCOL_COUNT) {
            ADD(td, td_n, ARGOS_ENTERPRISE_TCP_PORTS[i]);
            ADD(ts, ts_n, ARGOS_ENTERPRISE_TCP_PORTS[i]);
        }
    }
    /* NTLM identity shares SMB's destination port but not its parser bit.
     * Add it after the canonical enterprise order so legacy work is unchanged. */
    if (HAS(NTLM)) ADD(td, td_n, 445);
    for (size_t i = 0; i < ARGOS_ENTERPRISE_UDP_PORT_COUNT; ++i) {
        if (ARGOS_ENTERPRISE_UDP_PORTS[i] == ARGOS_STUN_TURN_UDP_PORT) continue;
        if (argos_dispatch_udp_port_engine(
                &transport_plan, 0U, ARGOS_ENTERPRISE_UDP_PORTS[i]) <
            ARGOS_PROTOCOL_COUNT) {
            ADD(ud, ud_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);
            ADD(us, us_n, ARGOS_ENTERPRISE_UDP_PORTS[i]);
        }
    }
    if (cfg->wireguard_port != 0U && HAS(WIREGUARD)) {
        ADD(ud, ud_n, cfg->wireguard_port);
        ADD(us, us_n, cfg->wireguard_port);
    }

    const int stun_turn = HAS(STUN_TURN);
    const int need_tcp = (cfg->l4_routes & ARGOS_DISPATCH_L4_TCP) != 0U &&
                         (cfg->syn || td_n || ts_n);
    const int need_udp = (cfg->l4_routes & ARGOS_DISPATCH_L4_UDP) != 0U &&
                         (ud_n || us_n || stun_turn);
    const int need_ipv4 = (cfg->l3_routes & ARGOS_DISPATCH_L3_IPV4) != 0U;

    /* Tagged/PPPoE frames remain conservative pass-through because classic
     * BPF cannot cheaply follow arbitrary stacked encapsulation offsets. */
    EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_ABS, 12));
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_ARP)
        EMIT(abpf_pass_ethertype(p, 0x0806)); /* ARP */
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_LLDP)
        EMIT(abpf_pass_ethertype(p, 0x88cc)); /* LLDP / LLDP-MED */
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_SLOW)
        EMIT(abpf_pass_ethertype(p, 0x8809)); /* Slow Protocols / LACP */
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_EAPOL)
        EMIT(abpf_pass_ethertype(p, 0x888e)); /* EAPoL */
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_PROFINET)
        EMIT(abpf_pass_ethertype(p, 0x8892)); /* PROFINET */
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_PTP)
        EMIT(abpf_pass_ethertype(p, 0x88f7)); /* native IEEE 1588 PTP */
    EMIT(abpf_pass_ethertype(p, 0x8100)); /* VLAN */
    EMIT(abpf_pass_ethertype(p, 0x88a8)); /* QinQ */
    EMIT(abpf_pass_ethertype(p, 0x8864)); /* PPPoE session */
    if (cfg->l3_routes & ARGOS_DISPATCH_L3_IPV6)
        EMIT(abpf_pass_ethertype(p, 0x86dd));
    if (cfg->l2_routes & ARGOS_DISPATCH_L2_LLC) {
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
    if (cfg->l3_routes & ARGOS_DISPATCH_L3_IGMP) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1));
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
    }
    if (cfg->l3_routes & ARGOS_DISPATCH_L3_OSPF) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 89, 0, 1));
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
    }
    if (cfg->l3_routes & ARGOS_DISPATCH_L3_VRRP) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 112, 0, 1));
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
    }
    if (cfg->l3_routes & ARGOS_DISPATCH_L3_ESP) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 50, 0, 1));
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
    }
    if (cfg->l3_routes & ARGOS_DISPATCH_L3_AH) {
        EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 51, 0, 1));
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
        if (!cfg->syn && HAS(HTTP_PROXY)) {
            /* Admit generation boundaries only for the selected proxy ports. */
            const unsigned count = sizeof(ARGOS_HTTP_PROXY_TCP_PORTS) / sizeof(ARGOS_HTTP_PROXY_TCP_PORTS[0]);
            EMIT(abpf_stmt(p, BPF_LD | BPF_B | BPF_IND, 27));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JSET | BPF_K, 0x02, 0, (uint8_t)(2U + 2U * count)));
            for (unsigned direction = 0; direction < 2; ++direction) {
                EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, direction ? 14 : 16));
                for (unsigned i = 0; i < count; ++i)
                    EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ARGOS_HTTP_PROXY_TCP_PORTS[i], UINT8_MAX, 0));
            }
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
                    EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, td[i], UINT8_MAX, 0));
                }
            }
            if (ts_n) {
                EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 14));
                for (size_t i = 0; i < ts_n; ++i) {
                    EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ts[i], UINT8_MAX, 0));
                }
            }
        }
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
    }

    if (need_udp) {
        size_t udp_start = p->len;
        p->code[udp_ja].k = (uint32_t)(udp_start - udp_ja - 1U);
        EMIT(abpf_stmt(p, BPF_LDX | BPF_B | BPF_MSH, 14));
        size_t stun_dport_ja = (size_t)-1, stun_sport_ja = (size_t)-1;
        if (stun_turn) {
            /* UDP/3478 is special: TURN relay data can be an elephant flow.
             * Jump matched 3478 packets to a small STUN-only admission block
             * after the generic UDP port checks. */
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 16));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ARGOS_STUN_TURN_UDP_PORT, 0, 1));
            stun_dport_ja = p->len; EMIT(abpf_stmt(p, BPF_JMP | BPF_JA, 0));
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 14));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ARGOS_STUN_TURN_UDP_PORT, 0, 1));
            stun_sport_ja = p->len; EMIT(abpf_stmt(p, BPF_JMP | BPF_JA, 0));
        }
        if (ud_n) {
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 16));
            for (size_t i = 0; i < ud_n; ++i) {
                EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, ud[i], UINT8_MAX, 0));
            }
        }
        if (us_n) {
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 14));
            for (size_t i = 0; i < us_n; ++i) {
                EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, us[i], UINT8_MAX, 0));
            }
        }
        EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
        if (stun_turn) {
            size_t stun_start = p->len;
            p->code[stun_dport_ja].k = (uint32_t)(stun_start - stun_dport_ja - 1U);
            p->code[stun_sport_ja].k = (uint32_t)(stun_start - stun_sport_ja - 1U);
            /* Minimum STUN datagram: 8-byte UDP + 20-byte STUN header. */
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 18));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JGT | BPF_K, 27, 1, 0));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
            /* STUN has top two bits 00; ChannelData starts 01 and is dropped. */
            EMIT(abpf_stmt(p, BPF_LD | BPF_B | BPF_IND, 22));
            EMIT(abpf_stmt(p, BPF_ALU | BPF_AND | BPF_K, 0xc0));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
            /* TURN Send/Data indications (0x0016/0x0017) carry relay payload. */
            EMIT(abpf_stmt(p, BPF_LD | BPF_H | BPF_IND, 22));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0x0016, 0, 1));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
            EMIT(abpf_jump(p, BPF_JMP | BPF_JEQ | BPF_K, 0x0017, 0, 1));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_DROP));
            EMIT(abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS));
        }
    }

#undef ADD
#undef HAS
#undef EMIT
    /* Port matches share one ACCEPT target, instead of one RET per port.
     * UINT8_MAX is a construction-only true-branch marker. With <=256
     * instructions every real forward offset is <=254. No fixup array,
     * heap allocation or extra executed packet instruction is needed. */
    _Static_assert(ARGOS_BPF_MAX_INSNS <= UINT8_MAX + 1U, "BPF fixup offset bound");
    if (!abpf_stmt(p, BPF_RET | BPF_K, ARGOS_BPF_PASS)) return 0;
    for (unsigned i = 0; i + 1U < p->len; ++i) {
        if (p->code[i].code == (BPF_JMP | BPF_JEQ | BPF_K) &&
            p->code[i].jt == UINT8_MAX)
            p->code[i].jt = (uint8_t)(p->len - i - 2U);
    }
    return 1;
}

static inline int argos_bpf_attach(int sock, const argos_bpf_config_t *cfg) {
    argos_bpf_program_t built;
    if (!cfg) { errno = EINVAL; return -1; }
    if (!argos_bpf_build(cfg, &built)) { errno = EOVERFLOW; return -1; }
    struct sock_fprog prog;
    prog.len = built.len;
    prog.filter = built.code;
    return setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
}

#endif /* ARGOS_BPF_H */
