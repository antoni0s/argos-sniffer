#include <stdint.h>
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

static uint32_t run_bpf_code(const struct sock_filter *code, size_t count,
                             const unsigned char *pkt, size_t len, unsigned *steps) {
    uint32_t A = 0, X = 0, M[16] = {0}; size_t pc = 0;
    if (steps) *steps = 0;
    while (code && pc < count) {
        struct sock_filter in = code[pc];
        if (steps) ++*steps;
        unsigned cls = BPF_CLASS(in.code), mode = BPF_MODE(in.code), size = BPF_SIZE(in.code);
        unsigned bytes = size == BPF_B ? 1U : size == BPF_H ? 2U : 4U;
        if (cls == BPF_LD) {
            size_t off = mode == BPF_IND ? (size_t)X + in.k : in.k;
            if ((mode == BPF_ABS || mode == BPF_IND) &&
                (off > len || bytes > len - off)) return 0;
            if (mode == BPF_ABS) A = load_n(pkt, len, in.k, bytes);
            else if (mode == BPF_IND) A = load_n(pkt, len, (size_t)X + in.k, bytes);
            else if (mode == BPF_MEM && in.k < 16U) A = M[in.k]; else return 0;
            ++pc; continue;
        }
        if (cls == BPF_LDX) {
            if (mode == BPF_MSH && in.k >= len) return 0;
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

static uint32_t run_bpf(const argos_bpf_program_t *p, const unsigned char *pkt, size_t len) {
    return p ? run_bpf_code(p->code, p->len, pkt, len, NULL) : 0;
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

/* Translate frozen CLI-era flags for equivalence fixtures only. Production
 * startup uses argos_bpf_config_compile() from the canonical dispatch plan. */
static void legacy_route_demand(argos_bpf_config_t *c, int l2, int ipv6) {
    if (l2)
        c->l2_routes |= ARGOS_DISPATCH_L2_ARP | ARGOS_DISPATCH_L2_LLDP;
    if (c->enterprise) {
        c->l2_routes |= ARGOS_DISPATCH_L2_LLDP | ARGOS_DISPATCH_L2_LLC |
                        ARGOS_DISPATCH_L2_SLOW | ARGOS_DISPATCH_L2_EAPOL |
                        ARGOS_DISPATCH_L2_PROFINET;
        c->l3_routes |= ARGOS_DISPATCH_L3_IGMP | ARGOS_DISPATCH_L3_OSPF |
                        ARGOS_DISPATCH_L3_VRRP;
    }
    if (c->syn || c->http || c->tls || c->enterprise)
        c->l4_routes |= ARGOS_DISPATCH_L4_TCP;
    if (c->multi || c->dhcp || c->netbios || c->dns || c->tls || c->enterprise)
        c->l4_routes |= ARGOS_DISPATCH_L4_UDP;
    if (c->l4_routes || c->enterprise)
        c->l3_routes |= ARGOS_DISPATCH_L3_IPV4;
    if (ipv6) c->l3_routes |= ARGOS_DISPATCH_L3_IPV6;
}

static void canonical_bpf(const char *protocol, int ipv6,
                          uint16_t wireguard_port, argos_bpf_config_t *c) {
    argos_cli_selection_t cli;
    argos_dispatch_plan_t plan;
    argos_cli_selection_init(&cli);
    expect(argos_cli_selection_apply_named(
        &cli, ARGOS_CLI_SELECTOR_PROTOCOL, protocol), "select canonical BPF protocol");
    if (ipv6)
        argos_feature_selection_apply(&cli.features, ARGOS_FEATURE_IPV6, 0);
    argos_dispatch_plan_compile(&plan, &cli);
    argos_bpf_config_compile(c, &plan, wireguard_port);
}

int main(void) {
    unsigned char pkt[2048]; argos_bpf_program_t p; argos_bpf_config_t c;
    memset(&c, 0, sizeof(c)); c.dns = 1; legacy_route_demand(&c, 0, 0); expect(argos_bpf_build(&c, &p), "build DNS");
    expect(pass(&p, pkt, udp4(pkt, 50000, 53, 20)), "DNS query passes");
    expect(pass(&p, pkt, udp4(pkt, 53, 50000, 20)), "DNS response passes");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 5353, 20)), "mDNS drops in DNS-only mode");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 443, 0x10, 20)), "TLS drops in DNS-only mode");

    memset(&c, 0, sizeof(c)); c.http = 1; legacy_route_demand(&c, 0, 0); expect(argos_bpf_build(&c, &p), "build HTTP");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 80, 0x18, 20)), "HTTP payload passes");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 80, 0x10, 0)), "HTTP empty ACK drops");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 443, 0x18, 20)), "TLS port drops in HTTP-only mode");

    memset(&c, 0, sizeof(c)); c.syn = 1; legacy_route_demand(&c, 0, 0); expect(argos_bpf_build(&c, &p), "build SYN");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 65000, 0x02, 0)), "arbitrary TCP SYN passes");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 65000, 0x10, 20)), "non-control TCP drops in SYN-only mode");

    memset(&c, 0, sizeof(c)); legacy_route_demand(&c, 1, 0); expect(argos_bpf_build(&c, &p), "build L2");
    expect(pass(&p, pkt, eth(pkt, 0x0806)), "ARP passes in L2 mode");
    expect(pass(&p, pkt, eth(pkt, 0x88cc)), "LLDP passes in L2 mode");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 53, 20)), "IPv4 DNS drops in L2-only mode");
    expect(pass(&p, pkt, eth(pkt, 0x8100)), "VLAN remains conservative pass-through");

    canonical_bpf("arp", 0, 51820, &c); expect(argos_bpf_build(&c, &p), "build canonical ARP");
    expect(pass(&p, pkt, eth(pkt, 0x0806)), "canonical ARP route passes ARP");
    expect(!pass(&p, pkt, eth(pkt, 0x88cc)), "canonical ARP route excludes LLDP");
    expect(c.wireguard_port == 0U, "unselected WireGuard cannot project a port");

    canonical_bpf("lldp", 0, 51820, &c); expect(argos_bpf_build(&c, &p), "build canonical LLDP");
    expect(pass(&p, pkt, eth(pkt, 0x88cc)), "canonical LLDP route passes LLDP");
    expect(!pass(&p, pkt, eth(pkt, 0x0806)), "canonical LLDP route excludes ARP");

    canonical_bpf("ospf", 0, 51820, &c); expect(argos_bpf_build(&c, &p), "build canonical OSPF");
    expect(pass(&p, pkt, proto4(pkt, 89)), "canonical OSPF route passes OSPF");
    expect(!pass(&p, pkt, proto4(pkt, 2)), "canonical OSPF route excludes IGMP");
    expect(!pass(&p, pkt, proto4(pkt, 112)), "canonical OSPF route excludes VRRP");

    canonical_bpf("ndp", 1, 51820, &c); expect(argos_bpf_build(&c, &p), "build canonical IPv6");
    expect(pass(&p, pkt, eth(pkt, 0x86dd)), "canonical IPv6 demand keeps conservative IPv6 fallback");
    expect(pass(&p, pkt, eth(pkt, 0x8100)), "canonical plan keeps VLAN fallback unconditional");
    expect(pass(&p, pkt, eth(pkt, 0x88a8)), "canonical plan keeps QinQ fallback unconditional");
    expect(pass(&p, pkt, eth(pkt, 0x8864)), "canonical plan keeps PPPoE fallback unconditional");

    canonical_bpf("wireguard", 0, 51821, &c);
    expect(c.wireguard_port == 51821U, "selected WireGuard projects configured port");
    expect(argos_bpf_build(&c, &p), "build canonical WireGuard");
    expect(pass(&p, pkt, udp4(pkt, 50000, 51821, 148)), "canonical WireGuard port passes");

    memset(&c, 0, sizeof(c)); c.tls = 1; legacy_route_demand(&c, 0, 0); expect(argos_bpf_build(&c, &p), "build TLS");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 443, 0x18, 20)), "TLS HTTPS port passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 465, 0x18, 20)), "TLS SMTPS port passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 853, 0x18, 20)), "DNS-over-TLS port passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 993, 0x18, 20)), "TLS IMAPS port passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 995, 0x18, 20)), "TLS POP3S port passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 8443, 0x18, 20)), "alternate HTTPS port passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 8883, 0x18, 20)), "MQTTS TCP/8883 payload passes");
    expect(pass(&p, pkt, tcp4(pkt, 443, 50000, 0x18, 80)), "TLS server-direction payload passes");
    expect(pass(&p, pkt, tcp4(pkt, 853, 50000, 0x18, 80)), "DoT server-direction payload passes");
    expect(!pass(&p, pkt, tcp4(pkt, 587, 50000, 0x18, 80)), "STARTTLS server direction stays out");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 587, 0x18, 20)), "STARTTLS 587 stays out of direct-TLS policy");
    expect(pass(&p, pkt, udp4(pkt, 50000, 443, 1200)), "QUIC destination 443 passes");
    expect(!pass(&p, pkt, udp4(pkt, 443, 50000, 1200)), "QUIC server direction drops in client-only TLS mode");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 853, 1200)), "DoT is TCP; UDP/853 drops in TLS mode");

    memset(&c, 0, sizeof(c)); c.enterprise = 1; c.wireguard_port = 51821; legacy_route_demand(&c, 0, 1); expect(argos_bpf_build(&c, &p), "build enterprise");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 44818, 0x18, 24)), "EtherNet/IP TCP/44818 passes");
    expect(pass(&p, pkt, tcp4(pkt, 50000, 1883, 0x18, 24)), "MQTT TCP/1883 destination passes");
    expect(pass(&p, pkt, tcp4(pkt, 44818, 50000, 0x18, 24)), "EtherNet/IP TCP response passes");
    expect(pass(&p, pkt, udp4(pkt, 50000, 123, 48)), "NTP UDP/123 passes");
    expect(pass(&p, pkt, udp4(pkt, 50000, 51821, 148)), "custom WireGuard destination port passes");
    expect(pass(&p, pkt, udp4(pkt, 51821, 50000, 92)), "custom WireGuard source port passes");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 51820, 148)), "default WireGuard port is not hard-coded when custom port is configured");
    expect(pass(&p, pkt, udp4(pkt, 50000, 47808, 20)), "BACnet/IP passes");
    expect(pass(&p, pkt, udp4(pkt, 50000, 5683, 20)), "CoAP UDP/5683 passes");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 5684, 20)), "CoAPS UDP/5684 stays out of plaintext enterprise parser");
    size_t stun_n = udp4(pkt, 50000, 3478, 32); pkt[42]=0x00; pkt[43]=0x01;
    expect(pass(&p, pkt, stun_n), "STUN Binding control on UDP/3478 passes");
    stun_n = udp4(pkt, 3478, 50000, 32); pkt[42]=0x01; pkt[43]=0x01;
    expect(pass(&p, pkt, stun_n), "STUN response from UDP/3478 passes");
    stun_n = udp4(pkt, 50000, 3478, 32); pkt[42]=0x40; pkt[43]=0x01;
    expect(!pass(&p, pkt, stun_n), "TURN ChannelData fast-drops in kernel BPF");
    stun_n = udp4(pkt, 50000, 3478, 32); pkt[42]=0x00; pkt[43]=0x16;
    expect(!pass(&p, pkt, stun_n), "TURN Send indication fast-drops in kernel BPF");
    stun_n = udp4(pkt, 3478, 50000, 32); pkt[42]=0x00; pkt[43]=0x17;
    expect(!pass(&p, pkt, stun_n), "TURN Data indication fast-drops in kernel BPF");
    expect(!pass(&p, pkt, udp4(pkt, 50000, 3478, 0)), "short UDP/3478 packet drops");
    expect(pass(&p, pkt, proto4(pkt, 2)), "IGMP passes");
    expect(pass(&p, pkt, proto4(pkt, 89)), "OSPF passes");
    expect(pass(&p, pkt, proto4(pkt, 112)), "VRRP passes");
    expect(pass(&p, pkt, eth(pkt, 100)), "802.3 LLC enterprise discovery passes");
    expect(pass(&p, pkt, eth(pkt, 0x86dd)), "IPv6 passes when enabled");
    expect(!pass(&p, pkt, tcp4(pkt, 50000, 25, 0x18, 20)), "unparsed enterprise TCP port drops");

    memset(&c, 0, sizeof(c)); c.enterprise = 1; legacy_route_demand(&c, 0, 0);
    expect(argos_bpf_build(&c, &p), "enterprise-only BPF builds");
    memset(pkt, 0, sizeof(pkt)); put16(pkt + 12, 0x88cc);
    expect(pass(&p, pkt, 64), "enterprise-only admits LLDP-MED EtherType");
    expect(pass(&p, pkt, eth(pkt, 0x8809)), "enterprise-only admits Slow Protocols/LACP EtherType");

    puts("dynamic BPF functional matrix: PASS");
    return 0;
}
