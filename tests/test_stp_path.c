/* Reuse the existing BPF fixture interpreter, not a second implementation. */
#define main argos_bpf_fixture_main
#include "test_dynamic_bpf.c"
#undef main
#include "../src/argos_packet.h"
#include "../src/argos_l2.h"

static int parse_view(const argos_packet_view_t *v, unsigned version) {
    const unsigned char *p = v->frame + v->l3_offset;
    size_t n = (size_t)(v->packet_end - v->l3_offset);
    argos_stp_result_t stp;
    argos_mstp_result_t mstp;
    if (version == 3U) return argos_mstp_parse(p, n, &mstp);
    if (version == 2U) return argos_rstp_parse(p, n, &stp);
    return argos_stp_parse(p, n, &stp);
}

int main(void) {
    unsigned char frame[256];
    argos_bpf_config_t cfg;
    argos_bpf_program_t enabled, disabled;
    canonical_bpf("stp", 0, 0, &cfg);
    expect(argos_bpf_build(&cfg, &enabled), "STP BPF");
    memset(&cfg, 0, sizeof(cfg));
    expect(argos_bpf_build(&cfg, &disabled), "disabled BPF");
    const unsigned versions[] = {0, 2, 3};
    for (size_t vi = 0; vi < 3; ++vi) {
        unsigned version = versions[vi];
        size_t body = version == 3 ? 105U : version == 2 ? 39U : 38U;
        for (unsigned tags = 0; tags <= 2; ++tags) {
            memset(frame, 0, sizeof(frame));
            frame[0] = 1; frame[1] = 0x80; frame[2] = 0xc2;
            frame[6] = 2; frame[11] = 1;
            size_t off = 14U + 4U * tags;
            if (tags) {
                put16(frame + 12, tags == 2 ? 0x88a8 : 0x8100);
                put16(frame + 14, 100);
                if (tags == 2) { put16(frame + 16, 0x8100); put16(frame + 18, 200); }
            }
            put16(frame + off - 2, (uint16_t)body);
            unsigned char *p = frame + off;
            p[0] = 0x42; p[1] = 0x42; p[2] = 3;
            p[5] = (unsigned char)version; p[6] = version ? 2 : 0;
            if (version == 3) put16(p + 39, 64);
            size_t length = off + body + 8U; /* captured Ethernet padding */
            memset(p + body, 0xa5, 8);
            argos_packet_view_t view;
            expect(pass(&enabled, frame, length), "BPF admits BPDU");
            if (!tags) expect(!pass(&disabled, frame, length), "disabled native STP drops in BPF");
            expect(argos_packet_decode(LINK_ETHERNET, frame, (int)length, 1, &view),
                   "normalization admits STP LLC");
            expect(!view.is_ip && view.l3_proto == body && view.l3_offset == (int)off,
                   "STP preserves LLC for canonical parser");
            expect(view.packet_end == (int)(off + body), "802.3 padding excluded");
            expect(parse_view(&view, version), "canonical BPDU parser reached");
            for (size_t n = 0; n < off + body; ++n)
                expect(!argos_packet_decode(LINK_ETHERNET, frame, (int)n, 1, &view),
                       "truncated declared 802.3 frame rejected");
            put16(frame + off - 2, (uint16_t)(body - 1));
            expect(argos_packet_decode(LINK_ETHERNET, frame, (int)length, 1, &view),
                   "short declared BPDU stays bounded");
            expect(!parse_view(&view, version), "padding cannot complete short BPDU");
            put16(frame + off - 2, 2);
            expect(!argos_packet_decode(LINK_ETHERNET, frame, (int)length, 1, &view),
                   "LLC beyond declared length rejected");
            put16(frame + off - 2, (uint16_t)body);
            p[0] = 0x43;
            expect(!argos_packet_decode(LINK_ETHERNET, frame, (int)length, 1, &view),
                   "unknown LLC remains rejected");
        }
    }
    puts("STP/RSTP/MSTP BPF-normalization-parser path: PASS");
    return 0;
}
