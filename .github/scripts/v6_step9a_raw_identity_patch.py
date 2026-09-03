from pathlib import Path
import re


def replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)

Path('src/argos_raw_identity.h').write_text(r'''#ifndef ARGOS_RAW_IDENTITY_H
#define ARGOS_RAW_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

/* LINK_RAW_IP (PPP/TUN/WireGuard and similar) has no L2 addresses. Generate
 * deterministic, locally-administered unicast surrogate MACs from the L3
 * endpoints so existing fixed-size identity/state tables can distinguish
 * tunnel clients without allocating memory or changing Ethernet semantics.
 *
 * IPv4 is collision-free within the address family: 02:<IPv4 bytes>:04.
 * IPv6 uses a 40-bit FNV-1a digest behind family marker 06; 06 has the local
 * bit set and multicast bit clear, so it cannot be mistaken for a globally
 * administered hardware address. */
static inline uint64_t argos_raw_id_hash64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    if (!p) return h;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static inline void argos_raw_identity_v4(const uint8_t addr[4], uint8_t mac[6]) {
    mac[0] = 0x02U;
    mac[1] = addr[0]; mac[2] = addr[1]; mac[3] = addr[2]; mac[4] = addr[3];
    mac[5] = 0x04U;
}

static inline void argos_raw_identity_v6(const uint8_t addr[16], uint8_t mac[6]) {
    uint64_t h = argos_raw_id_hash64(addr, 16U);
    mac[0] = 0x06U;
    mac[1] = (uint8_t)(h >> 32); mac[2] = (uint8_t)(h >> 24);
    mac[3] = (uint8_t)(h >> 16); mac[4] = (uint8_t)(h >> 8); mac[5] = (uint8_t)h;
}

#endif /* ARGOS_RAW_IDENTITY_H */
''')

srcp=Path('src/argos-sniffer.c')
s=srcp.read_text()
s=replace_once(s,
'''#include "argos_hsrp.h"\n#include "argos_enterprise.h"\n''',
'''#include "argos_hsrp.h"\n#include "argos_enterprise.h"\n#include "argos_raw_identity.h"\n''','raw identity include')

needle='''            if (filter_mode2.is_active) {\n                if (!evaluate_filter(&filter_mode2, src_mac, dst_mac, src_ip_num, dst_ip_num, filt_src_ip6, filt_dst_ip6)) continue;\n            }\n'''
insert='''            /* Raw-IP links have no hardware MACs. Create stable L3-derived\n             * surrogate identities before any MAC-keyed filter/state/dedup path.\n             * Sensor/interface provenance remains separate in the OBS envelope. */\n            if (pkt_type == LINK_RAW_IP && is_ip_packet) {\n                if (is_ipv6_packet) {\n                    argos_raw_identity_v6(src_ip6_addr.s6_addr, src_mac);\n                    argos_raw_identity_v6(dst_ip6_addr.s6_addr, dst_mac);\n                } else {\n                    argos_raw_identity_v4(buffer + l3_offset + 12, src_mac);\n                    argos_raw_identity_v4(buffer + l3_offset + 16, dst_mac);\n                }\n            }\n\n'''+needle
s=replace_once(s,needle,insert,'raw identity activation')

s=replace_once(s,
'''            } else if (pkt_type == LINK_RAW_IP) {\n                memset(device_mac, 0, 6);\n            } else if (is_outbound) {\n''',
'''            } else if (is_outbound) {\n''','device identity raw branch')

s=replace_once(s,
'''            if (pkt_type != LINK_RAW_IP) {\n                if (memcmp(device_mac, zero_mac, 6) == 0 || memcmp(device_mac, bcast_mac, 6) == 0) continue;\n            }\n\n            char mac_str[18];\n            const char *routed_str = routed_evidence ? "|routed" : "";\n\n            if (pkt_type == LINK_RAW_IP) {\n                snprintf(mac_str, sizeof(mac_str), "%s", current_iface->name);\n            } else {\n                snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",\n                         device_mac[0], device_mac[1], device_mac[2], device_mac[3], device_mac[4], device_mac[5]);\n            }\n''',
'''            if (memcmp(device_mac, zero_mac, 6) == 0 || memcmp(device_mac, bcast_mac, 6) == 0) continue;\n\n            char mac_str[18];\n            const char *routed_str = routed_evidence ? "|routed" : "";\n            format_mac(device_mac, mac_str);\n''','raw mac_str identity')

# Enterprise telemetry had multiple copies of the same raw-IP interface-name
# fallback at different indentation depths (VRRP, OSPF, TCP, HSRP and UDP).
# Replace them structurally so every enterprise vector uses the same stable
# source identity, while still failing closed if the source shape changes.
pat = re.compile(r'(?m)^(?P<i>\s*)if \(pkt_type == LINK_RAW_IP\) snprintf\(ent_mac, sizeof\(ent_mac\), "%s", current_iface->name\);\n(?P=i)else format_mac\(src_mac, ent_mac\);$')
matches = list(pat.finditer(s))
if len(matches) != 5:
    raise SystemExit(f'enterprise raw identity overrides: expected 5, got {len(matches)}')
s = pat.sub(lambda m: f'{m.group("i")}format_mac(src_mac, ent_mac);', s)

srcp.write_text(s)

Path('tests/test_raw_identity.c').write_text(r'''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_raw_identity.h"

int main(void) {
    const uint8_t a4[4]={192,168,1,20}, b4[4]={192,168,1,21};
    uint8_t ma[6], mb[6], ma2[6];
    argos_raw_identity_v4(a4,ma); argos_raw_identity_v4(b4,mb); argos_raw_identity_v4(a4,ma2);
    const uint8_t expect4[6]={0x02,192,168,1,20,0x04};
    assert(memcmp(ma,expect4,6)==0 && memcmp(ma,ma2,6)==0 && memcmp(ma,mb,6)!=0);
    assert((ma[0]&0x03U)==0x02U);

    const uint8_t a6[16]={0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0x12,0x34};
    uint8_t m6[6], m62[6], other6[16]; memcpy(other6,a6,16); other6[15]^=1;
    uint8_t m63[6]; argos_raw_identity_v6(a6,m6); argos_raw_identity_v6(a6,m62); argos_raw_identity_v6(other6,m63);
    assert(m6[0]==0x06U && (m6[0]&0x03U)==0x02U);
    assert(memcmp(m6,m62,6)==0 && memcmp(m6,m63,6)!=0);
    puts("raw-IP stable identity fixtures: PASS");
    return 0;
}
''')
