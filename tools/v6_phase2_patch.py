#!/usr/bin/env python3
from pathlib import Path


def one(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {n}")
    return text.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Capture-side LLC/SNAP recognition: EDP and FDP join CDP/IS-IS.
# ---------------------------------------------------------------------------
sp = Path("src/argos-sniffer.c")
s = sp.read_text(encoding="utf-8")
s = one(s,
'''        /* IEEE 802.3 + LLC/SNAP control protocols. The 16-bit field at
         * Ethernet offset 12 is a payload length (<=1500), not an EtherType.
         * CDP uses SNAP OUI 00:00:0c + PID 0x2000. IS-IS uses LLC FE:FE:03. */
        if (eth_type <= 1500U) {
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0x00U && buffer[offset + 5] == 0x0cU &&
                read_be16(buffer + offset + 6) == 0x2000U) {
                *l3_proto = 0x2000U;
                return offset + 8;
            }
''',
'''        /* IEEE 802.3 + LLC/SNAP control protocols. The 16-bit field at
         * Ethernet offset 12 is a payload length (<=1500), not an EtherType.
         * CDP: OUI 00:00:0c/PID 0x2000; EDP: OUI 00:e0:2b/PID 0x00bb;
         * FDP: OUI 00:e0:52/PID 0x2000; IS-IS uses LLC FE:FE:03. */
        if (eth_type <= 1500U) {
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0xe0U && buffer[offset + 5] == 0x2bU &&
                read_be16(buffer + offset + 6) == 0x00bbU) {
                *l3_proto = 0x00bbU; /* internal EDP discriminator */
                return offset + 8;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0xe0U && buffer[offset + 5] == 0x52U &&
                read_be16(buffer + offset + 6) == 0x2000U) {
                *l3_proto = 0xf200U; /* internal FDP discriminator */
                return offset + 8;
            }
            if (len >= offset + 8 && buffer[offset] == 0xaaU && buffer[offset + 1] == 0xaaU &&
                buffer[offset + 2] == 0x03U && buffer[offset + 3] == 0x00U &&
                buffer[offset + 4] == 0x00U && buffer[offset + 5] == 0x0cU &&
                read_be16(buffer + offset + 6) == 0x2000U) {
                *l3_proto = 0x2000U;
                return offset + 8;
            }
''', 'LLC vendor discovery recognition')

needle = 'l3_proto == 0x2000U || l3_proto == 0x00feU'
count = s.count(needle)
if count != 3:
    raise SystemExit(f"enterprise L2 protocol lists: expected 3 matches, found {count}")
s = s.replace(needle, 'l3_proto == 0x2000U || l3_proto == 0x00feU ||\n                                    l3_proto == 0x00bbU || l3_proto == 0xf200U')
sp.write_text(s, encoding="utf-8")

# ---------------------------------------------------------------------------
# Parser-side additions and corrections.
# ---------------------------------------------------------------------------
hp = Path("src/argos_enterprise.h")
h = hp.read_text(encoding="utf-8")

# Do not capture TCP ports for which v6 currently has no parser.
h = one(h,
'''    const uint16_t ports[] = {
        22, 88, 111, 179, 389, 445, 502, 631, 1433, 1521, 2000, 2049,
        3260, 3306, 3389, 5060, 5432, 5672, 6379, 9100
    };
''',
'''    const uint16_t ports[] = {
        22, 88, 111, 179, 445, 502, 631, 1433, 1521, 2000, 2049,
        3260, 3306, 3389, 5060, 5432, 9100
    };
''', 'enterprise TCP port list')

# SCCP Register: Wireshark layout is data length @0, message ID @8,
# DeviceName[16] @12, device type @40, max streams @44.
sccp = r'''
static inline int ae_sccp(const unsigned char *p, int len, argos_enterprise_result_t *r) {
    if (len < 12) return 0;
    uint32_t data_len = ae_le32(p);
    uint32_t msgid = ae_le32(p + 8);
    if (msgid != 0x00000001U) return 0; /* RegisterMessage only */
    if (len < 48) return 0;
    char device[32];
    ae_clean(p + 12, 16, device, sizeof(device));
    uint32_t device_type = ae_le32(p + 40);
    uint32_t max_streams = ae_le32(p + 44);
    ae_set(r, "sccp", 1, "register device=%s device_type=%u max_streams=%u data_len=%u",
           device[0] ? device : "-", device_type, max_streams, data_len);
    return 1;
}

/* Defined below with the UDP identity parsers; forward declaration lets TCP/88
 * reuse the exact same bounded Kerberos request parser. */
static inline int ae_kerberos(const unsigned char *p, int len, argos_enterprise_result_t *r);

'''
h = one(h,
'static inline int argos_enterprise_parse_tcp(uint16_t sport, uint16_t dport,\n',
sccp + 'static inline int argos_enterprise_parse_tcp(uint16_t sport, uint16_t dport,\n',
'SCCP/Kerberos forward insertion')

h = one(h,
'''    if (port != 22 && port != 88 && port != 111 && port != 179 && port != 389 && port != 445 &&
        port != 502 && port != 631 && port != 1433 && port != 1521 && port != 2000 && port != 2049 &&
        port != 3260 && port != 3306 && port != 3389 && port != 5060 && port != 5432 && port != 5672 &&
        port != 6379 && port != 9100) port = sport;
''',
'''    if (port != 22 && port != 88 && port != 111 && port != 179 && port != 445 &&
        port != 502 && port != 631 && port != 1433 && port != 1521 && port != 2000 && port != 2049 &&
        port != 3260 && port != 3306 && port != 3389 && port != 5060 && port != 5432 &&
        port != 9100) port = sport;
''', 'TCP server-port selection')
h = one(h,
'''    switch (port) {
        case 22: return ae_ssh(p, len, r);
        case 111: case 2049: return ae_rpc(p, len, 1, r);
''',
'''    switch (port) {
        case 22: return ae_ssh(p, len, r);
        case 88: return ae_kerberos(p, len, r);
        case 111: case 2049: return ae_rpc(p, len, 1, r);
''', 'TCP Kerberos dispatch')
h = one(h,
'''        case 1521: return ae_tns(p, len, r);
        case 3260: return ae_iscsi(p, len, r);
''',
'''        case 1521: return ae_tns(p, len, r);
        case 2000: return ae_sccp(p, len, r);
        case 3260: return ae_iscsi(p, len, r);
''', 'SCCP dispatch')

# Exact EDP and FDP discovery parsing based on their LLC/SNAP dissector layouts.
vendor_l2 = r'''
    if (proto == 0x00bbU) { /* Extreme Discovery Protocol */
        if (len < 16) return 0;
        uint8_t version = p[0];
        uint16_t advertised = ae_be16(p + 2);
        int end = advertised >= 16U && advertised <= (uint16_t)len ? advertised : len;
        int pos = 16;
        char name[128] = {0};
        unsigned slot = 0, port = 0, v1 = 0, v2 = 0, vs = 0, vi = 0;
        while (pos + 4 <= end) {
            uint8_t type = p[pos + 1];
            uint16_t tl = ae_be16(p + pos + 2);
            if (tl < 4U || pos + tl > end) break;
            if (type == 0x01U && tl > 4U) {
                ae_clean(p + pos + 4, (int)tl - 4, name, sizeof(name));
            } else if (type == 0x02U && tl >= 20U) {
                slot = ae_be16(p + pos + 4) + 1U;
                port = ae_be16(p + pos + 6) + 1U;
                v1 = p[pos + 16]; v2 = p[pos + 17]; vs = p[pos + 18]; vi = p[pos + 19];
            }
            pos += tl;
        }
        ae_set(r, "edp", 0, "version=%u name=%s slot=%u port=%u software=%u.%u.%u.%u",
               version, name[0] ? name : "-", slot, port, v1, v2, vs, vi);
        return 1;
    }
    if (proto == 0xf200U) { /* Foundry Discovery Protocol */
        if (len < 4) return 0;
        uint8_t version = p[0], hold = p[1];
        int pos = 4;
        char name[128] = {0}, iface[96] = {0}, release[160] = {0}, model[128] = {0};
        while (pos + 4 <= len) {
            uint16_t type = ae_be16(p + pos), tl = ae_be16(p + pos + 2);
            if (tl < 4U || pos + tl > len) break;
            if (type == 1U) ae_clean(p + pos + 4, (int)tl - 4, name, sizeof(name));
            else if (type == 3U) ae_clean(p + pos + 4, (int)tl - 4, iface, sizeof(iface));
            else if (type == 5U) ae_clean(p + pos + 4, (int)tl - 4, release, sizeof(release));
            else if (type == 6U) ae_clean(p + pos + 4, (int)tl - 4, model, sizeof(model));
            pos += tl;
        }
        ae_set(r, "fdp", 0, "version=%u hold=%u device=%s model=%s software=%s interface=%s",
               version, hold, name[0] ? name : "-", model[0] ? model : "-",
               release[0] ? release : "-", iface[0] ? iface : "-");
        return 1;
    }
    if (proto == 0x00feU) { /* ISO IS-IS after LLC FE:FE:03 */
        if (len < 20 || p[0] != 0x83U) return 0;
        uint8_t pdu_type = (uint8_t)(p[4] & 0x1fU);
        if (pdu_type != 15U && pdu_type != 16U && pdu_type != 17U) return 0;
        char sysid[32];
        snprintf(sysid, sizeof(sysid), "%02x%02x.%02x%02x.%02x%02x",
                 p[9], p[10], p[11], p[12], p[13], p[14]);
        uint16_t hold = ae_be16(p + 15);
        uint16_t plen = ae_be16(p + 17);
        unsigned circuit = p[8] & 0x03U;
        if (pdu_type == 15U || pdu_type == 16U) {
            unsigned priority = p[19] & 0x7fU;
            ae_set(r, "isis", 0, "hello=%s system_id=%s circuit=%u hold=%u pdu_len=%u priority=%u",
                   pdu_type == 15U ? "L1-LAN" : "L2-LAN", sysid, circuit, hold, plen, priority);
        } else {
            ae_set(r, "isis", 0, "hello=P2P system_id=%s circuit=%u hold=%u pdu_len=%u local_circuit=%u",
                   sysid, circuit, hold, plen, p[19]);
        }
        return 1;
    }
'''
h = one(h,
'''    if (proto == 0x2000U) { /* CDP SNAP PID */
''',
vendor_l2 + '''    if (proto == 0x2000U) { /* CDP SNAP PID */
''', 'EDP/FDP/IS-IS parsers')

# OSPFv2 Hello fields start after the 24-byte OSPF header:
# mask@24, hello interval@28, options@30, priority@31, dead interval@32.
h = one(h,
'''    if (ver == 2U && len >= 44) {
        uint16_t hello = ae_be16(p + 32); uint32_t dead = ae_be32(p + 36);
        ae_set(r, "ospf", 0, "v2 hello router_id=%s area=%s hello=%u dead=%u options=0x%02x",
               rid, area, hello, dead, p[35]);
''',
'''    if (ver == 2U && len >= 44) {
        uint16_t hello = ae_be16(p + 28); uint32_t dead = ae_be32(p + 32);
        ae_set(r, "ospf", 0, "v2 hello router_id=%s area=%s hello=%u dead=%u options=0x%02x",
               rid, area, hello, dead, p[30]);
''', 'OSPFv2 Hello offsets')

h = one(h,
'''    const uint16_t tports[] = {22,88,111,179,389,445,502,631,1433,1521,2000,2049,3260,3306,3389,5060,5432,5672,6379,9100};
''',
'''    const uint16_t tports[] = {22,88,111,179,445,502,631,1433,1521,2000,2049,3260,3306,3389,5060,5432,9100};
''', 'kernel TCP port list')

hp.write_text(h, encoding="utf-8")
print("v6 phase-2 parser patch applied")
