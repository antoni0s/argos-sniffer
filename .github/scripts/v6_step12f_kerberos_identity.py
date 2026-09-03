from pathlib import Path

h=Path('src/argos_identity.h')
src=Path('src/argos-sniffer.c')
test=Path('tests/test_identity_kerberos.c')

hs=h.read_text()
end='\n#endif\n'
if hs.count(end)!=1:
    raise SystemExit(f'identity header end count={hs.count(end)}')

extractor=r'''
/* Kerberos observed identity is intentionally limited to cname [1] from the
 * KDC-REQ-BODY of an AS-REQ. RFC 4120 defines cname there only for AS-REQ.
 * PA-DATA, tickets, authenticators, encrypted data and TGS-REQ identity are
 * deliberately outside this parser. */
static inline int argos_identity_der_tlv(const unsigned char *p, size_t n, size_t pos,
                                         uint8_t *tag, size_t *voff,
                                         size_t *vlen, size_t *next) {
    if (!p || !tag || !voff || !vlen || !next || pos >= n) return 0;
    uint8_t t = p[pos++];
    if ((t & 0x1fU) == 0x1fU || pos >= n) return 0;
    uint8_t lb = p[pos++];
    size_t len = 0U;
    if ((lb & 0x80U) == 0U) {
        len = (size_t)lb;
    } else {
        unsigned count = (unsigned)(lb & 0x7fU);
        if (count == 0U || count > 4U || (size_t)count > n - pos) return 0;
        for (unsigned i = 0U; i < count; ++i) {
            if (len > (SIZE_MAX >> 8)) return 0;
            len = (len << 8) | (size_t)p[pos++];
        }
    }
    if (len > n - pos) return 0;
    *tag = t; *voff = pos; *vlen = len; *next = pos + len;
    return 1;
}

static inline uint32_t argos_identity_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline int argos_identity_kerberos_string(const unsigned char *p,
                                                  size_t n, size_t pos,
                                                  const unsigned char **value,
                                                  size_t *value_len) {
    uint8_t tag; size_t voff, vlen, next;
    if (!value || !value_len ||
        !argos_identity_der_tlv(p, n, pos, &tag, &voff, &vlen, &next) ||
        tag != 0x1bU || vlen == 0U) return 0;
    (void)next;
    *value = p + voff; *value_len = vlen;
    return 1;
}

static inline int argos_identity_kerberos_asreq(const unsigned char *p, size_t len,
                                                int tcp_framed, int raw_mode,
                                                argos_identity_result_t *r) {
    if (!p || !r) return 0;
    size_t off = 0U, end = len;
    if (tcp_framed) {
        if (len < 5U) return 0;
        uint32_t record_len = argos_identity_be32(p);
        if (record_len == 0U || (size_t)record_len > len - 4U) return 0;
        off = 4U; end = off + (size_t)record_len;
    }

    uint8_t tag; size_t voff, vlen, next;
    if (!argos_identity_der_tlv(p, end, off, &tag, &voff, &vlen, &next) ||
        tag != 0x6aU) return 0; /* AS-REQ only; never TGS-REQ */
    (void)next;

    uint8_t seq_tag; size_t seq_voff, seq_vlen, seq_next;
    if (!argos_identity_der_tlv(p, voff + vlen, voff,
                                &seq_tag, &seq_voff, &seq_vlen, &seq_next) ||
        seq_tag != 0x30U) return 0;
    (void)seq_next;

    size_t body_voff = 0U, body_vlen = 0U;
    size_t seq_end = seq_voff + seq_vlen;
    for (size_t pos = seq_voff; pos < seq_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!argos_identity_der_tlv(p, seq_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa4U) { body_voff = cv; body_vlen = cl; break; }
        pos = cn;
    }
    if (body_vlen == 0U) return 0;

    uint8_t body_tag; size_t bvoff, bvlen, bnext;
    if (!argos_identity_der_tlv(p, body_voff + body_vlen, body_voff,
                                &body_tag, &bvoff, &bvlen, &bnext) ||
        body_tag != 0x30U) return 0;
    (void)bnext;

    size_t cname_voff = 0U, cname_vlen = 0U, realm_voff = 0U, realm_vlen = 0U;
    size_t body_end = bvoff + bvlen;
    for (size_t pos = bvoff; pos < body_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!argos_identity_der_tlv(p, body_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa1U) { cname_voff = cv; cname_vlen = cl; }
        else if (ct == 0xa2U) { realm_voff = cv; realm_vlen = cl; }
        pos = cn;
    }
    if (cname_vlen == 0U || realm_vlen == 0U) return 0;

    const unsigned char *realm = NULL; size_t realm_len = 0U;
    if (!argos_identity_kerberos_string(p, realm_voff + realm_vlen, realm_voff,
                                        &realm, &realm_len)) return 0;

    uint8_t pn_tag; size_t pn_voff, pn_vlen, pn_next;
    if (!argos_identity_der_tlv(p, cname_voff + cname_vlen, cname_voff,
                                &pn_tag, &pn_voff, &pn_vlen, &pn_next) ||
        pn_tag != 0x30U) return 0;
    (void)pn_next;

    size_t names_voff = 0U, names_vlen = 0U;
    size_t pn_end = pn_voff + pn_vlen;
    for (size_t pos = pn_voff; pos < pn_end; ) {
        uint8_t ct; size_t cv, cl, cn;
        if (!argos_identity_der_tlv(p, pn_end, pos, &ct, &cv, &cl, &cn)) return 0;
        if (ct == 0xa1U) { names_voff = cv; names_vlen = cl; break; }
        pos = cn;
    }
    if (names_vlen == 0U) return 0;

    uint8_t names_tag; size_t nvoff, nvlen, nnext;
    if (!argos_identity_der_tlv(p, names_voff + names_vlen, names_voff,
                                &names_tag, &nvoff, &nvlen, &nnext) ||
        names_tag != 0x30U) return 0;
    (void)nnext;

    unsigned char principal[161]; size_t used = 0U; unsigned components = 0U;
    size_t names_end = nvoff + nvlen;
    for (size_t pos = nvoff; pos < names_end; ) {
        uint8_t st; size_t sv, sl, sn;
        if (!argos_identity_der_tlv(p, names_end, pos, &st, &sv, &sl, &sn)) return 0;
        if (st != 0x1bU || sl == 0U) return 0;
        if (components >= 8U || sl > 120U) return 0;
        size_t need = sl + (components ? 1U : 0U);
        if (need > 160U - used) return 0;
        if (components) principal[used++] = (unsigned char)'/';
        memcpy(principal + used, p + sv, sl); used += sl; components++;
        pos = sn;
    }
    if (components == 0U || realm_len > 120U || realm_len + 1U > 160U - used) return 0;
    principal[used++] = (unsigned char)'@';
    memcpy(principal + used, realm, realm_len); used += realm_len;

    return argos_identity_build(r, "kerberos", "principal", principal, used, raw_mode);
}
'''
h.write_text(hs.replace(end,'\n'+extractor+end,1))

s=src.read_text()
# TCP: insert after NTLM identity integration, before app_track.
tcp_anchor='''                if (app_track) {\n                    int fingerprint_complete = app_flow_payload_complete(\n'''
if s.count(tcp_anchor)!=1:
    raise SystemExit(f'TCP app_track anchor count={s.count(tcp_anchor)}')
tcp_insert=r'''                /* Kerberos observed identity: only client->KDC AS-REQ cname/realm. */
                if (opt_identity && dport == 88U && payload_len > 0) {
                    argos_identity_result_t ident;
                    if (argos_identity_kerberos_asreq(buffer + payload_offset,
                                                      (size_t)payload_len, 1,
                                                      opt_identity_raw, &ident)) {
                        char ident_mac[18], ident_sig[320];
                        format_mac(src_mac, ident_mac);
                        snprintf(ident_sig, sizeof(ident_sig), "%.45s|%.23s|%.23s|%.191s",
                                 src_ip_str, ident.protocol, ident.type, ident.value);
                        if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, opt_enterprise_rl))
                            emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                                           ident_mac, src_ip_str, ident.protocol,
                                           ident.type, ident.value, routed_str);
                    }
                }

'''
s=s.replace(tcp_anchor,tcp_insert+tcp_anchor,1)

udp_anchor='''                if (opt_enterprise && argos_enterprise_udp_port(sport, dport)) {\n                    argos_enterprise_result_t ent_udp;\n'''
if s.count(udp_anchor)!=1:
    raise SystemExit(f'UDP enterprise anchor count={s.count(udp_anchor)}')
# Put IDENT after ENT block using the exact closing before UDP protocol branch end.
udp_close='''                    }\n                }\n            }\n        }\n        if (opt_v6) {\n'''
if s.count(udp_close)!=1:
    raise SystemExit(f'UDP close anchor count={s.count(udp_close)}')
udp_insert=r'''                    }
                }
                /* UDP/88 uses the same strictly bounded AS-REQ parser without
                 * the RFC 4120 TCP record-length prefix. */
                if (opt_identity && dport == 88U) {
                    argos_identity_result_t ident;
                    if (argos_identity_kerberos_asreq(payload, (size_t)payload_len, 0,
                                                      opt_identity_raw, &ident)) {
                        char ident_mac[18], ident_sig[320];
                        format_mac(src_mac, ident_mac);
                        snprintf(ident_sig, sizeof(ident_sig), "%.45s|%.23s|%.23s|%.191s",
                                 src_ip_str, ident.protocol, ident.type, ident.value);
                        if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, opt_enterprise_rl))
                            emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                                           ident_mac, src_ip_str, ident.protocol,
                                           ident.type, ident.value, routed_str);
                    }
                }
            }
        }
        if (opt_v6) {
'''
s=s.replace(udp_close,udp_insert,1)
src.write_text(s)

# Build deterministic short-form DER fixture bytes.
def tlv(tag, body):
    if len(body) < 128:
        return bytes([tag, len(body)]) + body
    if len(body) < 256:
        return bytes([tag, 0x81, len(body)]) + body
    return bytes([tag, 0x82, len(body) >> 8, len(body) & 0xff]) + body

def integer(v):
    return tlv(0x02, bytes([v]))

def gstr(s):
    return tlv(0x1b, s.encode('ascii'))

def principal(parts):
    name_type=tlv(0xa0, integer(1))
    names=tlv(0xa1, tlv(0x30, b''.join(gstr(x) for x in parts)))
    return tlv(0x30, name_type+names)

cname=tlv(0xa1, principal(['alice','admin']))
realm=tlv(0xa2, gstr('EXAMPLE.COM'))
sname=tlv(0xa3, principal(['krbtgt','EXAMPLE.COM']))
etypes=tlv(0xa8, tlv(0x30, integer(18)+integer(17)))
body=tlv(0x30, cname+realm+sname+etypes)
req_body=tlv(0xa4, body)
pvno=tlv(0xa1, integer(5))
msg=tlv(0xa2, integer(10))
# PA-DATA-like opaque context deliberately carries a secret-looking token;
# identity parser must skip context [3] entirely.
padata=tlv(0xa3, tlv(0x04,b'PA-SECRET-DO-NOT-EMIT'))
seq=tlv(0x30, pvno+msg+padata+req_body)
asreq=tlv(0x6a, seq)
tgsreq=bytes([0x6c])+asreq[1:]

def carr(data):
    return ','.join(f'0x{x:02x}' for x in data)

test.write_text(f'''#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include "../src/argos_identity.h"\n\nstatic void check(int ok,const char *msg){{if(!ok){{fprintf(stderr,"FAIL: %s\\n",msg);exit(1);}}}}\nstatic const unsigned char asreq[] = {{{carr(asreq)}}};\nstatic const unsigned char tgsreq[] = {{{carr(tgsreq)}}};\nint main(void){{\n argos_identity_result_t r;\n check(argos_identity_kerberos_asreq(asreq,sizeof(asreq),0,0,&r)==1,"UDP AS-REQ parsed");\n check(strcmp(r.protocol,"kerberos")==0&&strcmp(r.type,"principal")==0,"Kerberos identity labels");\n check(strncmp(r.value,"hash=",5)==0,"hash mode default");\n check(strstr(r.value,"alice")==NULL&&strstr(r.value,"EXAMPLE.COM")==NULL,"hash mode hides principal");\n check(strstr(r.value,"PA-SECRET")==NULL,"PA-DATA secret excluded");\n check(argos_identity_kerberos_asreq(asreq,sizeof(asreq),0,1,&r)==1,"raw AS-REQ parsed");\n check(strcmp(r.value,"alice/admin@EXAMPLE.COM")==0,"raw principal canonical form");\n check(strstr(r.value,"krbtgt")==NULL&&strstr(r.value,"PA-SECRET")==NULL,"sname and PA-DATA excluded");\n check(argos_identity_kerberos_asreq(tgsreq,sizeof(tgsreq),0,1,&r)==0,"TGS-REQ rejected");\n unsigned char tcp[sizeof(asreq)+4];\n size_t n=sizeof(asreq);tcp[0]=(unsigned char)(n>>24);tcp[1]=(unsigned char)(n>>16);tcp[2]=(unsigned char)(n>>8);tcp[3]=(unsigned char)n;memcpy(tcp+4,asreq,n);\n check(argos_identity_kerberos_asreq(tcp,sizeof(tcp),1,1,&r)==1,"TCP framed AS-REQ parsed");\n check(strcmp(r.value,"alice/admin@EXAMPLE.COM")==0,"TCP raw principal");\n tcp[3]=(unsigned char)(tcp[3]+8U);check(argos_identity_kerberos_asreq(tcp,sizeof(tcp),1,1,&r)==0,"oversized TCP record rejected");\n unsigned char bad[sizeof(asreq)];memcpy(bad,asreq,sizeof(bad));bad[1]=0xff;check(argos_identity_kerberos_asreq(bad,sizeof(bad),0,1,&r)==0,"malformed DER length rejected");\n check(argos_identity_kerberos_asreq(asreq,8,0,1,&r)==0,"truncated AS-REQ rejected");\n puts("Kerberos identity fixtures: PASS");return 0;\n}}\n''')
print('staged Kerberos AS-REQ observed identity extractor')
