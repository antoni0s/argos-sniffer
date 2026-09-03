from pathlib import Path

h=Path('src/argos_identity.h')
src=Path('src/argos-sniffer.c')
test=Path('tests/test_identity_ntlm.c')

hs=h.read_text()
end='\n#endif\n'
if hs.count(end)!=1: raise SystemExit(f'identity header end count={hs.count(end)}')
extractor=r'''
/* NTLM Type 3 observed identity extraction. Only DomainName, UserName and
 * Workstation security buffers are consulted. LM/NT responses, session keys,
 * MICs and authentication blobs are deliberately never read or copied. */
static inline uint16_t argos_identity_le16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

static inline uint32_t argos_identity_le32(const unsigned char *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static inline int argos_identity_ntlm_utf16_field(const unsigned char *ntlm,
                                                   size_t remain,
                                                   size_t secbuf_off,
                                                   const char *type,
                                                   int raw_mode,
                                                   argos_identity_result_t *r) {
    if (!ntlm || !type || !r || secbuf_off + 8U > remain) return 0;
    uint16_t bytes = argos_identity_le16(ntlm + secbuf_off);
    uint32_t off = argos_identity_le32(ntlm + secbuf_off + 4U);
    if (bytes == 0U) return 0;
    if ((bytes & 1U) != 0U || off >= remain || (size_t)bytes > remain - (size_t)off)
        return 0;

    size_t chars = (size_t)bytes / 2U;
    if (chars > 160U) chars = 160U;
    unsigned char decoded[161];
    size_t out = 0U;
    for (size_t i = 0; i < chars; ++i) {
        unsigned char lo = ntlm[(size_t)off + i * 2U];
        unsigned char hi = ntlm[(size_t)off + i * 2U + 1U];
        unsigned char c = (hi == 0U && lo >= 32U && lo <= 126U) ? lo : (unsigned char)'?';
        decoded[out++] = c;
    }
    if (out == 0U) return 0;
    return argos_identity_build(r, "ntlm", type, decoded, out, raw_mode);
}

static inline size_t argos_identity_ntlm_type3(const unsigned char *p, size_t len,
                                                int raw_mode,
                                                argos_identity_result_t out[3]) {
    static const unsigned char smb2[] = {0xfeU,'S','M','B'};
    static const unsigned char sig[] = {'N','T','L','M','S','S','P',0};
    if (!p || !out || len < 64U || memcmp(p, smb2, sizeof(smb2)) != 0) return 0U;
    if (argos_identity_le16(p + 12U) != 0x0001U) return 0U; /* SESSION_SETUP */

    const unsigned char *n = NULL;
    for (size_t i = 64U; i + sizeof(sig) <= len; ++i) {
        if (memcmp(p + i, sig, sizeof(sig)) == 0) { n = p + i; break; }
    }
    if (!n) return 0U;
    size_t remain = len - (size_t)(n - p);
    if (remain < 52U || argos_identity_le32(n + 8U) != 3U) return 0U;

    memset(out, 0, sizeof(argos_identity_result_t) * 3U);
    size_t count = 0U;
    argos_identity_result_t r;
    if (argos_identity_ntlm_utf16_field(n, remain, 28U, "domain", raw_mode, &r))
        out[count++] = r;
    if (argos_identity_ntlm_utf16_field(n, remain, 36U, "user", raw_mode, &r))
        out[count++] = r;
    if (argos_identity_ntlm_utf16_field(n, remain, 44U, "workstation", raw_mode, &r))
        out[count++] = r;
    return count;
}
'''
h.write_text(hs.replace(end,'\n'+extractor+end,1))

s=src.read_text()
rdp_block=r'''                /* Identity is a separate explicit vector. RDP extraction is
                 * attempted only on client->server 3389 handshake payloads that
                 * enterprise mode already admitted; default ENT remains redacted. */
                if (opt_identity && dport == 3389U && payload_len > 0) {
                    argos_identity_result_t ident;
                    if (argos_identity_rdp_mstshash(buffer + payload_offset, (size_t)payload_len,
                                                    opt_identity_raw, &ident)) {
                        char ident_mac[18], ident_sig[320];
                        format_mac(src_mac, ident_mac);
                        snprintf(ident_sig, sizeof(ident_sig), "%s|%s|%s|%s",
                                 src_ip_str, ident.protocol, ident.type, ident.value);
                        if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, opt_enterprise_rl))
                            emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                                           ident_mac, src_ip_str, ident.protocol,
                                           ident.type, ident.value, routed_str);
                    }
                }

'''
if s.count(rdp_block)!=1: raise SystemExit(f'RDP identity integration anchor count={s.count(rdp_block)}')
ntlm_block=rdp_block+r'''                /* NTLM Type 3 is the client authentication handshake carrying
                 * observed domain/user/workstation identity metadata. Only those
                 * three bounded security buffers are parsed; auth responses are not. */
                if (opt_identity && dport == 445U && payload_len > 0) {
                    argos_identity_result_t ids[3];
                    size_t id_count = argos_identity_ntlm_type3(
                        buffer + payload_offset, (size_t)payload_len,
                        opt_identity_raw, ids);
                    for (size_t ii = 0; ii < id_count; ++ii) {
                        char ident_mac[18], ident_sig[320];
                        format_mac(src_mac, ident_mac);
                        snprintf(ident_sig, sizeof(ident_sig), "%s|%s|%s|%s",
                                 src_ip_str, ids[ii].protocol, ids[ii].type, ids[ii].value);
                        if (!dedup_should_suppress(ident_mac, "IDENT", ident_sig, opt_enterprise_rl))
                            emit_telemetry("IDENT|%s|%s|%s|%s|%s%s\n",
                                           ident_mac, src_ip_str, ids[ii].protocol,
                                           ids[ii].type, ids[ii].value, routed_str);
                    }
                }

'''
src.write_text(s.replace(rdp_block,ntlm_block,1))

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_identity.h"

static void check(int ok,const char *msg){if(!ok){fprintf(stderr,"FAIL: %s\n",msg);exit(1);}}
static void put16(unsigned char*p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);}
static void put32(unsigned char*p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);}
static size_t put_utf16(unsigned char*p,const char*s){size_t n=0;while(*s){p[n++]=(unsigned char)*s++;p[n++]=0;}return n;}
static void secbuf(unsigned char*n,size_t o,unsigned len,unsigned off){put16(n+o,len);put16(n+o+2,len);put32(n+o+4,off);}
static size_t make_type3(unsigned char*p,size_t cap){
    if(cap<320) return 0;
    memset(p,0,cap);
    p[0]=0xfe;p[1]='S';p[2]='M';p[3]='B';put16(p+12,1);
    unsigned char*n=p+64;memcpy(n,"NTLMSSP\0",8);put32(n+8,3);
    /* Deliberately populate LM/NT response regions with secret-looking bytes.
     * Identity parser must never consult these security buffers. */
    memcpy(n+160,"LM-SECRET-DO-NOT-EMIT",21);secbuf(n,12,21,160);
    memcpy(n+190,"NT-SECRET-DO-NOT-EMIT",21);secbuf(n,20,21,190);
    size_t dl=put_utf16(n+220,"SECRET-CORP");secbuf(n,28,(unsigned)dl,220);
    size_t ul=put_utf16(n+246,"alice");secbuf(n,36,(unsigned)ul,246);
    size_t wl=put_utf16(n+260,"ALICE-PC");secbuf(n,44,(unsigned)wl,260);
    return 64U+276U;
}
static const argos_identity_result_t* find_type(const argos_identity_result_t*r,size_t n,const char*t){for(size_t i=0;i<n;++i)if(strcmp(r[i].type,t)==0)return&r[i];return NULL;}
int main(void){
 unsigned char p[384];argos_identity_result_t ids[3];size_t len=make_type3(p,sizeof(p));
 size_t n=argos_identity_ntlm_type3(p,len,0,ids);check(n==3,"three NTLM identities extracted");
 const argos_identity_result_t*d=find_type(ids,n,"domain"),*u=find_type(ids,n,"user"),*w=find_type(ids,n,"workstation");
 check(d&&u&&w,"domain/user/workstation labels");
 check(strstr(d->value,"SECRET-CORP")==NULL&&strstr(u->value,"alice")==NULL&&strstr(w->value,"ALICE-PC")==NULL,"hash mode hides raw identities");
 check(strncmp(d->value,"hash=",5)==0&&strncmp(u->value,"hash=",5)==0&&strncmp(w->value,"hash=",5)==0,"hash mode format");
 check(strstr(d->value,"LM-SECRET")==NULL&&strstr(u->value,"NT-SECRET")==NULL,"auth responses never surfaced");
 n=argos_identity_ntlm_type3(p,len,1,ids);check(n==3,"raw mode extracts three identities");
 d=find_type(ids,n,"domain");u=find_type(ids,n,"user");w=find_type(ids,n,"workstation");
 check(d&&strcmp(d->value,"SECRET-CORP")==0,"raw domain");check(u&&strcmp(u->value,"alice")==0,"raw user");check(w&&strcmp(w->value,"ALICE-PC")==0,"raw workstation");
 for(size_t i=0;i<n;++i){check(strstr(ids[i].value,"LM-SECRET")==NULL,"LM response excluded");check(strstr(ids[i].value,"NT-SECRET")==NULL,"NT response excluded");}

 /* Type 1 and Type 2 are not identity-bearing Type 3. */
 put32(p+64+8,1);check(argos_identity_ntlm_type3(p,len,0,ids)==0,"type1 ignored");
 put32(p+64+8,2);check(argos_identity_ntlm_type3(p,len,0,ids)==0,"type2 ignored");
 put32(p+64+8,3);
 /* Malformed user offset drops that field but preserves independently valid fields. */
 put32(p+64+40,0xffffff00U);n=argos_identity_ntlm_type3(p,len,1,ids);check(n==2,"malformed user field independently rejected");check(find_type(ids,n,"domain")&&find_type(ids,n,"workstation"),"valid sibling fields survive");
 len=make_type3(p,sizeof(p));p[0]=0xff;check(argos_identity_ntlm_type3(p,len,0,ids)==0,"non-SMB2 rejected");
 len=make_type3(p,sizeof(p));put16(p+12,0);check(argos_identity_ntlm_type3(p,len,0,ids)==0,"non-SESSION_SETUP rejected");
 puts("NTLM identity fixtures: PASS");return 0;
}
''')
print('staged NTLM Type 3 observed identity extractor')
