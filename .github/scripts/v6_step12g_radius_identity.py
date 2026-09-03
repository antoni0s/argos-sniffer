from pathlib import Path

h=Path('src/argos_identity.h')
src=Path('src/argos-sniffer.c')
test=Path('tests/test_identity_radius.c')

hs=h.read_text()
end='\n#endif\n'
if hs.count(end)!=1: raise SystemExit(f'identity header end count={hs.count(end)}')
extractor=r'''
/* RADIUS observed identity is deliberately limited to User-Name (Attribute 1)
 * in Access-Request (Code 1). The Request Authenticator and all other
 * attributes -- including User-Password, CHAP-Password, State, EAP-Message
 * and Message-Authenticator -- are skipped without copying their values. */
static inline int argos_identity_radius_access_request(const unsigned char *p, size_t len,
                                                       int raw_mode,
                                                       argos_identity_result_t *r) {
    if (!p || !r || len < 20U || p[0] != 1U) return 0; /* Access-Request only */
    uint16_t plen = (uint16_t)(((uint16_t)p[2] << 8) | p[3]);
    if (plen < 20U || plen > 4096U || (size_t)plen > len) return 0;

    for (size_t pos = 20U; pos < (size_t)plen; ) {
        if ((size_t)plen - pos < 2U) return 0;
        uint8_t type = p[pos];
        uint8_t alen = p[pos + 1U];
        if (alen < 2U || (size_t)alen > (size_t)plen - pos) return 0;
        size_t value_len = (size_t)alen - 2U;
        if (type == 1U) {
            if (value_len == 0U || value_len > 253U) return 0;
            /* Common framework caps the emitted/hash input to 160 bytes. */
            return argos_identity_build(r, "radius", "username",
                                        p + pos + 2U, value_len, raw_mode);
        }
        pos += (size_t)alen;
    }
    return 0;
}
'''
h.write_text(hs.replace(end,'\n'+extractor+end,1))

s=src.read_text()
anchor='''                /* UDP/88 uses the same strictly bounded AS-REQ parser without\n                 * the RFC 4120 TCP record-length prefix. */\n'''
if s.count(anchor)!=1: raise SystemExit(f'UDP identity anchor count={s.count(anchor)}')
radius=r'''                /* RADIUS observed identity: client Access-Request User-Name only. */
                if (opt_identity && dport == 1812U) {
                    argos_identity_result_t ident;
                    if (argos_identity_radius_access_request(payload, (size_t)payload_len,
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
src.write_text(s.replace(anchor,radius+anchor,1))

test.write_text(r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_identity.h"

static void check(int ok,const char *msg){if(!ok){fprintf(stderr,"FAIL: %s\n",msg);exit(1);}}
static size_t make_access(unsigned char *p,size_t cap){
    static const unsigned char auth[16]={'A','U','T','H','-','S','E','C','R','E','T','-','1','2','3','4'};
    const char *user="alice@example.com";
    const char *password="PW-SECRET-DO-NOT-EMIT";
    const char *state="STATE-SECRET-DO-NOT-EMIT";
    if(cap<128) return 0;
    memset(p,0,cap);p[0]=1;p[1]=7;memcpy(p+4,auth,16);
    size_t pos=20,ul=strlen(user),pl=strlen(password),sl=strlen(state);
    p[pos]=1;p[pos+1]=(unsigned char)(ul+2);memcpy(p+pos+2,user,ul);pos+=ul+2;
    p[pos]=2;p[pos+1]=(unsigned char)(pl+2);memcpy(p+pos+2,password,pl);pos+=pl+2;
    p[pos]=24;p[pos+1]=(unsigned char)(sl+2);memcpy(p+pos+2,state,sl);pos+=sl+2;
    p[pos]=79;p[pos+1]=6;memcpy(p+pos+2,"EAP!",4);pos+=6;
    p[pos]=80;p[pos+1]=18;memset(p+pos+2,0x5a,16);pos+=18;
    p[2]=(unsigned char)(pos>>8);p[3]=(unsigned char)pos;return pos;
}
int main(void){
 unsigned char p[256];argos_identity_result_t r;size_t len=make_access(p,sizeof(p));
 check(argos_identity_radius_access_request(p,len,0,&r)==1,"Access-Request username parsed");
 check(strcmp(r.protocol,"radius")==0&&strcmp(r.type,"username")==0,"RADIUS identity labels");
 check(strncmp(r.value,"hash=",5)==0,"hash mode default");
 check(strstr(r.value,"alice")==NULL,"hash hides username");
 check(strstr(r.value,"PW-SECRET")==NULL&&strstr(r.value,"STATE-SECRET")==NULL,"sensitive attrs excluded");
 check(argos_identity_radius_access_request(p,len,1,&r)==1,"raw username parsed");
 check(strcmp(r.value,"alice@example.com")==0,"raw username exact");
 check(strstr(r.value,"AUTH-SECRET")==NULL&&strstr(r.value,"PW-SECRET")==NULL&&strstr(r.value,"STATE-SECRET")==NULL,"auth/password/state excluded");
 p[0]=2;check(argos_identity_radius_access_request(p,len,1,&r)==0,"Access-Accept ignored");
 p[0]=4;check(argos_identity_radius_access_request(p,len,1,&r)==0,"Accounting-Request ignored");
 len=make_access(p,sizeof(p));p[21]=1;check(argos_identity_radius_access_request(p,len,1,&r)==0,"zero-length attribute rejected");
 len=make_access(p,sizeof(p));p[3]=(unsigned char)(p[3]+20U);check(argos_identity_radius_access_request(p,len,1,&r)==0,"truncated declared packet rejected");
 len=make_access(p,sizeof(p));p[20]=2;check(argos_identity_radius_access_request(p,len,1,&r)==0,"packet without User-Name ignored");
 puts("RADIUS identity fixtures: PASS");return 0;
}
''')
print('staged RADIUS Access-Request observed identity extractor')
