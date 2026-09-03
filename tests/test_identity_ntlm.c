#include <stdio.h>
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
