#include <stdio.h>
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
