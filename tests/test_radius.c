#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void put16(unsigned char *p, unsigned v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void put32(unsigned char *p, unsigned v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static int attr(unsigned char *p,int pos,unsigned type,const unsigned char *v,unsigned n){p[pos]=(unsigned char)type;p[pos+1]=(unsigned char)(n+2);memcpy(p+pos+2,v,n);return pos+(int)n+2;}

int main(void){
    unsigned char p[256]={0}; int pos=20;
    p[0]=1; p[1]=7;
    const unsigned char user[]="alice@example.org"; pos=attr(p,pos,1,user,sizeof(user)-1);
    unsigned char svc[4]; put32(svc,2); pos=attr(p,pos,6,svc,4);
    unsigned char npt[4]; put32(npt,19); pos=attr(p,pos,61,npt,4);
    const unsigned char call[]="AA-BB-CC-DD-EE-FF"; pos=attr(p,pos,31,call,sizeof(call)-1);
    unsigned char eap[2]={2,1}; pos=attr(p,pos,79,eap,2);
    unsigned char ma[16]={0}; pos=attr(p,pos,80,ma,16);
    unsigned char vsa[4]; put32(vsa,9); pos=attr(p,pos,26,vsa,4);
    put16(p+2,(unsigned)pos);

    argos_enterprise_result_t r;
    assert(ae_radius(p,pos,1812,&r)==1 && r.emit);
    assert(strcmp(r.proto,"radius")==0);
    assert(strstr(r.detail,"plane=auth") && strstr(r.detail,"Access-Request"));
    assert(strstr(r.detail,"service_type=2") && strstr(r.detail,"nas_port_type=19"));
    assert(strstr(r.detail,"eap=1") && strstr(r.detail,"message_auth=1") && strstr(r.detail,"vendor_id=9"));
    assert(strstr(r.detail,"alice")==NULL && strstr(r.detail,"AA-BB")==NULL);

    memset(p,0,sizeof(p)); pos=20; p[0]=4; p[1]=9;
    unsigned char ast[4]; put32(ast,1); pos=attr(p,pos,40,ast,4); put16(p+2,(unsigned)pos);
    assert(ae_radius(p,pos,1813,&r)==1 && strstr(r.detail,"plane=accounting") && strstr(r.detail,"acct_status=1"));

    p[20]=1; p[21]=1; assert(ae_radius(p,pos,1813,&r)==0);
    puts("RADIUS fixtures: PASS");
    return 0;
}
