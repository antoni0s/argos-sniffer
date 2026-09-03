#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_fhrp.h"
static void put16(unsigned char *p,uint16_t v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
    argos_vrrp_result_t r;
    unsigned char v2[32]={0};
    v2[0]=0x21; v2[1]=42; v2[2]=100; v2[3]=2; v2[4]=0; v2[5]=1;
    expect(argos_vrrp_parse(v2,24,4,&r),"VRRPv2 IPv4 advertisement");
    expect(r.version==2 && r.vrid==42 && r.priority==100 && r.address_count==2,"v2 identity");
    expect(strstr(r.detail,"interval_s=1")!=NULL && strstr(r.detail,"auth_type=0")!=NULL,"v2 interval/auth");
    expect(!argos_vrrp_parse(v2,24,6,&r),"VRRPv2 rejected on IPv6");

    unsigned char v3[40]={0};
    v3[0]=0x31; v3[1]=7; v3[2]=255; v3[3]=1; put16(v3+4,25);
    expect(argos_vrrp_parse(v3,12,4,&r),"VRRPv3 IPv4 advertisement");
    expect(r.version==3 && r.owner==1 && r.advert_interval==25,"v3 owner/interval");
    expect(strstr(r.detail,"family=ipv4")!=NULL && strstr(r.detail,"interval_cs=25")!=NULL,"v3 IPv4 detail");

    v3[2]=0; v3[3]=1; put16(v3+4,100);
    expect(argos_vrrp_parse(v3,24,6,&r),"VRRPv3 IPv6 advertisement");
    expect(r.relinquish==1 && strstr(r.detail,"family=ipv6")!=NULL,"v3 IPv6 relinquish");

    v3[0]=0x32; expect(!argos_vrrp_parse(v3,24,6,&r),"unknown VRRP type rejected");
    v3[0]=0x31; v3[1]=0; expect(!argos_vrrp_parse(v3,24,6,&r),"VRID zero rejected");
    v3[1]=7; v3[3]=0; expect(!argos_vrrp_parse(v3,24,6,&r),"zero address count rejected");
    puts("VRRP fixtures: PASS");
    return 0;
}
