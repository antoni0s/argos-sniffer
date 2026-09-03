#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/argos_multicast_membership.h"

int main(void) {
    argos_membership_result_t r;

    unsigned char igmp2[] = {0x16,0,0,0,239,1,2,3};
    assert(argos_igmp_parse(igmp2,sizeof(igmp2),&r));
    assert(strcmp(r.proto,"IGMP")==0 && strstr(r.detail,"version=2") && strstr(r.detail,"type=report"));
    assert(strstr(r.detail,"239.1.2.3")==NULL);

    unsigned char igmp3q[16] = {0x11,100,0,0,239,1,1,1,0,0,0,1,10,0,0,1};
    assert(argos_igmp_parse(igmp3q,sizeof(igmp3q),&r));
    assert(strstr(r.detail,"version=3") && strstr(r.detail,"type=query") && strstr(r.detail,"sources=1"));

    unsigned char igmp3r[20] = {0x22,0,0,0,0,0,0,1,1,0,0,1,239,1,1,2,10,0,0,1};
    assert(argos_igmp_parse(igmp3r,sizeof(igmp3r),&r));
    assert(strstr(r.detail,"records=1") && strstr(r.detail,"sources=1"));

    unsigned char mld1[24] = {131,0,0,0,0,0,0,0};
    mld1[8]=0xff; mld1[9]=0x02; mld1[23]=1;
    assert(argos_mld_parse(mld1,sizeof(mld1),&r));
    assert(strcmp(r.proto,"MLD")==0 && strstr(r.detail,"version=1") && strstr(r.detail,"type=report"));

    unsigned char mld2q[44] = {130,0,0,0,0,100,0,0};
    mld2q[8]=0xff; mld2q[9]=0x02; mld2q[23]=1; mld2q[24]=2; mld2q[25]=125; mld2q[26]=0; mld2q[27]=1; mld2q[28]=0x20; mld2q[29]=1;
    assert(argos_mld_parse(mld2q,sizeof(mld2q),&r));
    assert(strstr(r.detail,"version=2") && strstr(r.detail,"type=query") && strstr(r.detail,"sources=1"));

    unsigned char mld2r[44] = {143,0,0,0,0,0,0,1,1,0,0,1};
    mld2r[12]=0xff; mld2r[13]=0x02; mld2r[27]=2; mld2r[28]=0x20; mld2r[29]=1;
    assert(argos_mld_parse(mld2r,sizeof(mld2r),&r));
    assert(strstr(r.detail,"records=1") && strstr(r.detail,"sources=1"));

    igmp3r[7]=2; assert(!argos_igmp_parse(igmp3r,sizeof(igmp3r),&r));
    mld2r[7]=2; assert(!argos_mld_parse(mld2r,sizeof(mld2r),&r));
    puts("IGMP/MLD fixtures: PASS");
    return 0;
}
