#include <assert.h>
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
