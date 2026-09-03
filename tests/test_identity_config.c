#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_config.h"
static void check(int ok,const char *m){if(!ok){fprintf(stderr,"FAIL: %s\n",m);exit(1);}}
int main(void){
 argos_identity_mode_t m=ARGOS_IDENTITY_OFF;
 check(!argos_identity_enabled(m),"off disabled");
 check(argos_identity_mode_parse(NULL,&m)&&m==ARGOS_IDENTITY_HASH,"bare --identity maps hash");
 check(argos_identity_enabled(m)&&!argos_identity_raw(m),"hash enabled not raw");
 check(argos_identity_mode_parse("hash",&m)&&m==ARGOS_IDENTITY_HASH,"explicit hash");
 check(argos_identity_mode_parse("raw",&m)&&m==ARGOS_IDENTITY_RAW,"explicit raw");
 check(argos_identity_enabled(m)&&argos_identity_raw(m),"raw enabled raw");
 check(!argos_identity_mode_parse("RAW",&m),"mode names exact lowercase");
 check(!argos_identity_mode_parse("unsafe",&m),"unknown mode rejected");
 check(!argos_identity_mode_parse("raw",NULL),"NULL output rejected");
 puts("Identity config fixtures: PASS");return 0;
}
