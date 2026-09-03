#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_config.h"
static void check(int ok,const char *m){if(!ok){fprintf(stderr,"FAIL: %s\n",m);exit(1);}}
int main(void){
 argos_runtime_config_t c;
 argos_runtime_config_init(&c);
 check(!c.enterprise_enabled,"enterprise default off");
 check(c.enterprise_rate_limited==1,"enterprise default quiet");
 check(c.identity_mode==ARGOS_IDENTITY_OFF,"identity default off");
 check(c.wireguard_port==51820U&&!c.wireguard_port_explicit,"wireguard defaults");
 check(argos_runtime_config_validate(&c)==NULL,"default config valid");
 c.identity_mode=ARGOS_IDENTITY_HASH;
 check(argos_runtime_config_validate(&c)!=NULL,"identity requires enterprise");
 argos_runtime_enable_enterprise(&c,0);
 check(c.enterprise_enabled&&c.enterprise_rate_limited,"quiet enterprise mode");
 check(argos_runtime_config_validate(&c)==NULL,"identity+enterprise valid");
 argos_runtime_enable_enterprise(&c,1);
 check(c.enterprise_enabled&&!c.enterprise_rate_limited,"verbose enterprise mode");
 c.wireguard_port=44444U;c.wireguard_port_explicit=1;
 check(argos_runtime_config_validate(&c)==NULL,"explicit WG with enterprise valid");
 argos_runtime_config_init(&c);c.wireguard_port_explicit=1;
 check(strstr(argos_runtime_config_validate(&c),"wireguard-port")!=NULL,"WG dependency error");
 check(strstr(argos_runtime_config_validate(NULL),"invalid runtime")!=NULL,"NULL validation");
 puts("Runtime config fixtures: PASS");return 0;
}
