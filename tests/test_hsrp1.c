#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_fhrp.h"
static void expect(int ok,const char *s){if(!ok){fprintf(stderr,"FAIL: %s\n",s);exit(1);}}
int main(void){
 unsigned char p[20]={0,0,16,3,10,105,1,0,'c','i','s','c','o',0,0,0,172,28,230,1};
 argos_hsrp1_result_t r;
 expect(argos_hsrp1_parse(p,sizeof(p),&r),"valid HSRPv1 hello");
 expect(r.wire_version==0 && r.opcode==0 && r.state==16 && r.priority==105 && r.group==1,"HSRP identity");
 expect(strstr(r.detail,"opcode=hello")!=NULL && strstr(r.detail,"state=active")!=NULL,"opcode/state detail");
 expect(strstr(r.detail,"auth_present=1")!=NULL,"auth presence only");
 expect(strstr(r.detail,"cisco")==NULL && strstr(r.detail,"172.28.230.1")==NULL,"auth and VIP not emitted");
 p[1]=1; expect(argos_hsrp1_parse(p,sizeof(p),&r) && strstr(r.detail,"opcode=coup")!=NULL,"coup");
 p[1]=2; expect(argos_hsrp1_parse(p,sizeof(p),&r) && strstr(r.detail,"opcode=resign")!=NULL,"resign");
 p[0]=1; expect(!argos_hsrp1_parse(p,sizeof(p),&r),"non-v1 wire version rejected");
 p[0]=0; p[1]=3; expect(!argos_hsrp1_parse(p,sizeof(p),&r),"unknown opcode rejected");
 expect(!argos_hsrp1_parse(p,19,&r),"short payload rejected");
 puts("HSRPv1 fixtures: PASS"); return 0;
}
