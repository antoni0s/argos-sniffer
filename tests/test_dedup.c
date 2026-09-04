#include <stdio.h>
#include <stdlib.h>
#include "../src/argos_dedup.h"
static void check(int ok,const char *m){if(!ok){fprintf(stderr,"FAIL: %s\n",m);exit(1);}}
int main(void){
 argos_dedup_state_t s={0};
 check(s.table==NULL,"unprepared table");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",0,35,1,100)==0,"disabled fail open");
 check(s.table==NULL,"disabled no allocation");
 check(argos_dedup_prepare(&s),"explicit preparation");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,100)==0,"first emits");
 check(s.table!=NULL,"prepared table retained");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,110)==1,"duplicate suppresses");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,140)==1,"sliding extends window");
 check(argos_dedup_should_suppress_at(&s,"aa","ENT","x",1,35,1,176)==0,"sliding expires from last hit");
 argos_dedup_destroy(&s);
 check(s.table==NULL,"destroy clears table");
 check(argos_dedup_prepare(&s),"explicit reactivation");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","stable",1,30,0,200)==0,"fixed first emits");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","stable",1,30,0,220)==1,"fixed suppresses inside window");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","stable",1,30,0,231)==0,"fixed does not slide");
 check(argos_dedup_should_suppress_at(&s,"aa","ARP","changed",1,30,0,232)==0,"changed payload emits");
 check(argos_dedup_should_suppress_at(&s,"bb","ARP","changed",1,30,0,233)==0,"changed identity emits");
 check(argos_dedup_should_suppress_at(&s,"cc","TLS","clock",1,30,1,300)==0,"clock seed emits");
 check(argos_dedup_should_suppress_at(&s,"cc","TLS","clock",1,30,1,299)==0,"rollback starts fail-open epoch");
 check(argos_dedup_should_suppress_at(&s,"cc","TLS","clock",1,30,1,299)==1,"new epoch suppresses duplicate");
 argos_dedup_destroy(&s);
 puts("Dedup module fixtures: PASS");return 0;
}
