#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/argos_enterprise.h"

static void check(int ok,const char *msg){if(!ok){fprintf(stderr,"FAIL: %s\n",msg);exit(1);}}
static void put16(unsigned char*p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);}
static void put32(unsigned char*p,unsigned v){p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24);}
static int make_ntlm(unsigned char*p,unsigned mt){memset(p,0,160);p[0]=0xfe;p[1]='S';p[2]='M';p[3]='B';put16(p+12,1);memcpy(p+64,"NTLMSSP\0",8);put32(p+72,mt);return 144;}
int main(void){
 unsigned char p[160];argos_enterprise_result_t r;int len;
 len=make_ntlm(p,1);check(argos_enterprise_parse_tcp(50000,445,p,len,&r)==1,"type1 parsed");check(r.emit&&r.complete==0,"type1 remains inspectable");
 len=make_ntlm(p,2);check(argos_enterprise_parse_tcp(445,50000,p,len,&r)==1,"type2 parsed");check(r.emit&&r.complete==0,"type2 remains inspectable");
 len=make_ntlm(p,3);check(argos_enterprise_parse_tcp(50000,445,p,len,&r)==1,"type3 parsed");check(r.emit&&r.complete==1,"type3 completes flow");
 memset(p,0,sizeof(p));p[0]=0xfe;p[1]='S';p[2]='M';p[3]='B';put16(p+12,1);check(argos_enterprise_parse_tcp(50000,445,p,80,&r)==1,"SPNEGO setup parsed");check(r.complete==0,"SPNEGO setup remains inspectable");
 puts("NTLM flow completion fixtures: PASS");return 0;
}
