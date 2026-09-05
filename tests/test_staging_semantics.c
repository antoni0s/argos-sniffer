#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/argos_ah.h"
#include "../src/argos_airplay.h"
#include "../src/argos_cast.h"
#include "../src/argos_dlna.h"
#include "../src/argos_dnp3.h"
#include "../src/argos_esp.h"
#include "../src/argos_ftp.h"
#include "../src/argos_ike.h"
#include "../src/argos_knx.h"
#include "../src/argos_ldap.h"
#include "../src/argos_ldaps.h"
#include "../src/argos_matter.h"
#include "../src/argos_mongodb.h"
#include "../src/argos_nvmeof.h"
#include "../src/argos_opcua.h"
#include "../src/argos_openvpn.h"
#include "../src/argos_redis.h"
#include "../src/argos_rtcp.h"
#include "../src/argos_rtp.h"
#include "../src/argos_rtsp.h"
#include "../src/argos_s7.h"
#include "../src/argos_tacacs.h"
#include "../src/argos_thread.h"
#include "../src/argos_winrm.h"

#define SZ(a) (sizeof(a) / sizeof((a)[0]))

static void test_ah(void){unsigned char p[12]={6,1,0,0,0,0,0,1,0,0,0,2};argos_ah_result_t r;assert(argos_ah_parse(p,SZ(p),&r)==1);p[7]=0;assert(argos_ah_parse(p,SZ(p),&r)==0);p[7]=1;assert(argos_ah_parse(p,SZ(p)-1U,&r)==0);} 
static void test_airplay(void){static const unsigned char ok[]="POST /play RTSP/1.0\r\nX-Apple-Device-ID: aa\r\n\r\n",bad[]="GET / HTTP/1.1\r\n\r\n";argos_airplay_result_t r;assert(argos_airplay_parse(ok,SZ(ok)-1U,&r)==1);assert(argos_airplay_parse(bad,SZ(bad)-1U,&r)==0);assert(argos_airplay_parse(ok,7U,&r)==0);} 
static void test_cast(void){unsigned char ok[10]={0,0,0,6,'C','A','S','T','V','2'},bad[10]={0,0,0,6,'x','x','x','x','x','x'};argos_cast_result_t r;assert(argos_cast_parse(ok,SZ(ok),&r)==1);assert(argos_cast_parse(bad,SZ(bad),&r)==0);assert(argos_cast_parse(ok,SZ(ok)-1U,&r)==0);} 
static void test_dlna(void){static const unsigned char ok[]="contentFeatures.dlna.org: DLNA.ORG_OP=01\r\n",bad[]="ordinary payload";argos_dlna_result_t r;assert(argos_dlna_parse(ok,SZ(ok)-1U,&r)==1);assert(argos_dlna_parse(bad,SZ(bad)-1U,&r)==0);assert(argos_dlna_parse(ok,7U,&r)==0);} 
static void test_dnp3(void){unsigned char p[10]={0x05,0x64,0x05,0,0,0,0,0,0,0};argos_dnp3_result_t r;assert(argos_dnp3_parse(p,SZ(p),&r)==1);p[0]=4;assert(argos_dnp3_parse(p,SZ(p),&r)==0);p[0]=5;assert(argos_dnp3_parse(p,SZ(p)-1U,&r)==0);} 
static void test_esp(void){unsigned char p[8]={0,0,0,1,0,0,0,2};argos_esp_result_t r;assert(argos_esp_parse(p,SZ(p),&r)==1);p[3]=0;assert(argos_esp_parse(p,SZ(p),&r)==0);p[3]=1;assert(argos_esp_parse(p,SZ(p)-1U,&r)==0);} 
static void test_ftp(void){static const unsigned char ok[]="USER alice\r\n",bad[]="NOOP\r\n";argos_ftp_result_t r;assert(argos_ftp_parse(ok,SZ(ok)-1U,&r)==1);assert(argos_ftp_parse(bad,SZ(bad)-1U,&r)==0);assert(argos_ftp_parse(ok,2U,&r)==0);} 
static void test_ike(void){unsigned char p[28]={0};argos_ike_result_t r;p[0]=1;p[17]=0x20;p[18]=34;p[19]=8;p[27]=28;assert(argos_ike_parse(p,SZ(p),&r)==1);p[17]=0x30;assert(argos_ike_parse(p,SZ(p),&r)==0);p[17]=0x20;assert(argos_ike_parse(p,SZ(p)-1U,&r)==0);} 
static void test_knx(void){unsigned char p[6]={0x06,0x10,0x02,0x01,0,0x06};argos_knx_result_t r;assert(argos_knx_parse(p,SZ(p),&r)==1);p[0]=5;assert(argos_knx_parse(p,SZ(p),&r)==0);p[0]=6;assert(argos_knx_parse(p,SZ(p)-1U,&r)==0);} 
static void test_ldap(void){unsigned char ok[7]={0x30,0x05,0x02,0x01,0x01,0x42,0},bad[7]={0x30,0x03,0x02,0x01,0x01,0x42,0};argos_ldap_result_t r;assert(argos_ldap_parse(ok,SZ(ok),&r)==1);assert(argos_ldap_parse(bad,SZ(bad),&r)==0);assert(argos_ldap_parse(ok,SZ(ok)-1U,&r)==0);} 
static void test_ldaps(void){unsigned char p[5]={22,3,3,0,0};argos_ldaps_result_t r;assert(argos_ldaps_parse(p,SZ(p),&r)==1);p[0]=19;assert(argos_ldaps_parse(p,SZ(p),&r)==0);p[0]=22;assert(argos_ldaps_parse(p,SZ(p)-1U,&r)==0);} 
static void test_matter(void){unsigned char p[8]={0};argos_matter_result_t r;assert(argos_matter_parse(p,SZ(p),&r)==1);p[0]=0x20;assert(argos_matter_parse(p,SZ(p),&r)==0);p[0]=0;assert(argos_matter_parse(p,SZ(p)-1U,&r)==0);} 
static void test_mongodb(void){unsigned char p[16]={0};argos_mongodb_result_t r;p[0]=16;p[12]=0xdd;p[13]=7;assert(argos_mongodb_parse(p,SZ(p),&r)==1);p[12]=p[13]=0;assert(argos_mongodb_parse(p,SZ(p),&r)==0);p[12]=0xdd;p[13]=7;assert(argos_mongodb_parse(p,SZ(p)-1U,&r)==0);} 
static void test_nvmeof(void){unsigned char p[8]={0};argos_nvmeof_result_t r;p[0]=4;p[2]=8;p[4]=8;assert(argos_nvmeof_parse(p,SZ(p),&r)==1);p[0]=0xff;assert(argos_nvmeof_parse(p,SZ(p),&r)==0);p[0]=4;p[4]=9;assert(argos_nvmeof_parse(p,SZ(p),&r)==0);} 
static void test_opcua(void){unsigned char p[8]={'H','E','L','F',8,0,0,0};argos_opcua_result_t r;assert(argos_opcua_parse(p,SZ(p),&r)==1);p[0]='X';assert(argos_opcua_parse(p,SZ(p),&r)==0);p[0]='H';assert(argos_opcua_parse(p,SZ(p)-1U,&r)==0);} 
static void test_openvpn(void){unsigned char p[1]={8};argos_openvpn_result_t r;assert(argos_openvpn_parse(p,1U,&r)==1);p[0]=0;assert(argos_openvpn_parse(p,1U,&r)==0);p[0]=8;assert(argos_openvpn_parse(p,0U,&r)==0);} 
static void test_redis(void){static const unsigned char ok[]="PING\r\n";unsigned char bad[1]={0};argos_redis_result_t r;assert(argos_redis_parse(ok,SZ(ok)-1U,&r)==1);assert(argos_redis_parse(bad,1U,&r)==0);assert(argos_redis_parse(ok,0U,&r)==0);} 
static void test_rtcp(void){unsigned char p[4]={0x80,200,0,0};argos_rtcp_result_t r;assert(argos_rtcp_parse(p,SZ(p),&r)==1);p[0]=0x40;assert(argos_rtcp_parse(p,SZ(p),&r)==0);p[0]=0x80;assert(argos_rtcp_parse(p,SZ(p)-1U,&r)==0);} 
static void test_rtp(void){unsigned char p[12]={0x80,96,0,1,0,0,0,2,0,0,0,3};argos_rtp_result_t r;assert(argos_rtp_parse(p,SZ(p),&r)==1);p[0]=0x40;assert(argos_rtp_parse(p,SZ(p),&r)==0);p[0]=0x80;assert(argos_rtp_parse(p,SZ(p)-1U,&r)==0);} 
static void test_rtsp(void){static const unsigned char ok[]="OPTIONS rtsp://example RTSP/1.0\r\n\r\n",bad[]="options rtsp://example RTSP/1.0\r\n\r\n",edge[]="OPTIONS x RTSP/1.0";argos_rtsp_result_t r;assert(argos_rtsp_parse(ok,SZ(ok)-1U,&r)==1);assert(argos_rtsp_parse(bad,SZ(bad)-1U,&r)==0);assert(argos_rtsp_parse(edge,17U,&r)==0);} 
static void test_s7(void){unsigned char p[10]={0x32,1,0,0,0,1,0,0,0,0};argos_s7_result_t r;assert(argos_s7_parse(p,SZ(p),&r)==1);p[0]=0x31;assert(argos_s7_parse(p,SZ(p),&r)==0);p[0]=0x32;assert(argos_s7_parse(p,SZ(p)-1U,&r)==0);} 
static void test_tacacs(void){unsigned char p[12]={0xc0,1,1,0,0,0,0,1,0,0,0,0};argos_tacacs_result_t r;assert(argos_tacacs_parse(p,SZ(p),&r)==1);p[0]=0xb0;assert(argos_tacacs_parse(p,SZ(p),&r)==0);p[0]=0xc0;assert(argos_tacacs_parse(p,SZ(p)-1U,&r)==0);} 
static void test_thread(void){unsigned char ss[5]={0xb1,0x12,0x34,0x56,0x78};argos_thread_result_t r;assert(argos_thread_parse(ss,SZ(ss),&r)==1&&r.src_short==0x1234U&&r.dst_short==0x5678U);ss[0]=0x31;assert(argos_thread_parse(ss,SZ(ss),&r)==0);ss[0]=0xb1;assert(argos_thread_parse(ss,SZ(ss)-1U,&r)==0);unsigned char deep[6]={0xbf,20,0x12,0x34,0x56,0x78};assert(argos_thread_parse(deep,SZ(deep),&r)==1&&r.hops_left==20U);assert(argos_thread_parse(deep,SZ(deep)-1U,&r)==0);unsigned char ll[17]={0x81};assert(argos_thread_parse(ll,SZ(ll),&r)==1);assert(argos_thread_parse(ll,5U,&r)==0);} 
static void test_winrm(void){static const unsigned char ok[]="POST /wsman HTTP/1.1\r\nContent-Type: application/soap+xml\r\n\r\n",bad[]="GET / HTTP/1.1\r\n\r\n";argos_winrm_result_t r;assert(argos_winrm_parse(ok,SZ(ok)-1U,&r)==1);assert(argos_winrm_parse(bad,SZ(bad)-1U,&r)==0);assert(argos_winrm_parse(ok,7U,&r)==0);} 

int main(void){test_ah();test_airplay();test_cast();test_dlna();test_dnp3();test_esp();test_ftp();test_ike();test_knx();test_ldap();test_ldaps();test_matter();test_mongodb();test_nvmeof();test_opcua();test_openvpn();test_redis();test_rtcp();test_rtp();test_rtsp();test_s7();test_tacacs();test_thread();test_winrm();return 0;}
