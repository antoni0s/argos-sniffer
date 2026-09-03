#ifndef ARGOS_SYSLOG_H
#define ARGOS_SYSLOG_H
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef struct { int pri; int facility; int severity; int rfc5424; char detail[192]; } argos_syslog_result_t;
static inline int argos_syslog_parse(const unsigned char *p,size_t n,argos_syslog_result_t *r){ if(!p||!r||n<3U||p[0]!='<')return 0; memset(r,0,sizeof(*r)); size_t i=1U; int pri=0,d=0; while(i<n&&p[i]>='0'&&p[i]<='9'&&d<3){pri=pri*10+(p[i]-'0');i++;d++;} if(!d||i>=n||p[i]!='>'||pri>191)return 0; r->pri=pri;r->facility=pri/8;r->severity=pri%8;i++; r->rfc5424=(i+2U<n&&p[i]>='1'&&p[i]<='9'&&p[i+1]==' '); (void)snprintf(r->detail,sizeof(r->detail),"pri=%d;facility=%d;severity=%d;format=%s",r->pri,r->facility,r->severity,r->rfc5424?"rfc5424":"rfc3164"); return 1; }
#endif
