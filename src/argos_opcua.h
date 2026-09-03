#ifndef ARGOS_OPCUA_H
#define ARGOS_OPCUA_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { char message_type[4]; uint8_t chunk_type; uint32_t message_size; char detail[160]; } argos_opcua_result_t;
static inline uint32_t aopc_le32(const unsigned char*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static inline int argos_opcua_parse(const unsigned char*p,size_t n,argos_opcua_result_t*r){if(!p||!r||n<8U)return 0;memset(r,0,sizeof(*r)); if(!((p[0]=='H'&&p[1]=='E'&&p[2]=='L')||(p[0]=='A'&&p[1]=='C'&&p[2]=='K')||(p[0]=='E'&&p[1]=='R'&&p[2]=='R')||(p[0]=='O'&&p[1]=='P'&&p[2]=='N')||(p[0]=='M'&&p[1]=='S'&&p[2]=='G')||(p[0]=='C'&&p[1]=='L'&&p[2]=='O')))return 0; r->message_type[0]=(char)p[0];r->message_type[1]=(char)p[1];r->message_type[2]=(char)p[2];r->message_type[3]='\0';r->chunk_type=p[3];r->message_size=aopc_le32(p+4);if(r->message_size<8U||r->message_size>n)return 0;(void)snprintf(r->detail,sizeof(r->detail),"type=%s;chunk=%c;size=%u",r->message_type,(char)r->chunk_type,(unsigned)r->message_size);return 1;}
#endif
