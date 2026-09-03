#ifndef ARGOS_KNX_H
#define ARGOS_KNX_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint8_t header_length; uint8_t protocol_version; uint16_t service_type; uint16_t total_length; char detail[160]; } argos_knx_result_t;
static inline uint16_t aknx_be16(const unsigned char*p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);}
static inline int argos_knx_parse(const unsigned char*p,size_t n,argos_knx_result_t*r){if(!p||!r||n<6U)return 0;memset(r,0,sizeof(*r));r->header_length=p[0];r->protocol_version=p[1];r->service_type=aknx_be16(p+2);r->total_length=aknx_be16(p+4);if(r->header_length<6U||r->total_length<r->header_length||r->total_length>n)return 0;if(r->protocol_version!=0x10U)return 0;(void)snprintf(r->detail,sizeof(r->detail),"version=0x%02x;service=0x%04x;length=%u",(unsigned)r->protocol_version,(unsigned)r->service_type,(unsigned)r->total_length);return 1;}
#endif
