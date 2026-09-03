#ifndef ARGOS_IPFIX_H
#define ARGOS_IPFIX_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint16_t version; uint16_t length; uint32_t export_time; uint32_t sequence; uint32_t observation_domain; char detail[192]; } argos_ipfix_result_t;
static inline uint16_t aip_be16(const unsigned char*p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);} static inline uint32_t aip_be32(const unsigned char*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static inline int argos_ipfix_parse(const unsigned char*p,size_t n,argos_ipfix_result_t*r){if(!p||!r||n<16U)return 0;memset(r,0,sizeof(*r));r->version=aip_be16(p);r->length=aip_be16(p+2);if(r->version!=10U||r->length<16U||r->length>n)return 0;r->export_time=aip_be32(p+4);r->sequence=aip_be32(p+8);r->observation_domain=aip_be32(p+12);(void)snprintf(r->detail,sizeof(r->detail),"version=10;length=%u;export_time=%u;sequence=%u;observation_domain=%u",(unsigned)r->length,(unsigned)r->export_time,(unsigned)r->sequence,(unsigned)r->observation_domain);return 1;}
#endif
