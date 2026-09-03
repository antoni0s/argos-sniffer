#ifndef ARGOS_SFLOW_H
#define ARGOS_SFLOW_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint32_t version; uint32_t address_type; uint32_t sub_agent_id; uint32_t sequence; uint32_t samples; char detail[192]; } argos_sflow_result_t;
static inline uint32_t asf_be32(const unsigned char*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static inline int argos_sflow_parse(const unsigned char*p,size_t n,argos_sflow_result_t*r){if(!p||!r||n<28U)return 0;memset(r,0,sizeof(*r));r->version=asf_be32(p);if(r->version!=5U)return 0;r->address_type=asf_be32(p+4);size_t off=(r->address_type==1U)?12U:(r->address_type==2U?24U:0U);if(!off||n<off+16U)return 0;r->sub_agent_id=asf_be32(p+off);r->sequence=asf_be32(p+off+4);r->samples=asf_be32(p+off+12);(void)snprintf(r->detail,sizeof(r->detail),"version=5;agent_addr_type=%u;sub_agent=%u;sequence=%u;samples=%u",(unsigned)r->address_type,(unsigned)r->sub_agent_id,(unsigned)r->sequence,(unsigned)r->samples);return 1;}
#endif
