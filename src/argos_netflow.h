#ifndef ARGOS_NETFLOW_H
#define ARGOS_NETFLOW_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint16_t version; uint16_t count; uint32_t sequence; uint32_t source_id; char detail[192]; } argos_netflow_result_t;
static inline uint16_t anf_be16(const unsigned char*p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);} static inline uint32_t anf_be32(const unsigned char*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static inline int argos_netflow_parse(const unsigned char*p,size_t n,argos_netflow_result_t*r){if(!p||!r||n<16U)return 0;memset(r,0,sizeof(*r));r->version=anf_be16(p);if(r->version!=5U&&r->version!=7U&&r->version!=9U)return 0;r->count=anf_be16(p+2);if(r->version==9U){if(n<20U)return 0;r->sequence=anf_be32(p+12);r->source_id=anf_be32(p+16);}else{r->sequence=anf_be32(p+16);}(void)snprintf(r->detail,sizeof(r->detail),"version=%u;count=%u;sequence=%u;source_id=%u",(unsigned)r->version,(unsigned)r->count,(unsigned)r->sequence,(unsigned)r->source_id);return 1;}
#endif
