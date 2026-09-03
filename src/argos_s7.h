#ifndef ARGOS_S7_H
#define ARGOS_S7_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint8_t protocol_id; uint8_t rosctr; uint16_t pdu_ref; uint16_t parameter_length; uint16_t data_length; char detail[192]; } argos_s7_result_t;
static inline uint16_t as7_be16(const unsigned char*p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);}
static inline int argos_s7_parse(const unsigned char*p,size_t n,argos_s7_result_t*r){if(!p||!r||n<10U)return 0;memset(r,0,sizeof(*r));if(p[0]!=0x32U)return 0;r->protocol_id=p[0];r->rosctr=p[1];r->pdu_ref=as7_be16(p+4);r->parameter_length=as7_be16(p+6);r->data_length=as7_be16(p+8);size_t h=(r->rosctr==0x02U||r->rosctr==0x03U)?12U:10U;if(n<h+(size_t)r->parameter_length+(size_t)r->data_length)return 0;(void)snprintf(r->detail,sizeof(r->detail),"protocol=0x32;rosctr=0x%02x;pdu_ref=%u;param_len=%u;data_len=%u",(unsigned)r->rosctr,(unsigned)r->pdu_ref,(unsigned)r->parameter_length,(unsigned)r->data_length);return 1;}
#endif
