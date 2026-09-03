#ifndef ARGOS_DNP3_H
#define ARGOS_DNP3_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { uint8_t length; uint8_t control; uint16_t destination; uint16_t source; char detail[160]; } argos_dnp3_result_t;
static inline uint16_t adnp_le16(const unsigned char*p){return (uint16_t)((uint16_t)p[0]|((uint16_t)p[1]<<8));}
static inline int argos_dnp3_parse(const unsigned char*p,size_t n,argos_dnp3_result_t*r){if(!p||!r||n<10U)return 0;memset(r,0,sizeof(*r));if(p[0]!=0x05U||p[1]!=0x64U)return 0;r->length=p[2];r->control=p[3];r->destination=adnp_le16(p+4);r->source=adnp_le16(p+6);if(r->length<5U)return 0;(void)snprintf(r->detail,sizeof(r->detail),"length=%u;control=0x%02x;destination=%u;source=%u",(unsigned)r->length,(unsigned)r->control,(unsigned)r->destination,(unsigned)r->source);return 1;}
#endif
