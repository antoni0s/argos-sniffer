#ifndef ARGOS_FTP_H
#define ARGOS_FTP_H

/* Argos-Sniffer v6 staging engine: FTP.
 * Standalone passive parser only; not wired into CLI/runtime yet.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    int seen;
    int is_command;
    int is_response;
    int passive_mode;
    int tls_upgrade;
    unsigned response_code;
    char verb[12];
    char server[128];
    char detail[320];
} argos_ftp_result_t;

static inline int aftp_ci_prefix(const unsigned char *p, size_t n, const char *s) {
    size_t m = strlen(s);
    if (n < m) return 0;
    for (size_t i = 0; i < m; ++i)
        if (tolower((unsigned char)p[i]) != tolower((unsigned char)s[i])) return 0;
    return 1;
}

static inline void aftp_copy_token(const unsigned char *p, size_t n, char *out, size_t cap) {
    if (!out || cap == 0U) return;
    size_t i = 0U;
    while (i < n && i + 1U < cap && p[i] > 0x20U && p[i] < 0x7fU) {
        out[i] = (char)p[i];
        ++i;
    }
    out[i] = '\0';
}

static inline int argos_ftp_parse(const unsigned char *p, size_t n, argos_ftp_result_t *r) {
    if (!p || !r || n < 3U) return 0;
    memset(r, 0, sizeof(*r));

    if (n >= 4U && isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1]) &&
        isdigit((unsigned char)p[2]) && (p[3] == ' ' || p[3] == '-')) {
        r->is_response = 1;
        r->seen = 1;
        r->response_code = (unsigned)(p[0]-'0')*100U + (unsigned)(p[1]-'0')*10U + (unsigned)(p[2]-'0');
        if (r->response_code == 220U) {
            size_t off = 4U, take = n > off ? n - off : 0U;
            if (take >= sizeof(r->server)) take = sizeof(r->server) - 1U;
            for (size_t i=0;i<take;i++) {
                unsigned char c=p[off+i];
                r->server[i]=(char)((c>=0x20U&&c<0x7fU&&c!='|'&&c!=';')?c:' ');
            }
            r->server[take]='\0';
        }
        if (r->response_code == 227U || r->response_code == 229U) r->passive_mode = 1;
    } else {
        static const char *verbs[] = {"USER","PASS","SYST","FEAT","AUTH","PBSZ","PROT","PASV","EPSV","PORT","EPRT"};
        for (size_t i=0;i<sizeof(verbs)/sizeof(verbs[0]);++i) {
            size_t m=strlen(verbs[i]);
            if (n >= m && aftp_ci_prefix(p,n,verbs[i]) && (n==m || p[m]==' ' || p[m]=='\r' || p[m]=='\n')) {
                r->seen=1; r->is_command=1;
                (void)snprintf(r->verb,sizeof(r->verb),"%s",verbs[i]);
                if (!strcmp(verbs[i],"AUTH") && n >= m+4U && aftp_ci_prefix(p+m+1U,n-m-1U,"TLS")) r->tls_upgrade=1;
                if (!strcmp(verbs[i],"PASV") || !strcmp(verbs[i],"EPSV")) r->passive_mode=1;
                break;
            }
        }
    }

    if (!r->seen) return 0;
    (void)snprintf(r->detail,sizeof(r->detail),"kind=%s;verb=%s;code=%u;passive=%u;tls_upgrade=%u;server=%s",
                   r->is_command?"command":"response",r->verb,(unsigned)r->response_code,
                   (unsigned)r->passive_mode,(unsigned)r->tls_upgrade,r->server);
    return 1;
}

#endif /* ARGOS_FTP_H */
