#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/argos_fast_complete_staging.h"

static void test_every_policy_is_bounded(void)
{
    for (unsigned i = 0; i < (unsigned)ARGOS_FC_COUNT; ++i) {
        const argos_fast_complete_policy_t *p = argos_fast_complete_staging_get((argos_fast_complete_protocol_t)i);
        assert(p != NULL);
        assert(p->name != NULL && p->name[0] != '\0');
        assert(p->max_packets > 0U && p->max_packets <= 16U);
        assert(p->max_bytes > 0U && p->max_bytes <= 32768U);
        assert(p->timeout_ms > 0U && p->timeout_ms <= 10000U);
        assert(p->max_state_bytes > 0U && p->max_state_bytes <= 1024U);
        assert(p->direction_mask != 0U);
        assert(p->complete_when != NULL && p->complete_when[0] != '\0');
        assert(p->drop_when != NULL && p->drop_when[0] != '\0');
    }
}

static void test_elephant_protocols_have_early_ceiling(void)
{
    const argos_fast_complete_policy_t *http = argos_fast_complete_staging_get(ARGOS_FC_HTTP);
    const argos_fast_complete_policy_t *smb  = argos_fast_complete_staging_get(ARGOS_FC_SMB);
    const argos_fast_complete_policy_t *nfs  = argos_fast_complete_staging_get(ARGOS_FC_NFS);
    const argos_fast_complete_policy_t *rtsp = argos_fast_complete_staging_get(ARGOS_FC_RTSP);

    assert(http->max_packets <= 4U);
    assert(smb->max_packets <= 8U);
    assert(nfs->max_packets <= 6U);
    assert(rtsp->max_packets <= 6U);

    assert(strstr(http->drop_when, "body") != NULL || strstr(http->drop_when, "bulk") != NULL);
    assert(strstr(smb->drop_when, "bulk") != NULL);
    assert(strstr(nfs->drop_when, "bulk") != NULL);
    assert(strstr(rtsp->drop_when, "media") != NULL);
}

static void test_invalid_lookup(void)
{
    assert(argos_fast_complete_staging_get((argos_fast_complete_protocol_t)ARGOS_FC_COUNT) == NULL);
}

int main(void)
{
    test_every_policy_is_bounded();
    test_elephant_protocols_have_early_ceiling();
    test_invalid_lookup();
    puts("test_fast_complete_staging: ok");
    return 0;
}
