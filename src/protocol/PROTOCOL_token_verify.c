/**
 * @file PROTOCOL_token_verify.c
 * @brief Local post-quantum access-token issuance and verification.
 */

#include "PROTOCOL_token_verify.h"
#include <string.h>

static uint8_t g_authority_pubkey[QSAC_MLDSA_PUBKEY_SIZE];
static uint8_t g_authority_key_loaded = 0;

qsac_status_t qsac_token_load_authority_key(const uint8_t *pubkey)
{
    if (!pubkey) {
        return QSAC_ERR_INVALID_PARAM;
    }
    memcpy(g_authority_pubkey, pubkey, QSAC_MLDSA_PUBKEY_SIZE);
    g_authority_key_loaded = 1;
    return QSAC_OK;
}

qsac_status_t qsac_token_issue(const uint8_t *authority_privkey,
                               const qsac_token_payload_t *payload,
                               qsac_access_token_t *out_token)
{
    qsac_status_t status;

    if (!authority_privkey || !payload || !out_token) {
        return QSAC_ERR_INVALID_PARAM;
    }

    memcpy(&out_token->payload, payload, sizeof(qsac_token_payload_t));

    status = qsac_mldsa_sign(authority_privkey,
                             (const uint8_t *)&out_token->payload,
                             sizeof(qsac_token_payload_t),
                             out_token->signature);
    return status;
}

qsac_status_t qsac_token_verify(const qsac_access_token_t *token,
                                uint32_t current_time,
                                uint32_t *permissions)
{
    qsac_status_t status;

    if (!token || !permissions) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (!g_authority_key_loaded) {
        return QSAC_ERR_KEY_NOT_FOUND;
    }

    /* Check token temporal validity (issued_at <= current_time <= expires_at) */
    if (token->payload.issued_at > current_time) {
        return QSAC_ERR_VERIFY_FAIL; /* Token from the future */
    }

    if (token->payload.expires_at < current_time) {
        return QSAC_ERR_VERIFY_FAIL; /* Token expired */
    }

    /* Verify ML-DSA-44 signature against authority public key */
    status = qsac_mldsa_verify(g_authority_pubkey,
                               (const uint8_t *)&token->payload,
                               sizeof(qsac_token_payload_t),
                               token->signature);
    if (status != QSAC_OK) {
        return QSAC_ERR_VERIFY_FAIL;
    }

    *permissions = token->payload.permissions;
    return QSAC_OK;
}
