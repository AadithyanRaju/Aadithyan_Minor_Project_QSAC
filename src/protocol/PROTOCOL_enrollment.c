/**
 * @file PROTOCOL_enrollment.c
 * @brief Device enrollment protocol implementation.
 */

#include "PROTOCOL_enrollment.h"
#include <string.h>

typedef struct {
    uint8_t ecc_pubkey[QSAC_ECC_PUBKEY_SIZE];
    uint8_t mldsa_pubkey[QSAC_MLDSA_PUBKEY_SIZE];
    uint8_t mldsa_privkey[QSAC_MLDSA_PRIVKEY_SIZE];
    uint8_t enrolled;
} enrollment_state_t;

static enrollment_state_t g_enrollment = {0};

qsac_status_t qsac_enrollment_execute(void)
{
    qsac_status_t status;

    /* Generate ECC P-256 identity keypair */
    status = qsac_ecc_keygen(QSAC_KEY_SLOT_ECC_IDENTITY, g_enrollment.ecc_pubkey);
    if (status != QSAC_OK) {
        return status;
    }

    /* Generate ML-DSA-44 identity keypair */
    status = qsac_mldsa_keygen(g_enrollment.mldsa_pubkey, g_enrollment.mldsa_privkey);
    if (status != QSAC_OK) {
        return status;
    }

    g_enrollment.enrolled = 1;
    return QSAC_OK;
}

int qsac_enrollment_is_complete(void)
{
    return g_enrollment.enrolled;
}

const uint8_t *qsac_enrollment_get_ecc_pubkey(void)
{
    return g_enrollment.ecc_pubkey;
}

const uint8_t *qsac_enrollment_get_mldsa_pubkey(void)
{
    return g_enrollment.mldsa_pubkey;
}

const uint8_t *qsac_enrollment_get_mldsa_privkey(void)
{
    return g_enrollment.mldsa_privkey;
}
