/**
 * @file pqc_backend.c
 * @brief Software PQC backend for post-quantum cryptographic operations.
 *
 * Implements the PQC portion of the crypto_api:
 *   - ML-KEM-512 (FIPS 203) — key encapsulation mechanism
 *   - ML-DSA-2 / ML-DSA-44 (FIPS 204) — digital signature algorithm
 */

#include "crypto_api.h"
#include "pqc/mlkem512/CRYPTO_PQC_MLKEM512_kem.h"
#include "pqc/mldsa44/CRYPTO_PQC_MLDSA44_sign.h"
#include <string.h>

/* ----------------------------------------------
 * ML-KEM-512 (FIPS 203 / CRYSTALS-Kyber)
 * ---------------------------------------------- */

qsac_status_t qsac_mlkem_keygen(uint8_t *pubkey, uint8_t *privkey)
{
    if (!pubkey || !privkey) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (pqcrystals_kyber512_ref_keypair(pubkey, privkey) != 0) {
        return QSAC_ERR_HSM_FAULT;
    }
    return QSAC_OK;
}

qsac_status_t qsac_mlkem_encaps(const uint8_t *pubkey,
                                 uint8_t *ciphertext,
                                 uint8_t *shared_secret)
{
    if (!pubkey || !ciphertext || !shared_secret) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (pqcrystals_kyber512_ref_enc(ciphertext, shared_secret, pubkey) != 0) {
        return QSAC_ERR_HSM_FAULT;
    }
    return QSAC_OK;
}

qsac_status_t qsac_mlkem_decaps(const uint8_t *privkey,
                                 const uint8_t *ciphertext,
                                 uint8_t *shared_secret)
{
    if (!privkey || !ciphertext || !shared_secret) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (pqcrystals_kyber512_ref_dec(shared_secret, ciphertext, privkey) != 0) {
        return QSAC_ERR_HSM_FAULT;
    }
    return QSAC_OK;
}

/* ----------------------------------------------
 * ML-DSA-2 / Dilithium2 (FIPS 204)
 * ---------------------------------------------- */

qsac_status_t qsac_mldsa_keygen(uint8_t *pubkey, uint8_t *privkey)
{
    if (!pubkey || !privkey) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (pqcrystals_dilithium2_ref_keypair(pubkey, privkey) != 0) {
        return QSAC_ERR_HSM_FAULT;
    }
    return QSAC_OK;
}

qsac_status_t qsac_mldsa_sign(const uint8_t *privkey,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig)
{
    if (!privkey || !msg || !sig) {
        return QSAC_ERR_INVALID_PARAM;
    }

    size_t sig_len = 0;
    if (pqcrystals_dilithium2_ref_signature(sig, &sig_len, msg, msg_len, privkey) != 0) {
        return QSAC_ERR_HSM_FAULT;
    }
    if (sig_len != QSAC_MLDSA_SIG_SIZE) {
        return QSAC_ERR_HSM_FAULT;
    }
    return QSAC_OK;
}

qsac_status_t qsac_mldsa_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig)
{
    if (!pubkey || !msg || !sig) {
        return QSAC_ERR_INVALID_PARAM;
    }

    int result = pqcrystals_dilithium2_ref_verify(sig, QSAC_MLDSA_SIG_SIZE,
                                                  msg, msg_len, pubkey);
    return (result == 0) ? QSAC_OK : QSAC_ERR_VERIFY_FAIL;
}
