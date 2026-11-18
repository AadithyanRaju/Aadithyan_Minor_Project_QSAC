/**
 * @file CRYPTO_PQC_MLDSA44_sign.h
 * @brief Digital signature algorithms declarations for ML-DSA-44 (Dilithium-2).
 */

#ifndef CRYPTO_PQC_MLDSA44_SIGN_H
#define CRYPTO_PQC_MLDSA44_SIGN_H

#include <stdint.h>
#include <stddef.h>
#include "CRYPTO_PQC_MLDSA44_params.h"

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_dilithium2_ref_signature(uint8_t *sig,
                                        size_t *siglen,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *sk);

int pqcrystals_dilithium2_ref_verify(const uint8_t *sig,
                                     size_t siglen,
                                     const uint8_t *m,
                                     size_t mlen,
                                     const uint8_t *pk);

#endif /* CRYPTO_PQC_MLDSA44_SIGN_H */
