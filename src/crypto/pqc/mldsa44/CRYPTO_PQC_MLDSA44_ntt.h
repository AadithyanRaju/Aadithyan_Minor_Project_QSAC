/**
 * @file CRYPTO_PQC_MLDSA44_ntt.h
 * @brief Number Theoretic Transform declarations for Dilithium.
 */

#ifndef CRYPTO_PQC_MLDSA44_NTT_H
#define CRYPTO_PQC_MLDSA44_NTT_H

#include <stdint.h>
#include "CRYPTO_PQC_MLDSA44_params.h"

extern const int32_t dilithium_zetas[256];
extern const int32_t dilithium_zetas_inv[256];

void dilithium_ntt(int32_t a[256]);
void dilithium_invntt_tomont(int32_t a[256]);

#endif /* CRYPTO_PQC_MLDSA44_NTT_H */
