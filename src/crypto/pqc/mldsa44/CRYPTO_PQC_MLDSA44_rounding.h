/**
 * @file CRYPTO_PQC_MLDSA44_rounding.h
 * @brief Rounding and hint generation declarations for Dilithium.
 */

#ifndef CRYPTO_PQC_MLDSA44_ROUNDING_H
#define CRYPTO_PQC_MLDSA44_ROUNDING_H

#include <stdint.h>
#include "CRYPTO_PQC_MLDSA44_params.h"

int32_t power2round(int32_t *a0, int32_t a);
int32_t decompose(int32_t *a0, int32_t a);
unsigned int make_hint(int32_t a0, int32_t a1);
int32_t use_hint(int32_t a, unsigned int hint);

#endif /* CRYPTO_PQC_MLDSA44_ROUNDING_H */
