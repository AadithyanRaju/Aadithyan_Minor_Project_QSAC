/**
 * @file CRYPTO_PQC_MLDSA44_reduce.h
 * @brief Modular reduction declarations for Dilithium.
 */

#ifndef CRYPTO_PQC_MLDSA44_REDUCE_H
#define CRYPTO_PQC_MLDSA44_REDUCE_H

#include <stdint.h>
#include "CRYPTO_PQC_MLDSA44_params.h"

#define MONT -4186625 // 2^32 mod q
#define QINV 58728449 // q^-1 mod 2^32

static inline __attribute__((always_inline)) int32_t dilithium_montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)((uint32_t)a * QINV);
    int64_t u = ((int64_t)t << 23) - ((int64_t)t << 13) + t;
    return (int32_t)((a - u) >> 32);
}

static inline __attribute__((always_inline)) int32_t dilithium_reduce32(int32_t a) {
    int32_t t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q;
    return t;
}

static inline __attribute__((always_inline)) int32_t dilithium_csubq(int32_t a) {
    a -= DILITHIUM_Q;
    a += ((int32_t)a >> 31) & DILITHIUM_Q;
    return a;
}

#endif /* CRYPTO_PQC_MLDSA44_REDUCE_H */
