/**
 * @file CRYPTO_PQC_MLDSA44_rounding.c
 * @brief Rounding and hint generation implementation for Dilithium.
 */

#include "CRYPTO_PQC_MLDSA44_rounding.h"

int32_t power2round(int32_t *a0, int32_t a) {
    int32_t a1 = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    *a0 = a - (a1 << DILITHIUM_D);
    return a1;
}

int32_t decompose(int32_t *a0, int32_t a) {
    int32_t a1 = (a + 127) >> 7;
    // For gamma2 = (q-1)/88 = 95232:
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;

    *a0 = a - a1 * 2 * DILITHIUM_GAMMA2;
    *a0 -= (((DILITHIUM_Q / 2 - *a0) >> 31) & DILITHIUM_Q);
    return a1;
}

unsigned int make_hint(int32_t a0, int32_t a1) {
    int32_t t0, t1;
    int32_t val = (int32_t)(((int64_t)a0 + (int64_t)a1 * 2 * DILITHIUM_GAMMA2) % DILITHIUM_Q);
    if (val < 0) {
        val += DILITHIUM_Q;
    }
    t1 = decompose(&t0, val);
    return (t1 != a1) ? 1 : 0;
}

int32_t use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;
    a1 = decompose(&a0, a);
    if (hint == 0) return a1;

    if (a0 > 0) {
        if (a1 == (DILITHIUM_Q - 1) / (2 * DILITHIUM_GAMMA2) - 1) {
            return 0;
        } else {
            return a1 + 1;
        }
    } else {
        if (a1 == 0) {
            return (DILITHIUM_Q - 1) / (2 * DILITHIUM_GAMMA2) - 1;
        } else {
            return a1 - 1;
        }
    }
}
