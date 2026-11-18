/**
 * @file CRYPTO_PQC_MLKEM512_verify.c
 * @brief Constant-time verification and conditional move implementation.
 */

#include "CRYPTO_PQC_MLKEM512_verify.h"

int pqc_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t r = 0;
    for (size_t i = 0; i < len; ++i) {
        r |= a[i] ^ b[i];
    }
    return (int)((-((uint64_t)r)) >> 63);
}

void pqc_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    uint8_t mask = (uint8_t)(-(int8_t)b);
    for (size_t i = 0; i < len; ++i) {
        r[i] ^= mask & (x[i] ^ r[i]);
    }
}
