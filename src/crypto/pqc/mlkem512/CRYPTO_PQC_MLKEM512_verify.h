/**
 * @file CRYPTO_PQC_MLKEM512_verify.h
 * @brief Constant-time verification and conditional move declarations.
 */

#ifndef CRYPTO_PQC_MLKEM512_VERIFY_H
#define CRYPTO_PQC_MLKEM512_VERIFY_H

#include <stddef.h>
#include <stdint.h>

int pqc_verify(const uint8_t *a, const uint8_t *b, size_t len);
void pqc_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#endif /* CRYPTO_PQC_MLKEM512_VERIFY_H */
