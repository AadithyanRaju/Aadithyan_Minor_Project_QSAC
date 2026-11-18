/**
 * @file CRYPTO_PQC_MLKEM512_ntt.h
 * @brief Number Theoretic Transform declarations for Kyber.
 */

#ifndef CRYPTO_PQC_MLKEM512_NTT_H
#define CRYPTO_PQC_MLKEM512_NTT_H

#include <stdint.h>
#include "CRYPTO_PQC_MLKEM512_params.h"

extern const int16_t kyber_zetas[128];
extern const int16_t kyber_zetas_inv[128];

void kyber_ntt(int16_t poly[256]);
void kyber_invntt(int16_t poly[256]);
void kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif /* CRYPTO_PQC_MLKEM512_NTT_H */
