/**
 * @file CRYPTO_PQC_MLDSA44_poly.h
 * @brief Polynomial arithmetic declarations for Dilithium-2.
 */

#ifndef CRYPTO_PQC_MLDSA44_POLY_H
#define CRYPTO_PQC_MLDSA44_POLY_H

#include <stdint.h>
#include <stddef.h>
#include "CRYPTO_PQC_MLDSA44_params.h"

typedef struct {
    int32_t coeffs[DILITHIUM_N];
} poly;

void dilithium_poly_reduce(poly *a);
void dilithium_poly_caddq(poly *a);
void dilithium_poly_freeze(poly *a);

void dilithium_poly_add(poly *c, const poly *a, const poly *b);
void dilithium_poly_sub(poly *c, const poly *a, const poly *b);
void dilithium_poly_shiftl(poly *a);

void dilithium_poly_ntt(poly *a);
void dilithium_poly_invntt_tomont(poly *a);
void dilithium_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

void dilithium_poly_power2round(poly *a1, poly *a0, const poly *a);
void dilithium_poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int dilithium_poly_make_hint(poly *h, const poly *a0, const poly *a1);
void dilithium_poly_use_hint(poly *b, const poly *a, const poly *h);

int dilithium_poly_chknorm(const poly *a, int32_t B);
void dilithium_poly_uniform(poly *a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce);
void dilithium_poly_uniform_eta(poly *a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void dilithium_poly_uniform_gamma1(poly *a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void dilithium_poly_challenge(poly *c, const uint8_t seed[DILITHIUM_SEEDBYTES]);

void dilithium_polyeta_pack(uint8_t *r, const poly *a);
void dilithium_polyeta_unpack(poly *r, const uint8_t *a);

void dilithium_polyt1_pack(uint8_t *r, const poly *a);
void dilithium_polyt1_unpack(poly *r, const uint8_t *a);

void dilithium_polyt0_pack(uint8_t *r, const poly *a);
void dilithium_polyt0_unpack(poly *r, const uint8_t *a);

void dilithium_polyz_pack(uint8_t *r, const poly *a);
void dilithium_polyz_unpack(poly *r, const uint8_t *a);

void dilithium_polyw1_pack(uint8_t *r, const poly *a);

#endif /* CRYPTO_PQC_MLDSA44_POLY_H */
