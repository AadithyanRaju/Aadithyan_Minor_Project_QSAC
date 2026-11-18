/**
 * @file CRYPTO_PQC_MLDSA44_polyvec.h
 * @brief Polynomial vector operations declarations for Dilithium-2.
 */

#ifndef CRYPTO_PQC_MLDSA44_POLYVEC_H
#define CRYPTO_PQC_MLDSA44_POLYVEC_H

#include <stdint.h>
#include <stddef.h>
#include "CRYPTO_PQC_MLDSA44_params.h"
#include "CRYPTO_PQC_MLDSA44_poly.h"

/* Vectors of length L = 4 */
typedef struct {
    poly vec[DILITHIUM_L];
} polyvecl;

void dilithium_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void dilithium_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void dilithium_polyvecl_reduce(polyvecl *v);
void dilithium_polyvecl_freeze(polyvecl *v);
void dilithium_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void dilithium_polyvecl_ntt(polyvecl *v);
void dilithium_polyvecl_invntt_tomont(polyvecl *v);
void dilithium_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
void dilithium_polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v);
int dilithium_polyvecl_chknorm(const polyvecl *v, int32_t B);

/* Vectors of length K = 4 */
typedef struct {
    poly vec[DILITHIUM_K];
} polyveck;

void dilithium_polyveck_uniform_eta(polyveck *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void dilithium_polyveck_reduce(polyveck *v);
void dilithium_polyveck_caddq(polyveck *v);
void dilithium_polyveck_freeze(polyveck *v);
void dilithium_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void dilithium_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void dilithium_polyveck_shiftl(polyveck *v);
void dilithium_polyveck_ntt(polyveck *v);
void dilithium_polyveck_invntt_tomont(polyveck *v);
void dilithium_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);
int dilithium_polyveck_chknorm(const polyveck *v, int32_t B);

void dilithium_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void dilithium_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int dilithium_polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1);
void dilithium_polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h);

void dilithium_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DILITHIUM_K], const polyvecl *v);

#endif /* CRYPTO_PQC_MLDSA44_POLYVEC_H */
