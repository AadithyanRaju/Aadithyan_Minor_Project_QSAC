/**
 * @file CRYPTO_PQC_MLKEM512_poly.h
 * @brief Polynomial arithmetic declarations for Kyber.
 */

#ifndef CRYPTO_PQC_MLKEM512_POLY_H
#define CRYPTO_PQC_MLKEM512_POLY_H

#include <stdint.h>
#include <stddef.h>
#include "CRYPTO_PQC_MLKEM512_params.h"

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

void kyber_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_DV], const poly *a);
void kyber_poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_DV]);

void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a);
void kyber_poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]);

void kyber_poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
void kyber_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a);

void kyber_poly_getnoise_eta1(poly *r, const uint8_t seed[32], uint8_t nonce);
void kyber_poly_getnoise_eta2(poly *r, const uint8_t seed[32], uint8_t nonce);

void kyber_poly_ntt(poly *r);
void kyber_poly_invntt_tomont(poly *r);
void kyber_poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void kyber_poly_tomont(poly *r);

void kyber_poly_reduce(poly *r);
void kyber_poly_add(poly *r, const poly *a, const poly *b);
void kyber_poly_sub(poly *r, const poly *a, const poly *b);

#endif /* CRYPTO_PQC_MLKEM512_POLY_H */
