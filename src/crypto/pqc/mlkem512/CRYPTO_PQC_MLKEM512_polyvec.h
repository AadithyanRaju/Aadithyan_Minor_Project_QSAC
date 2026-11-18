/**
 * @file CRYPTO_PQC_MLKEM512_polyvec.h
 * @brief Polynomial vector operations declarations for Kyber (k=2).
 */

#ifndef CRYPTO_PQC_MLKEM512_POLYVEC_H
#define CRYPTO_PQC_MLKEM512_POLYVEC_H

#include <stdint.h>
#include <stddef.h>
#include "CRYPTO_PQC_MLKEM512_params.h"
#include "CRYPTO_PQC_MLKEM512_poly.h"

typedef struct {
    poly vec[KYBER_K];
} polyvec;

void kyber_polyvec_compress_du(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_DU], const polyvec *a);
void kyber_polyvec_decompress_du(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_DU]);

void kyber_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
void kyber_polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

void kyber_polyvec_ntt(polyvec *r);
void kyber_polyvec_invntt_tomont(polyvec *r);
void kyber_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void kyber_polyvec_reduce(polyvec *r);
void kyber_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif /* CRYPTO_PQC_MLKEM512_POLYVEC_H */
