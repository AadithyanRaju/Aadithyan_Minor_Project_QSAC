/**
 * @file CRYPTO_PQC_MLKEM512_kem.h
 * @brief CCA-secure Key Encapsulation Mechanism declarations for ML-KEM-512.
 */

#ifndef CRYPTO_PQC_MLKEM512_KEM_H
#define CRYPTO_PQC_MLKEM512_KEM_H

#include <stdint.h>
#include "CRYPTO_PQC_MLKEM512_params.h"

int pqcrystals_kyber512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);

int pqcrystals_kyber512_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* CRYPTO_PQC_MLKEM512_KEM_H */
