/**
 * @file CRYPTO_PQC_MLKEM512_indcpa.h
 * @brief IND-CPA key generation, encryption, and decryption declarations for Kyber-512.
 */

#ifndef CRYPTO_PQC_MLKEM512_INDCPA_H
#define CRYPTO_PQC_MLKEM512_INDCPA_H

#include <stdint.h>
#include "CRYPTO_PQC_MLKEM512_params.h"

void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif /* CRYPTO_PQC_MLKEM512_INDCPA_H */
