/**
 * @file CRYPTO_PQC_MLKEM512_cbd.h
 * @brief Centered Binomial Distribution sampling declarations for Kyber.
 */

#ifndef CRYPTO_PQC_MLKEM512_CBD_H
#define CRYPTO_PQC_MLKEM512_CBD_H

#include <stdint.h>
#include <stddef.h>
#include "CRYPTO_PQC_MLKEM512_params.h"

void cbd2(int16_t r[256], const uint8_t buf[2 * KYBER_N / 4]);
void cbd3(int16_t r[256], const uint8_t buf[3 * KYBER_N / 4]);

#endif /* CRYPTO_PQC_MLKEM512_CBD_H */
