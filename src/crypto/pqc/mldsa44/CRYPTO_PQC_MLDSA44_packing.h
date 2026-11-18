/**
 * @file CRYPTO_PQC_MLDSA44_packing.h
 * @brief Key and signature packing declarations for Dilithium-2.
 */

#ifndef CRYPTO_PQC_MLDSA44_PACKING_H
#define CRYPTO_PQC_MLDSA44_PACKING_H

#include <stdint.h>
#include "CRYPTO_PQC_MLDSA44_params.h"
#include "CRYPTO_PQC_MLDSA44_polyvec.h"

void pack_pk(uint8_t pk[DILITHIUM_PUBLICKEYBYTES],
             const uint8_t rho[DILITHIUM_SEEDBYTES],
             const polyveck *t1);

void unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[DILITHIUM_PUBLICKEYBYTES]);

void pack_sk(uint8_t sk[DILITHIUM_SECRETKEYBYTES],
             const uint8_t rho[DILITHIUM_SEEDBYTES],
             const uint8_t tr[DILITHIUM_TRBYTES],
             const uint8_t key[DILITHIUM_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

void unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
               uint8_t tr[DILITHIUM_TRBYTES],
               uint8_t key[DILITHIUM_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[DILITHIUM_SECRETKEYBYTES]);

void pack_sig(uint8_t sig[DILITHIUM_SIGNATUREBYTES],
              const uint8_t c[DILITHIUM_SEEDBYTES],
              const polyvecl *z,
              const polyveck *h);

int unpack_sig(uint8_t c[DILITHIUM_SEEDBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[DILITHIUM_SIGNATUREBYTES]);

#endif /* CRYPTO_PQC_MLDSA44_PACKING_H */
