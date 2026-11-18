/**
 * @file CRYPTO_PQC_MLDSA44_packing.c
 * @brief Key and signature packing implementation for Dilithium-2.
 */

#include "CRYPTO_PQC_MLDSA44_packing.h"
#include "CRYPTO_PQC_MLDSA44_poly.h"
#include <string.h>

void pack_pk(uint8_t pk[DILITHIUM_PUBLICKEYBYTES],
             const uint8_t rho[DILITHIUM_SEEDBYTES],
             const polyveck *t1) {
    memcpy(pk, rho, DILITHIUM_SEEDBYTES);
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyt1_pack(pk + DILITHIUM_SEEDBYTES + i * DILITHIUM_POLYT1_PACKEDBYTES, &t1->vec[i]);
    }
}

void unpack_pk(uint8_t rho[DILITHIUM_SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[DILITHIUM_PUBLICKEYBYTES]) {
    memcpy(rho, pk, DILITHIUM_SEEDBYTES);
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyt1_unpack(&t1->vec[i], pk + DILITHIUM_SEEDBYTES + i * DILITHIUM_POLYT1_PACKEDBYTES);
    }
}

void pack_sk(uint8_t sk[DILITHIUM_SECRETKEYBYTES],
             const uint8_t rho[DILITHIUM_SEEDBYTES],
             const uint8_t tr[DILITHIUM_TRBYTES],
             const uint8_t key[DILITHIUM_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2) {
    size_t offset = 0;
    memcpy(sk + offset, rho, DILITHIUM_SEEDBYTES);
    offset += DILITHIUM_SEEDBYTES;

    memcpy(sk + offset, key, DILITHIUM_SEEDBYTES);
    offset += DILITHIUM_SEEDBYTES;

    memcpy(sk + offset, tr, DILITHIUM_TRBYTES);
    offset += DILITHIUM_TRBYTES;

    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_polyeta_pack(sk + offset, &s1->vec[i]);
        offset += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyeta_pack(sk + offset, &s2->vec[i]);
        offset += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyt0_pack(sk + offset, &t0->vec[i]);
        offset += DILITHIUM_POLYT0_PACKEDBYTES;
    }
}

void unpack_sk(uint8_t rho[DILITHIUM_SEEDBYTES],
               uint8_t tr[DILITHIUM_TRBYTES],
               uint8_t key[DILITHIUM_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[DILITHIUM_SECRETKEYBYTES]) {
    size_t offset = 0;
    memcpy(rho, sk + offset, DILITHIUM_SEEDBYTES);
    offset += DILITHIUM_SEEDBYTES;

    memcpy(key, sk + offset, DILITHIUM_SEEDBYTES);
    offset += DILITHIUM_SEEDBYTES;

    memcpy(tr, sk + offset, DILITHIUM_TRBYTES);
    offset += DILITHIUM_TRBYTES;

    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_polyeta_unpack(&s1->vec[i], sk + offset);
        offset += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyeta_unpack(&s2->vec[i], sk + offset);
        offset += DILITHIUM_POLYETA_PACKEDBYTES;
    }

    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyt0_unpack(&t0->vec[i], sk + offset);
        offset += DILITHIUM_POLYT0_PACKEDBYTES;
    }
}

void pack_sig(uint8_t sig[DILITHIUM_SIGNATUREBYTES],
              const uint8_t c[DILITHIUM_SEEDBYTES],
              const polyvecl *z,
              const polyveck *h) {
    size_t offset = 0;
    memcpy(sig + offset, c, DILITHIUM_SEEDBYTES);
    offset += DILITHIUM_SEEDBYTES;

    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_polyz_pack(sig + offset, &z->vec[i]);
        offset += DILITHIUM_POLYZ_PACKEDBYTES;
    }

    memset(sig + offset, 0, DILITHIUM_POLYVECH_PACKEDBYTES);
    size_t k = 0;
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        for (size_t j = 0; j < DILITHIUM_N; ++j) {
            if (h->vec[i].coeffs[j] != 0) {
                sig[offset + k++] = (uint8_t)j;
            }
        }
        sig[offset + DILITHIUM_OMEGA + i] = (uint8_t)k;
    }
}

int unpack_sig(uint8_t c[DILITHIUM_SEEDBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[DILITHIUM_SIGNATUREBYTES]) {
    size_t offset = 0;
    memcpy(c, sig + offset, DILITHIUM_SEEDBYTES);
    offset += DILITHIUM_SEEDBYTES;

    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_polyz_unpack(&z->vec[i], sig + offset);
        offset += DILITHIUM_POLYZ_PACKEDBYTES;
    }

    const uint8_t *sig_h = sig + offset;
    size_t k = 0;
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        for (size_t j = 0; j < DILITHIUM_N; ++j) {
            h->vec[i].coeffs[j] = 0;
        }

        if (sig_h[DILITHIUM_OMEGA + i] < k || sig_h[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA) {
            return 1;
        }

        for (size_t j = k; j < sig_h[DILITHIUM_OMEGA + i]; ++j) {
            if (j > k && sig_h[j] <= sig_h[j - 1]) {
                return 1;
            }
            h->vec[i].coeffs[sig_h[j]] = 1;
        }
        k = sig_h[DILITHIUM_OMEGA + i];
    }

    for (size_t j = k; j < DILITHIUM_OMEGA; ++j) {
        if (sig_h[j] != 0) {
            return 1;
        }
    }
    return 0;
}
