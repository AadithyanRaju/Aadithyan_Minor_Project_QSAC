/**
 * @file CRYPTO_PQC_MLKEM512_polyvec.c
 * @brief Polynomial vector operations implementation for Kyber (k=2).
 */

#include "CRYPTO_PQC_MLKEM512_polyvec.h"
#include "CRYPTO_PQC_MLKEM512_reduce.h"

void kyber_polyvec_compress_du(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_DU], const polyvec *a) {
    uint16_t t[4];
    for (size_t i = 0; i < KYBER_K; ++i) {
        for (size_t j = 0; j < KYBER_N / 4; ++j) {
            for (size_t k = 0; k < 4; ++k) {
                uint32_t d0 = (uint32_t)kyber_freeze(a->vec[i].coeffs[4 * j + k]);
                t[k] = (uint16_t)((((d0 << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FF);
            }
            r[320 * i + 5 * j + 0] = (uint8_t)(t[0] >> 0);
            r[320 * i + 5 * j + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[320 * i + 5 * j + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[320 * i + 5 * j + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[320 * i + 5 * j + 4] = (uint8_t)(t[3] >> 2);
        }
    }
}

void kyber_polyvec_decompress_du(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_DU]) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        for (size_t j = 0; j < KYBER_N / 4; ++j) {
            uint16_t t[4];
            t[0] = (uint16_t)((a[320 * i + 5 * j + 0] >> 0) | ((uint16_t)a[320 * i + 5 * j + 1] << 8)) & 0x3FF;
            t[1] = (uint16_t)((a[320 * i + 5 * j + 1] >> 2) | ((uint16_t)a[320 * i + 5 * j + 2] << 6)) & 0x3FF;
            t[2] = (uint16_t)((a[320 * i + 5 * j + 2] >> 4) | ((uint16_t)a[320 * i + 5 * j + 3] << 4)) & 0x3FF;
            t[3] = (uint16_t)((a[320 * i + 5 * j + 3] >> 6) | ((uint16_t)a[320 * i + 5 * j + 4] << 2)) & 0x3FF;

            r->vec[i].coeffs[4 * j + 0] = (int16_t)(((uint32_t)t[0] * KYBER_Q + 512) >> 10);
            r->vec[i].coeffs[4 * j + 1] = (int16_t)(((uint32_t)t[1] * KYBER_Q + 512) >> 10);
            r->vec[i].coeffs[4 * j + 2] = (int16_t)(((uint32_t)t[2] * KYBER_Q + 512) >> 10);
            r->vec[i].coeffs[4 * j + 3] = (int16_t)(((uint32_t)t[3] * KYBER_Q + 512) >> 10);
        }
    }
}

void kyber_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}

void kyber_polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}

void kyber_polyvec_ntt(polyvec *r) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_ntt(&r->vec[i]);
    }
}

void kyber_polyvec_invntt_tomont(polyvec *r) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_invntt_tomont(&r->vec[i]);
    }
}

void kyber_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b) {
    poly t;
    kyber_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (size_t i = 1; i < KYBER_K; ++i) {
        kyber_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        kyber_poly_add(r, r, &t);
    }
    kyber_poly_reduce(r);
}

void kyber_polyvec_reduce(polyvec *r) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_reduce(&r->vec[i]);
    }
}

void kyber_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
