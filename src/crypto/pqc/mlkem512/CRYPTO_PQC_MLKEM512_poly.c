/**
 * @file CRYPTO_PQC_MLKEM512_poly.c
 * @brief Polynomial arithmetic implementation for Kyber.
 */

#include "CRYPTO_PQC_MLKEM512_poly.h"
#include "CRYPTO_PQC_MLKEM512_ntt.h"
#include "CRYPTO_PQC_MLKEM512_reduce.h"
#include "CRYPTO_PQC_MLKEM512_cbd.h"
#include "../../fips202.h"
#include <string.h>

void kyber_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_DV], const poly *a) {
    uint8_t t[8];
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            uint32_t d0 = (uint32_t)kyber_freeze(a->coeffs[8 * i + j]);
            t[j] = (uint8_t)((((d0 << 4) + KYBER_Q / 2) / KYBER_Q) & 15);
        }
        r[4 * i + 0] = t[0] | (t[1] << 4);
        r[4 * i + 1] = t[2] | (t[3] << 4);
        r[4 * i + 2] = t[4] | (t[5] << 4);
        r[4 * i + 3] = t[6] | (t[7] << 4);
    }
}

void kyber_poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_DV]) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
        r->coeffs[8 * i + 0] = (int16_t)(((uint32_t)(a[4 * i + 0] & 15) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 1] = (int16_t)(((uint32_t)(a[4 * i + 0] >> 4) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 2] = (int16_t)(((uint32_t)(a[4 * i + 1] & 15) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 3] = (int16_t)(((uint32_t)(a[4 * i + 1] >> 4) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 4] = (int16_t)(((uint32_t)(a[4 * i + 2] & 15) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 5] = (int16_t)(((uint32_t)(a[4 * i + 2] >> 4) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 6] = (int16_t)(((uint32_t)(a[4 * i + 3] & 15) * KYBER_Q + 8) >> 4);
        r->coeffs[8 * i + 7] = (int16_t)(((uint32_t)(a[4 * i + 3] >> 4) * KYBER_Q + 8) >> 4);
    }
}

void kyber_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a) {
    for (size_t i = 0; i < KYBER_N / 2; ++i) {
        uint16_t t0 = (uint16_t)kyber_freeze(a->coeffs[2 * i + 0]);
        uint16_t t1 = (uint16_t)kyber_freeze(a->coeffs[2 * i + 1]);
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

void kyber_poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    for (size_t i = 0; i < KYBER_N / 2; ++i) {
        r->coeffs[2 * i + 0] = (int16_t)(((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF);
        r->coeffs[2 * i + 1] = (int16_t)(((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF);
    }
}

void kyber_poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            int16_t mask = (int16_t)(-((int16_t)(msg[i] >> j) & 1));
            r->coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
        }
    }
}

void kyber_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
        msg[i] = 0;
        for (size_t j = 0; j < 8; ++j) {
            uint32_t t = (uint32_t)kyber_freeze(a->coeffs[8 * i + j]);
            t = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
            msg[i] |= (uint8_t)(t << j);
        }
    }
}

void kyber_poly_getnoise_eta1(poly *r, const uint8_t seed[32], uint8_t nonce) {
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    uint8_t extseed[33];
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    shake256(buf, sizeof(buf), extseed, sizeof(extseed));
    cbd3(r->coeffs, buf);
}

void kyber_poly_getnoise_eta2(poly *r, const uint8_t seed[32], uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    uint8_t extseed[33];
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    shake256(buf, sizeof(buf), extseed, sizeof(extseed));
    cbd2(r->coeffs, buf);
}

void kyber_poly_ntt(poly *r) {
    kyber_ntt(r->coeffs);
    kyber_poly_reduce(r);
}

void kyber_poly_invntt_tomont(poly *r) {
    kyber_invntt(r->coeffs);
}

void kyber_poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
    for (size_t i = 0; i < KYBER_N / 4; ++i) {
        kyber_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], kyber_zetas[64 + i]);
        kyber_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -kyber_zetas[64 + i]);
    }
}

void kyber_poly_tomont(poly *r) {
    const int16_t f = (int16_t)(((uint64_t)1 << 32) % KYBER_Q);
    for (size_t i = 0; i < KYBER_N; ++i) {
        r->coeffs[i] = kyber_montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}

void kyber_poly_reduce(poly *r) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        r->coeffs[i] = kyber_barrett_reduce(r->coeffs[i]);
    }
}

void kyber_poly_add(poly *r, const poly *a, const poly *b) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] + b->coeffs[i]);
    }
}

void kyber_poly_sub(poly *r, const poly *a, const poly *b) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] - b->coeffs[i]);
    }
}
