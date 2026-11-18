/**
 * @file CRYPTO_PQC_MLDSA44_poly.c
 * @brief Polynomial operations and packing implementation for Dilithium-2.
 */

#include "CRYPTO_PQC_MLDSA44_poly.h"
#include "CRYPTO_PQC_MLDSA44_ntt.h"
#include "CRYPTO_PQC_MLDSA44_reduce.h"
#include "CRYPTO_PQC_MLDSA44_rounding.h"
#include "../../fips202.h"
#include <string.h>

void dilithium_poly_reduce(poly *a) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a->coeffs[i] = dilithium_reduce32(a->coeffs[i]);
    }
}

void dilithium_poly_caddq(poly *a) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a->coeffs[i] += ((int32_t)a->coeffs[i] >> 31) & DILITHIUM_Q;
    }
}

void dilithium_poly_freeze(poly *a) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a->coeffs[i] = dilithium_csubq(a->coeffs[i]);
    }
}

void dilithium_poly_add(poly *c, const poly *a, const poly *b) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void dilithium_poly_sub(poly *c, const poly *a, const poly *b) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

void dilithium_poly_shiftl(poly *a) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a->coeffs[i] <<= DILITHIUM_D;
    }
}

void dilithium_poly_ntt(poly *a) {
    dilithium_ntt(a->coeffs);
}

void dilithium_poly_invntt_tomont(poly *a) {
    dilithium_invntt_tomont(a->coeffs);
}

void __attribute__((optimize("O3"))) dilithium_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        c->coeffs[i] = dilithium_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

void dilithium_poly_power2round(poly *a1, poly *a0, const poly *a) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
    }
}

void dilithium_poly_decompose(poly *a1, poly *a0, const poly *a) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
    }
}

unsigned int dilithium_poly_make_hint(poly *h, const poly *a0, const poly *a1) {
    unsigned int s = 0;
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        h->coeffs[i] = (int32_t)make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += (unsigned int)h->coeffs[i];
    }
    return s;
}

void dilithium_poly_use_hint(poly *b, const poly *a, const poly *h) {
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        b->coeffs[i] = use_hint(a->coeffs[i], (unsigned int)h->coeffs[i]);
    }
}

int dilithium_poly_chknorm(const poly *a, int32_t B) {
    if (B > (DILITHIUM_Q - 1) / 8) return 1;
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        int32_t t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);
        if (t >= B) return 1;
    }
    return 0;
}

static size_t rej_uniform(int32_t *a, size_t len, const uint8_t *buf, size_t buflen) {
    size_t ctr = 0, pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint32_t t = (uint32_t)buf[pos + 0];
        t |= (uint32_t)buf[pos + 1] << 8;
        t |= (uint32_t)buf[pos + 2] << 16;
        t &= 0x7FFFFF;
        pos += 3;
        if (t < DILITHIUM_Q) {
            a[ctr++] = (int32_t)t;
        }
    }
    return ctr;
}

void dilithium_poly_uniform(poly *a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce) {
    uint8_t buf[SHAKE128_RATE];
    uint8_t extseed[DILITHIUM_SEEDBYTES + 2];
    memcpy(extseed, seed, DILITHIUM_SEEDBYTES);
    extseed[DILITHIUM_SEEDBYTES + 0] = (uint8_t)(nonce >> 0);
    extseed[DILITHIUM_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    shake128incctx state;
    shake128_inc_init(&state);
    shake128_inc_absorb(&state, extseed, sizeof(extseed));
    shake128_inc_finalize(&state);

    size_t ctr = 0;
    while (ctr < DILITHIUM_N) {
        shake128_inc_squeeze(buf, sizeof(buf), &state);
        ctr += rej_uniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, sizeof(buf));
    }
}

static size_t rej_eta(int32_t *a, size_t len, const uint8_t *buf, size_t buflen) {
    size_t ctr = 0, pos = 0;
    while (ctr < len && pos < buflen) {
        uint8_t t0 = buf[pos] & 0x0F;
        uint8_t t1 = buf[pos++] >> 4;
        if (t0 < 15) {
            int32_t t = (int32_t)(t0 - ((int32_t)(205 * t0) >> 10) * 5);
            a[ctr++] = 2 - t;
        }
        if (ctr < len && t1 < 15) {
            int32_t t = (int32_t)(t1 - ((int32_t)(205 * t1) >> 10) * 5);
            a[ctr++] = 2 - t;
        }
    }
    return ctr;
}

void dilithium_poly_uniform_eta(poly *a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce) {
    uint8_t buf[SHAKE256_RATE];
    uint8_t extseed[DILITHIUM_CRHBYTES + 2];
    memcpy(extseed, seed, DILITHIUM_CRHBYTES);
    extseed[DILITHIUM_CRHBYTES + 0] = (uint8_t)(nonce >> 0);
    extseed[DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, extseed, sizeof(extseed));
    shake256_inc_finalize(&state);

    size_t ctr = 0;
    while (ctr < DILITHIUM_N) {
        shake256_inc_squeeze(buf, sizeof(buf), &state);
        ctr += rej_eta(a->coeffs + ctr, DILITHIUM_N - ctr, buf, sizeof(buf));
    }
}

static void polyz_unpack_chunk(int32_t *r, const uint8_t *a, size_t n_groups) {
    for (size_t i = 0; i < n_groups; ++i) {
        r[4 * i + 0] = (int32_t)((a[9 * i + 0] >> 0) | ((uint32_t)a[9 * i + 1] << 8) | ((uint32_t)a[9 * i + 2] << 16)) & 0x3FFFF;
        r[4 * i + 1] = (int32_t)((a[9 * i + 2] >> 2) | ((uint32_t)a[9 * i + 3] << 6) | ((uint32_t)a[9 * i + 4] << 14)) & 0x3FFFF;
        r[4 * i + 2] = (int32_t)((a[9 * i + 4] >> 4) | ((uint32_t)a[9 * i + 5] << 4) | ((uint32_t)a[9 * i + 6] << 12)) & 0x3FFFF;
        r[4 * i + 3] = (int32_t)((a[9 * i + 6] >> 6) | ((uint32_t)a[9 * i + 7] << 2) | ((uint32_t)a[9 * i + 8] << 10)) & 0x3FFFF;

        for (size_t j = 0; j < 4; ++j) {
            r[4 * i + j] = DILITHIUM_GAMMA1 - r[4 * i + j];
        }
    }
}

void dilithium_poly_uniform_gamma1(poly *a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce) {
    uint8_t buf[72];
    uint8_t extseed[DILITHIUM_CRHBYTES + 2];
    memcpy(extseed, seed, DILITHIUM_CRHBYTES);
    extseed[DILITHIUM_CRHBYTES + 0] = (uint8_t)(nonce >> 0);
    extseed[DILITHIUM_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, extseed, sizeof(extseed));
    shake256_inc_finalize(&state);

    for (size_t chunk = 0; chunk < 8; ++chunk) {
        shake256_inc_squeeze(buf, sizeof(buf), &state);
        polyz_unpack_chunk(&a->coeffs[chunk * 32], buf, 8);
    }
}

void dilithium_poly_challenge(poly *c, const uint8_t seed[DILITHIUM_SEEDBYTES]) {
    uint8_t buf[SHAKE256_RATE];
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, seed, DILITHIUM_SEEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(buf, sizeof(buf), &state);

    uint64_t signs = 0;
    for (size_t i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }
    size_t pos = 8;

    memset(c->coeffs, 0, sizeof(c->coeffs));
    for (size_t i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; ++i) {
        size_t b;
        do {
            if (pos >= SHAKE256_RATE) {
                shake256_inc_squeeze(buf, sizeof(buf), &state);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

void dilithium_polyeta_pack(uint8_t *r, const poly *a) {
    uint8_t t[8];
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            t[j] = (uint8_t)(2 - a->coeffs[8 * i + j]);
        }
        r[3 * i + 0] = (uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
        r[3 * i + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
        r[3 * i + 2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
    }
}

void dilithium_polyeta_unpack(poly *r, const uint8_t *a) {
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i) {
        r->coeffs[8 * i + 0] = 2 - (int32_t)((a[3 * i + 0] >> 0) & 7);
        r->coeffs[8 * i + 1] = 2 - (int32_t)((a[3 * i + 0] >> 3) & 7);
        r->coeffs[8 * i + 2] = 2 - (int32_t)(((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7);
        r->coeffs[8 * i + 3] = 2 - (int32_t)((a[3 * i + 1] >> 1) & 7);
        r->coeffs[8 * i + 4] = 2 - (int32_t)((a[3 * i + 1] >> 4) & 7);
        r->coeffs[8 * i + 5] = 2 - (int32_t)(((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7);
        r->coeffs[8 * i + 6] = 2 - (int32_t)((a[3 * i + 2] >> 2) & 7);
        r->coeffs[8 * i + 7] = 2 - (int32_t)((a[3 * i + 2] >> 5) & 7);
    }
}

void dilithium_polyt1_pack(uint8_t *r, const poly *a) {
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i) {
        r[5 * i + 0] = (uint8_t)(a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (uint8_t)((a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2));
        r[5 * i + 2] = (uint8_t)((a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4));
        r[5 * i + 3] = (uint8_t)((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6));
        r[5 * i + 4] = (uint8_t)(a->coeffs[4 * i + 3] >> 2);
    }
}

void dilithium_polyt1_unpack(poly *r, const uint8_t *a) {
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i) {
        r->coeffs[4 * i + 0] = (int32_t)(((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF);
        r->coeffs[4 * i + 1] = (int32_t)(((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF);
        r->coeffs[4 * i + 2] = (int32_t)(((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF);
        r->coeffs[4 * i + 3] = (int32_t)(((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF);
    }
}

void dilithium_polyt0_pack(uint8_t *r, const poly *a) {
    uint32_t t[8];
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            t[j] = (uint32_t)((1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + j]);
        }
        r[13 * i +  0] = (uint8_t)(t[0] >> 0);
        r[13 * i +  1] = (uint8_t)(t[0] >> 8 | t[1] << 5);
        r[13 * i +  2] = (uint8_t)(t[1] >> 3);
        r[13 * i +  3] = (uint8_t)(t[1] >> 11 | t[2] << 2);
        r[13 * i +  4] = (uint8_t)(t[2] >> 6 | t[3] << 7);
        r[13 * i +  5] = (uint8_t)(t[3] >> 1);
        r[13 * i +  6] = (uint8_t)(t[3] >> 9 | t[4] << 4);
        r[13 * i +  7] = (uint8_t)(t[4] >> 4);
        r[13 * i +  8] = (uint8_t)(t[4] >> 12 | t[5] << 1);
        r[13 * i +  9] = (uint8_t)(t[5] >> 7 | t[6] << 6);
        r[13 * i + 10] = (uint8_t)(t[6] >> 2);
        r[13 * i + 11] = (uint8_t)(t[6] >> 10 | t[7] << 3);
        r[13 * i + 12] = (uint8_t)(t[7] >> 5);
    }
}

void dilithium_polyt0_unpack(poly *r, const uint8_t *a) {
    for (size_t i = 0; i < DILITHIUM_N / 8; ++i) {
        r->coeffs[8 * i + 0] = (int32_t)((a[13 * i +  0] >> 0) | ((uint32_t)a[13 * i +  1] << 8)) & 0x1FFF;
        r->coeffs[8 * i + 1] = (int32_t)((a[13 * i +  1] >> 5) | ((uint32_t)a[13 * i +  2] << 3) | ((uint32_t)a[13 * i + 3] << 11)) & 0x1FFF;
        r->coeffs[8 * i + 2] = (int32_t)((a[13 * i +  3] >> 2) | ((uint32_t)a[13 * i +  4] << 6)) & 0x1FFF;
        r->coeffs[8 * i + 3] = (int32_t)((a[13 * i +  4] >> 7) | ((uint32_t)a[13 * i +  5] << 1) | ((uint32_t)a[13 * i + 6] << 9)) & 0x1FFF;
        r->coeffs[8 * i + 4] = (int32_t)((a[13 * i +  6] >> 4) | ((uint32_t)a[13 * i +  7] << 4) | ((uint32_t)a[13 * i + 8] << 12)) & 0x1FFF;
        r->coeffs[8 * i + 5] = (int32_t)((a[13 * i +  8] >> 1) | ((uint32_t)a[13 * i +  9] << 7)) & 0x1FFF;
        r->coeffs[8 * i + 6] = (int32_t)((a[13 * i +  9] >> 6) | ((uint32_t)a[13 * i + 10] << 2) | ((uint32_t)a[13 * i + 11] << 10)) & 0x1FFF;
        r->coeffs[8 * i + 7] = (int32_t)((a[13 * i + 11] >> 3) | ((uint32_t)a[13 * i + 12] << 5)) & 0x1FFF;

        for (size_t j = 0; j < 8; ++j) {
            r->coeffs[8 * i + j] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + j];
        }
    }
}

void dilithium_polyz_pack(uint8_t *r, const poly *a) {
    uint32_t t[4];
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            t[j] = (uint32_t)(DILITHIUM_GAMMA1 - a->coeffs[4 * i + j]);
        }
        r[9 * i + 0] = (uint8_t)(t[0] >> 0);
        r[9 * i + 1] = (uint8_t)(t[0] >> 8);
        r[9 * i + 2] = (uint8_t)(t[0] >> 16 | t[1] << 2);
        r[9 * i + 3] = (uint8_t)(t[1] >> 6);
        r[9 * i + 4] = (uint8_t)(t[1] >> 14 | t[2] << 4);
        r[9 * i + 5] = (uint8_t)(t[2] >> 4);
        r[9 * i + 6] = (uint8_t)(t[2] >> 12 | t[3] << 6);
        r[9 * i + 7] = (uint8_t)(t[3] >> 2);
        r[9 * i + 8] = (uint8_t)(t[3] >> 10);
    }
}

void dilithium_polyz_unpack(poly *r, const uint8_t *a) {
    polyz_unpack_chunk(r->coeffs, a, DILITHIUM_N / 4);
}

void dilithium_polyw1_pack(uint8_t *r, const poly *a) {
    for (size_t i = 0; i < DILITHIUM_N / 4; ++i) {
        r[3 * i + 0] = (uint8_t)(a->coeffs[4 * i + 0] | (a->coeffs[4 * i + 1] << 6));
        r[3 * i + 1] = (uint8_t)((a->coeffs[4 * i + 1] >> 2) | (a->coeffs[4 * i + 2] << 4));
        r[3 * i + 2] = (uint8_t)((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 2));
    }
}
