/**
 * @file CRYPTO_PQC_MLDSA44_polyvec.c
 * @brief Polynomial vector operations implementation for Dilithium-2.
 */

#include "CRYPTO_PQC_MLDSA44_polyvec.h"
#include "CRYPTO_PQC_MLDSA44_reduce.h"

/* Vectors of length L */
void dilithium_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void dilithium_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t)(DILITHIUM_L * nonce + i));
    }
}

void dilithium_polyvecl_reduce(polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_reduce(&v->vec[i]);
    }
}

void dilithium_polyvecl_freeze(polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_freeze(&v->vec[i]);
    }
}

void dilithium_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void dilithium_polyvecl_ntt(polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

void dilithium_polyvecl_invntt_tomont(polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_invntt_tomont(&v->vec[i]);
    }
}

void dilithium_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

void __attribute__((optimize("O3"))) dilithium_polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v) {
    dilithium_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (size_t i = 1; i < DILITHIUM_L; ++i) {
        for (size_t j = 0; j < DILITHIUM_N; ++j) {
            int32_t t = dilithium_montgomery_reduce((int64_t)u->vec[i].coeffs[j] * v->vec[i].coeffs[j]);
            w->coeffs[j] += t;
        }
    }
    dilithium_poly_reduce(w);
}

int dilithium_polyvecl_chknorm(const polyvecl *v, int32_t B) {
    for (size_t i = 0; i < DILITHIUM_L; ++i) {
        if (dilithium_poly_chknorm(&v->vec[i], B)) return 1;
    }
    return 0;
}

/* Vectors of length K */
void dilithium_polyveck_uniform_eta(polyveck *v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void dilithium_polyveck_reduce(polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_reduce(&v->vec[i]);
    }
}

void dilithium_polyveck_caddq(polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_caddq(&v->vec[i]);
    }
}

void dilithium_polyveck_freeze(polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_freeze(&v->vec[i]);
    }
}

void dilithium_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void dilithium_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void dilithium_polyveck_shiftl(polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_shiftl(&v->vec[i]);
    }
}

void dilithium_polyveck_ntt(polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_ntt(&v->vec[i]);
    }
}

void dilithium_polyveck_invntt_tomont(polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_invntt_tomont(&v->vec[i]);
    }
}

void dilithium_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int dilithium_polyveck_chknorm(const polyveck *v, int32_t B) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        if (dilithium_poly_chknorm(&v->vec[i], B)) return 1;
    }
    return 0;
}

void dilithium_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

void dilithium_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

unsigned int dilithium_polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1) {
    unsigned int s = 0;
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        s += dilithium_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }
    return s;
}

void dilithium_polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

void dilithium_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DILITHIUM_K], const polyvecl *v) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}
