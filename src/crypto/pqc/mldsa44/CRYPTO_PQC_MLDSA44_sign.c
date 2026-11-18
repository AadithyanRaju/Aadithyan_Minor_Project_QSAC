/**
 * @file CRYPTO_PQC_MLDSA44_sign.c
 * @brief Digital signature algorithms implementation for ML-DSA-44 (Dilithium-2).
 */

#include "CRYPTO_PQC_MLDSA44_sign.h"
#include "CRYPTO_PQC_MLDSA44_packing.h"
#include "CRYPTO_PQC_MLDSA44_polyvec.h"
#include "CRYPTO_PQC_MLDSA44_poly.h"
#include "CRYPTO_PQC_MLDSA44_reduce.h"
#include "CRYPTO_PQC_MLDSA44_rounding.h"
#include "../../crypto_api.h"
#include "../../fips202.h"
#include <string.h>

typedef struct {
    polyvecl mat[DILITHIUM_K];
    polyvecl v_l[3];
    polyveck v_k[5];
    poly cp;
    uint8_t w1_packed[DILITHIUM_K * 192];
} mldsa_workspace_t;

static mldsa_workspace_t dsa_ws;

static void polyvec_matrix_expand(polyvecl mat[DILITHIUM_K], const uint8_t rho[DILITHIUM_SEEDBYTES]) {
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        for (size_t j = 0; j < DILITHIUM_L; ++j) {
            dilithium_poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

int pqcrystals_dilithium2_ref_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    uint8_t tr[DILITHIUM_TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl *mat = dsa_ws.mat;
    polyvecl *s1 = &dsa_ws.v_l[0];
    polyvecl *s1hat = &dsa_ws.v_l[1];
    polyveck *s2 = &dsa_ws.v_k[0];
    polyveck *t1 = &dsa_ws.v_k[1];
    polyveck *t0 = &dsa_ws.v_k[2];

    if (qsac_random_bytes(seedbuf, DILITHIUM_SEEDBYTES) != QSAC_OK) {
        return -1;
    }

    shake256(seedbuf, 2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES, seedbuf, DILITHIUM_SEEDBYTES);
    rho = seedbuf;
    rhoprime = rho + DILITHIUM_SEEDBYTES;
    key = rhoprime + DILITHIUM_CRHBYTES;

    polyvec_matrix_expand(mat, rho);

    dilithium_polyvecl_uniform_eta(s1, rhoprime, 0);
    dilithium_polyveck_uniform_eta(s2, rhoprime, DILITHIUM_L);

    *s1hat = *s1;
    dilithium_polyvecl_ntt(s1hat);
    dilithium_polyvec_matrix_pointwise_montgomery(t1, mat, s1hat);

    dilithium_polyveck_reduce(t1);
    dilithium_polyveck_invntt_tomont(t1);

    dilithium_polyveck_add(t1, t1, s2);
    dilithium_polyveck_caddq(t1);
    dilithium_polyveck_power2round(t1, t0, t1);

    pack_pk(pk, rho, t1);

    shake256(tr, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEYBYTES);
    pack_sk(sk, rho, tr, key, t0, s1, s2);
    return 0;
}

int pqcrystals_dilithium2_ref_signature(uint8_t *sig,
                                        size_t *siglen,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *sk) {
    uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES + 2 * DILITHIUM_CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint16_t nonce = 0;
    polyvecl *mat = dsa_ws.mat;
    polyvecl *s1 = &dsa_ws.v_l[0];
    polyvecl *y = &dsa_ws.v_l[1];
    polyvecl *z = &dsa_ws.v_l[2];
    polyveck *s2 = &dsa_ws.v_k[0];
    polyveck *t0 = &dsa_ws.v_k[1];
    polyveck *w1 = &dsa_ws.v_k[2];
    polyveck *w0 = &dsa_ws.v_k[3];
    polyveck *h = &dsa_ws.v_k[4];
    poly *cp = &dsa_ws.cp;
    uint8_t *w1_packed = dsa_ws.w1_packed;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + DILITHIUM_SEEDBYTES;
    key = tr + DILITHIUM_TRBYTES;
    mu = key + DILITHIUM_SEEDBYTES;
    rhoprime = mu + DILITHIUM_CRHBYTES;

    unpack_sk(rho, tr, key, t0, s1, s2, sk);

    // Compute mu = CRH(tr || msg)
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, DILITHIUM_TRBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, DILITHIUM_CRHBYTES, &state);

    // Compute rhoprime = CRH(key || mu)
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, key, DILITHIUM_SEEDBYTES);
    shake256_inc_absorb(&state, mu, DILITHIUM_CRHBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(rhoprime, DILITHIUM_CRHBYTES, &state);

    polyvec_matrix_expand(mat, rho);
    dilithium_polyvecl_ntt(s1);
    dilithium_polyveck_ntt(s2);
    dilithium_polyveck_ntt(t0);

rej:
    dilithium_polyvecl_uniform_gamma1(y, rhoprime, nonce++);
    *z = *y;
    dilithium_polyvecl_ntt(z);

    dilithium_polyvec_matrix_pointwise_montgomery(w1, mat, z);
    dilithium_polyveck_reduce(w1);
    dilithium_polyveck_invntt_tomont(w1);

    dilithium_polyveck_caddq(w1);
    dilithium_polyveck_decompose(w1, w0, w1);

    // Challenge c = H(mu || w1)
    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyw1_pack(w1_packed + i * 192, &w1->vec[i]);
    }

    uint8_t c[DILITHIUM_SEEDBYTES];
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, DILITHIUM_CRHBYTES);
    shake256_inc_absorb(&state, w1_packed, DILITHIUM_K * 192);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c, DILITHIUM_SEEDBYTES, &state);

    dilithium_poly_challenge(cp, c);
    dilithium_poly_ntt(cp);

    // z = y + c * s1
    dilithium_polyvecl_pointwise_poly_montgomery(z, cp, s1);
    dilithium_polyvecl_invntt_tomont(z);
    dilithium_polyvecl_add(z, z, y);
    dilithium_polyvecl_reduce(z);
    if (dilithium_polyvecl_chknorm(z, DILITHIUM_GAMMA1 - DILITHIUM_BETA)) {
        goto rej;
    }

    // Check norm of w0 - c*s2
    dilithium_polyveck_pointwise_poly_montgomery(h, cp, s2);
    dilithium_polyveck_invntt_tomont(h);
    dilithium_polyveck_sub(w0, w0, h);
    dilithium_polyveck_reduce(w0);
    if (dilithium_polyveck_chknorm(w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA)) {
        goto rej;
    }

    // Compute hint
    dilithium_polyveck_pointwise_poly_montgomery(h, cp, t0);
    dilithium_polyveck_invntt_tomont(h);
    dilithium_polyveck_reduce(h);
    if (dilithium_polyveck_chknorm(h, DILITHIUM_GAMMA2)) {
        goto rej;
    }

    dilithium_polyveck_add(w0, w0, h);
    dilithium_polyveck_caddq(w0);
    unsigned int n_hints = dilithium_polyveck_make_hint(h, w0, w1);
    if (n_hints > DILITHIUM_OMEGA) {
        goto rej;
    }

    pack_sig(sig, c, z, h);
    *siglen = DILITHIUM_SIGNATUREBYTES;
    return 0;
}

int pqcrystals_dilithium2_ref_verify(const uint8_t *sig,
                                     size_t siglen,
                                     const uint8_t *m,
                                     size_t mlen,
                                     const uint8_t *pk) {
    uint8_t rho[DILITHIUM_SEEDBYTES];
    uint8_t mu[DILITHIUM_CRHBYTES];
    uint8_t c[DILITHIUM_SEEDBYTES];
    uint8_t c2[DILITHIUM_SEEDBYTES];
    polyvecl *mat = dsa_ws.mat;
    polyvecl *z = &dsa_ws.v_l[0];
    polyveck *t1 = &dsa_ws.v_k[0];
    polyveck *w1 = &dsa_ws.v_k[1];
    polyveck *h = &dsa_ws.v_k[2];
    poly *cp = &dsa_ws.cp;
    uint8_t *w1_packed = dsa_ws.w1_packed;
    shake256incctx state;

    if (siglen != DILITHIUM_SIGNATUREBYTES) {
        return -1;
    }

    unpack_pk(rho, t1, pk);
    if (unpack_sig(c, z, h, sig)) {
        return -1;
    }

    if (dilithium_polyvecl_chknorm(z, DILITHIUM_GAMMA1 - DILITHIUM_BETA)) {
        return -1;
    }

    // Compute mu = CRH(CRH(pk) || msg)
    shake256(mu, DILITHIUM_TRBYTES, pk, DILITHIUM_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, DILITHIUM_TRBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, DILITHIUM_CRHBYTES, &state);

    dilithium_poly_challenge(cp, c);
    polyvec_matrix_expand(mat, rho);

    dilithium_polyvecl_ntt(z);
    dilithium_polyvec_matrix_pointwise_montgomery(w1, mat, z);

    dilithium_poly_ntt(cp);
    dilithium_polyveck_shiftl(t1);
    dilithium_polyveck_ntt(t1);
    dilithium_polyveck_pointwise_poly_montgomery(t1, cp, t1);

    dilithium_polyveck_sub(w1, w1, t1);
    dilithium_polyveck_reduce(w1);
    dilithium_polyveck_invntt_tomont(w1);

    dilithium_polyveck_caddq(w1);
    dilithium_polyveck_use_hint(w1, w1, h);

    for (size_t i = 0; i < DILITHIUM_K; ++i) {
        dilithium_polyw1_pack(w1_packed + i * 192, &w1->vec[i]);
    }

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, DILITHIUM_CRHBYTES);
    shake256_inc_absorb(&state, w1_packed, DILITHIUM_K * 192);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, DILITHIUM_SEEDBYTES, &state);

    if (memcmp(c, c2, DILITHIUM_SEEDBYTES) != 0) {
        return -1;
    }

    return 0;
}
