/**
 * @file CRYPTO_PQC_MLKEM512_indcpa.c
 * @brief IND-CPA key generation, encryption, and decryption implementation for Kyber-512.
 */

#include "CRYPTO_PQC_MLKEM512_indcpa.h"
#include "CRYPTO_PQC_MLKEM512_poly.h"
#include "CRYPTO_PQC_MLKEM512_polyvec.h"
#include "CRYPTO_PQC_MLKEM512_reduce.h"
#include "../../fips202.h"
#include <string.h>

#define GEN_MATRIX_NBLOCKS ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + SHAKE128_RATE) / SHAKE128_RATE)

typedef struct {
    polyvec pv[6];
    poly p[3];
} mlkem_workspace_t;

static mlkem_workspace_t kem_ws;

static size_t rej_uniform(int16_t *r, size_t len, const uint8_t *buf, size_t buflen) {
    size_t ctr = 0, pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        uint16_t val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        uint16_t val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            r[ctr++] = (int16_t)val0;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr++] = (int16_t)val1;
        }
    }
    return ctr;
}

static void gen_matrix(polyvec a[KYBER_K], const uint8_t seed[KYBER_SYMBYTES], int transposed) {
    uint8_t buf[GEN_MATRIX_NBLOCKS * SHAKE128_RATE];
    shake128incctx state;

    for (size_t i = 0; i < KYBER_K; ++i) {
        for (size_t j = 0; j < KYBER_K; ++j) {
            uint8_t sep[2];
            if (transposed) {
                sep[0] = (uint8_t)i;
                sep[1] = (uint8_t)j;
            } else {
                sep[0] = (uint8_t)j;
                sep[1] = (uint8_t)i;
            }

            shake128_inc_init(&state);
            shake128_inc_absorb(&state, seed, KYBER_SYMBYTES);
            shake128_inc_absorb(&state, sep, 2);
            shake128_inc_finalize(&state);
            shake128_inc_squeeze(buf, sizeof(buf), &state);

            size_t ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, sizeof(buf));
            while (ctr < KYBER_N) {
                uint8_t extra[SHAKE128_RATE];
                shake128_inc_squeeze(extra, SHAKE128_RATE, &state);
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, extra, SHAKE128_RATE);
            }
        }
    }
}

void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES]) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    polyvec *a = &kem_ws.pv[0];
    polyvec *e = &kem_ws.pv[2];
    polyvec *pkpv = &kem_ws.pv[3];
    polyvec *skpv = &kem_ws.pv[4];

    sha3_512(buf, coins, KYBER_SYMBYTES);

    gen_matrix(a, publicseed, 0);

    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_getnoise_eta1(&skpv->vec[i], noiseseed, (uint8_t)i);
    }
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_getnoise_eta1(&e->vec[i], noiseseed, (uint8_t)(KYBER_K + i));
    }

    kyber_polyvec_ntt(skpv);
    kyber_polyvec_ntt(e);

    // Matrix-vector multiplication: pkpv = a * skpv + e
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_polyvec_basemul_acc_montgomery(&pkpv->vec[i], &a[i], skpv);
        kyber_poly_tomont(&pkpv->vec[i]);
        kyber_poly_add(&pkpv->vec[i], &pkpv->vec[i], &e->vec[i]);
        kyber_poly_reduce(&pkpv->vec[i]);
    }

    kyber_polyvec_tobytes(pk, pkpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES);
    kyber_polyvec_tobytes(sk, skpv);
}

void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]) {
    polyvec *sp = &kem_ws.pv[0];
    polyvec *pkpv = &kem_ws.pv[1];
    polyvec *ep = &kem_ws.pv[2];
    polyvec *at = &kem_ws.pv[3];
    polyvec *bp = &kem_ws.pv[5];
    poly *v = &kem_ws.p[0];
    poly *k = &kem_ws.p[1];
    poly *epp = &kem_ws.p[2];
    const uint8_t *seed = pk + KYBER_POLYVECBYTES;

    kyber_polyvec_frombytes(pkpv, pk);
    gen_matrix(at, seed, 1);

    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_getnoise_eta1(&sp->vec[i], coins, (uint8_t)i);
    }
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_poly_getnoise_eta2(&ep->vec[i], coins, (uint8_t)(KYBER_K + i));
    }
    kyber_poly_getnoise_eta2(epp, coins, (uint8_t)(2 * KYBER_K));

    kyber_polyvec_ntt(sp);

    // bp = at * sp + ep
    for (size_t i = 0; i < KYBER_K; ++i) {
        kyber_polyvec_basemul_acc_montgomery(&bp->vec[i], &at[i], sp);
        kyber_poly_tomont(&bp->vec[i]);
    }
    kyber_polyvec_invntt_tomont(bp);
    kyber_polyvec_add(bp, bp, ep);
    kyber_polyvec_reduce(bp);

    // v = pkpv^T * sp + epp + m
    kyber_polyvec_basemul_acc_montgomery(v, pkpv, sp);
    kyber_poly_tomont(v);
    kyber_poly_invntt_tomont(v);
    kyber_poly_add(v, v, epp);
    kyber_poly_frommsg(k, m);
    kyber_poly_add(v, v, k);
    kyber_poly_reduce(v);

    kyber_polyvec_compress_du(c, bp);
    kyber_poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES_DU, v);
}

void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec *bp = &kem_ws.pv[0];
    polyvec *skpv = &kem_ws.pv[1];
    poly *v = &kem_ws.p[0];
    poly *mp = &kem_ws.p[1];

    kyber_polyvec_decompress_du(bp, c);
    kyber_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES_DU);
    kyber_polyvec_frombytes(skpv, sk);

    kyber_polyvec_ntt(bp);
    kyber_polyvec_basemul_acc_montgomery(mp, skpv, bp);
    kyber_poly_tomont(mp);
    kyber_poly_invntt_tomont(mp);

    kyber_poly_sub(mp, v, mp);
    kyber_poly_reduce(mp);

    kyber_poly_tomsg(m, mp);
}
