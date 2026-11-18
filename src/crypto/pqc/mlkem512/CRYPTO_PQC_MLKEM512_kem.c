/**
 * @file CRYPTO_PQC_MLKEM512_kem.c
 * @brief CCA-secure Key Encapsulation Mechanism implementation for ML-KEM-512.
 */

#include "CRYPTO_PQC_MLKEM512_kem.h"
#include "CRYPTO_PQC_MLKEM512_indcpa.h"
#include "CRYPTO_PQC_MLKEM512_verify.h"
#include "../../crypto_api.h"
#include "../../fips202.h"
#include <string.h>

int pqcrystals_kyber512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    sha3_256(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t coins[2 * KYBER_SYMBYTES];
    if (qsac_random_bytes(coins, sizeof(coins)) != QSAC_OK) {
        return -1;
    }
    return pqcrystals_kyber512_ref_keypair_derand(pk, sk, coins);
}

int pqcrystals_kyber512_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];

    memcpy(buf, coins, KYBER_SYMBYTES);
    sha3_256(buf + KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);
    sha3_512(kr, buf, 2 * KYBER_SYMBYTES);

    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);

    shake256(ss, KYBER_SSBYTES, kr, KYBER_SYMBYTES);
    return 0;
}

int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t coins[KYBER_SYMBYTES];
    if (qsac_random_bytes(coins, sizeof(coins)) != QSAC_OK) {
        return -1;
    }
    return pqcrystals_kyber512_ref_enc_derand(ct, ss, pk, coins);
}

int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, ct, sk);

    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);
    sha3_512(kr, buf, 2 * KYBER_SYMBYTES);

    indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

    int fail = pqc_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    shake256(kr, KYBER_SYMBYTES, kr, KYBER_SYMBYTES);

    // Compute rejection key: SHAKE256(z || ct)
    uint8_t rk[KYBER_SYMBYTES];
    shake256incctx state;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
    shake256_inc_absorb(&state, ct, KYBER_CIPHERTEXTBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(rk, KYBER_SYMBYTES, &state);

    pqc_cmov(kr, rk, KYBER_SYMBYTES, (uint8_t)fail);
    memcpy(ss, kr, KYBER_SSBYTES);
    return 0;
}
