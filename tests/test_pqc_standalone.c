/**
 * @file test_pqc_standalone.c
 * @brief Standalone host test for ML-KEM-512 and ML-DSA-44.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../src/crypto/crypto_api.h"
#include "../src/crypto/fips202.h"
#include "../src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_kem.h"
#include "../src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_sign.h"

/* Host random bytes generator */
qsac_status_t qsac_random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return QSAC_OK;
}

int main(void) {
    srand(42);
    printf("=== Starting PQC Unit Tests on Host ===\n");

    /* 1. Test FIPS 202 SHA-3-256 */
    uint8_t digest[32];
    sha3_256(digest, (const uint8_t *)"", 0);
    printf("SHA3-256(\"\"): %02x%02x%02x%02x...\n", digest[0], digest[1], digest[2], digest[3]);
    const uint8_t sha3_expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    if (memcmp(digest, sha3_expected, 32) != 0) {
        printf("[FAIL] SHA3-256 test vector mismatch!\n");
        return 1;
    }
    printf("[PASS] SHA3-256 test vector matched!\n");

    /* 2. Test ML-KEM-512 */
    printf("\n--- Testing ML-KEM-512 ---\n");
    uint8_t kem_pk[800], kem_sk[1632], kem_ct[768];
    uint8_t ss_alice[32], ss_bob[32], ss_corrupt[32];

    if (pqcrystals_kyber512_ref_keypair(kem_pk, kem_sk) != 0) {
        printf("[FAIL] ML-KEM KeyGen failed\n");
        return 1;
    }
    printf("[PASS] ML-KEM KeyGen\n");

    if (pqcrystals_kyber512_ref_enc(kem_ct, ss_alice, kem_pk) != 0) {
        printf("[FAIL] ML-KEM Encaps failed\n");
        return 1;
    }
    printf("[PASS] ML-KEM Encaps (ss: %02x%02x%02x%02x...)\n", ss_alice[0], ss_alice[1], ss_alice[2], ss_alice[3]);

    if (pqcrystals_kyber512_ref_dec(ss_bob, kem_ct, kem_sk) != 0) {
        printf("[FAIL] ML-KEM Decaps failed\n");
        return 1;
    }
    printf("[PASS] ML-KEM Decaps (ss: %02x%02x%02x%02x...)\n", ss_bob[0], ss_bob[1], ss_bob[2], ss_bob[3]);

    if (memcmp(ss_alice, ss_bob, 32) != 0) {
        printf("[FAIL] ML-KEM Shared secret mismatch!\n");
        return 1;
    }
    printf("[PASS] ML-KEM Shared secret match!\n");

    kem_ct[0] ^= 0xFF;
    pqcrystals_kyber512_ref_dec(ss_corrupt, kem_ct, kem_sk);
    if (memcmp(ss_alice, ss_corrupt, 32) == 0) {
        printf("[FAIL] ML-KEM Implicit rejection failed (corrupted ct gave same secret)\n");
        return 1;
    }
    printf("[PASS] ML-KEM Implicit rejection on corrupt ciphertext\n");

    /* 3. Test ML-DSA-44 */
    printf("\n--- Testing ML-DSA-44 ---\n");
    uint8_t dsa_pk[1312], dsa_sk[2560], dsa_sig[2420];
    size_t siglen = 0;
    const char *msg = "QSAC Post-Quantum Access Control Token";
    size_t msglen = strlen(msg);

    if (pqcrystals_dilithium2_ref_keypair(dsa_pk, dsa_sk) != 0) {
        printf("[FAIL] ML-DSA KeyGen failed\n");
        return 1;
    }
    printf("[PASS] ML-DSA KeyGen\n");

    if (pqcrystals_dilithium2_ref_signature(dsa_sig, &siglen, (const uint8_t *)msg, msglen, dsa_sk) != 0) {
        printf("[FAIL] ML-DSA Sign failed\n");
        return 1;
    }
    printf("[PASS] ML-DSA Sign (siglen: %zu)\n", siglen);

    if (pqcrystals_dilithium2_ref_verify(dsa_sig, siglen, (const uint8_t *)msg, msglen, dsa_pk) != 0) {
        printf("[FAIL] ML-DSA Verify failed\n");
        return 1;
    }
    printf("[PASS] ML-DSA Verify\n");

    dsa_sig[0] ^= 0x55;
    if (pqcrystals_dilithium2_ref_verify(dsa_sig, siglen, (const uint8_t *)msg, msglen, dsa_pk) == 0) {
        printf("[FAIL] ML-DSA Verify accepted corrupted signature!\n");
        return 1;
    }
    printf("[PASS] ML-DSA Corrupted signature rejected\n");

    dsa_sig[0] ^= 0x55; // restore
    const char *fake_msg = "QSAC Post-Quantum Access Control Fake!";
    if (pqcrystals_dilithium2_ref_verify(dsa_sig, siglen, (const uint8_t *)fake_msg, strlen(fake_msg), dsa_pk) == 0) {
        printf("[FAIL] ML-DSA Verify accepted tampered message!\n");
        return 1;
    }
    printf("[PASS] ML-DSA Tampered message rejected\n");

    printf("\n=== ALL HOST PQC TESTS PASSED! ===\n");
    return 0;
}
