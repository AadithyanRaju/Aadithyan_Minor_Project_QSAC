/**
 * @file main.c
 * @brief QSAC firmware entry point.
 *
 * Runs a phased bring-up sequence:
 *   Phase 1: System init, UART, RNG, AES-256-GCM self-test
 *   Phase 2: Classical ECDH handshake baseline (when enabled)
 *   Phase 3+: PQC and hybrid operations (when enabled)
 */

#include "qsac_features.h"
#include "crypto/crypto_api.h"
#include "crypto/atecc608b.h"
#include "protocol/PROTOCOL_handshake.h"
#include "protocol/PROTOCOL_token_verify.h"
#include "protocol/PROTOCOL_state_machine.h"
#include "protocol/PROTOCOL_enrollment.h"
#include "protocol/PROTOCOL_uart_bridge.h"
#include "hal/hal.h"
#include <stdint.h>
#include <string.h>

/* ----------------------------------------------
 * Version
 * ---------------------------------------------- */

#define QSAC_VERSION_MAJOR 0
#define QSAC_VERSION_MINOR 1
#define QSAC_VERSION_PATCH 0

/* ----------------------------------------------
 * Test functions
 * ---------------------------------------------- */

static int test_rng(void)
{
    uint8_t buf[32];
    qsac_status_t status = qsac_random_bytes(buf, sizeof(buf));

    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_random_bytes returned %d\r\n", status);
        return 0;
    }

    /* Sanity: check it's not all zeros */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (buf[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (all_zero) {
        hal_uart_print("  ERROR: RNG returned all zeros\r\n");
        return 0;
    }

    hal_uart_print("  Random 32 bytes: ");
    hal_print_hex(buf, 32);
    hal_uart_print("\r\n");
    return 1;
}

static int test_sha256(void)
{
    /* Test vector: SHA-256("") = e3b0c44298fc1c14... */
    const uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    uint8_t digest[32];

    qsac_status_t status = qsac_sha256((const uint8_t *)"", 0, digest);
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_sha256 returned %d\r\n", status);
        return 0;
    }

    if (memcmp(digest, expected, 32) != 0) {
        hal_uart_print("  ERROR: SHA-256 digest mismatch\r\n");
        hal_uart_print("  Expected: ");
        hal_print_hex(expected, 32);
        hal_uart_print("\r\n  Got:      ");
        hal_print_hex(digest, 32);
        hal_uart_print("\r\n");
        return 0;
    }

    hal_uart_print("  SHA-256(\"\") = ");
    hal_print_hex(digest, 16);
    hal_uart_print("...\r\n");
    return 1;
}

static int test_sha3(void)
{
    /* Test vector: SHA-3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
    const uint8_t expected[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };
    uint8_t digest[32];

    qsac_status_t status = qsac_sha3_256((const uint8_t *)"", 0, digest);
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_sha3_256 returned %d\r\n", status);
        return 0;
    }

    if (memcmp(digest, expected, 32) != 0) {
        hal_uart_print("  ERROR: SHA-3-256 digest mismatch\r\n");
        hal_uart_print("  Expected: ");
        hal_print_hex(expected, 32);
        hal_uart_print("\r\n  Got:      ");
        hal_print_hex(digest, 32);
        hal_uart_print("\r\n");
        return 0;
    }

    hal_uart_print("  SHA-3-256(\"\") = ");
    hal_print_hex(digest, 16);
    hal_uart_print("...\r\n");
    return 1;
}

static int test_aes_gcm(void)
{
    /* Test AES-256-GCM roundtrip */
    uint8_t key[QSAC_AES_KEY_SIZE];
    uint8_t iv[QSAC_AES_IV_SIZE];

    /* Deterministic test key/IV */
    for (int i = 0; i < QSAC_AES_KEY_SIZE; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < QSAC_AES_IV_SIZE; i++)  iv[i]  = (uint8_t)(0xA0 + i);

    const char *plaintext_str = "QSAC AES-256-GCM test vector!";
    size_t pt_len = strlen(plaintext_str);
    const uint8_t *plaintext = (const uint8_t *)plaintext_str;

    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    uint8_t tag[QSAC_AES_TAG_SIZE];

    /* Encrypt */
    qsac_status_t status = qsac_aes_gcm_encrypt(key, iv, NULL, 0,
                                                  plaintext, pt_len,
                                                  ciphertext, tag);
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: Encrypt returned %d\r\n", status);
        return 0;
    }

    hal_uart_print("  Ciphertext: ");
    hal_print_hex(ciphertext, pt_len > 16 ? 16 : pt_len);
    hal_uart_print("...\r\n");
    hal_uart_print("  Tag:        ");
    hal_print_hex(tag, QSAC_AES_TAG_SIZE);
    hal_uart_print("\r\n");

    /* Decrypt */
    status = qsac_aes_gcm_decrypt(key, iv, NULL, 0,
                                   ciphertext, pt_len,
                                   tag, decrypted);
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: Decrypt returned %d\r\n", status);
        return 0;
    }

    /* Verify roundtrip */
    if (memcmp(decrypted, plaintext, pt_len) != 0) {
        hal_uart_print("  ERROR: Plaintext mismatch after decrypt\r\n");
        return 0;
    }

    hal_uart_print("  Roundtrip:  OK\r\n");
    return 1;
}

static int test_ecc_keygen(void)
{
    uint8_t pubkey[QSAC_ECC_PUBKEY_SIZE];

    qsac_status_t status = qsac_ecc_keygen(0, pubkey);
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_ecc_keygen returned %d\r\n", status);
        return 0;
    }

    hal_uart_print("  ECC P-256 public key (x): ");
    hal_print_hex(pubkey, 32);
    hal_uart_print("\r\n");
    hal_uart_print("  ECC P-256 public key (y): ");
    hal_print_hex(pubkey + 32, 32);
    hal_uart_print("\r\n");
    return 1;
}

static int test_ecdh(void)
{
    /* Generate two keypairs and perform ECDH from both sides */
    uint8_t pub_a[QSAC_ECC_PUBKEY_SIZE], pub_b[QSAC_ECC_PUBKEY_SIZE];
    uint8_t secret_a[QSAC_ECC_SHARED_SECRET_SIZE];
    uint8_t secret_b[QSAC_ECC_SHARED_SECRET_SIZE];

    /* Key slot 1 = Alice, Key slot 2 = Bob */
    if (qsac_ecc_keygen(1, pub_a) != QSAC_OK ||
        qsac_ecc_keygen(2, pub_b) != QSAC_OK) {
        hal_uart_print("  ERROR: Keypair generation failed\r\n");
        return 0;
    }

    /* Alice computes shared secret using Bob's public key */
    if (qsac_ecdh(1, pub_b, secret_a) != QSAC_OK) {
        hal_uart_print("  ERROR: ECDH (Alice) failed\r\n");
        return 0;
    }

    /* Bob computes shared secret using Alice's public key */
    if (qsac_ecdh(2, pub_a, secret_b) != QSAC_OK) {
        hal_uart_print("  ERROR: ECDH (Bob) failed\r\n");
        return 0;
    }

    /* Both should agree */
    if (memcmp(secret_a, secret_b, QSAC_ECC_SHARED_SECRET_SIZE) != 0) {
        hal_uart_print("  ERROR: ECDH shared secrets do not match!\r\n");
        hal_uart_print("  Alice: ");
        hal_print_hex(secret_a, 32);
        hal_uart_print("\r\n  Bob:   ");
        hal_print_hex(secret_b, 32);
        hal_uart_print("\r\n");
        return 0;
    }

    hal_uart_print("  Shared secret: ");
    hal_print_hex(secret_a, 32);
    hal_uart_print("\r\n  Secrets match: YES\r\n");
    return 1;
}

static int test_ecdsa(void)
{
    uint8_t pubkey[QSAC_ECC_PUBKEY_SIZE];
    uint8_t sig[QSAC_ECDSA_SIG_SIZE];
    uint8_t digest[32];

    /* Deterministic test digest */
    for (int i = 0; i < 32; i++) digest[i] = (uint8_t)(0xC0 + i);

    /* Generate keypair in slot 3 */
    if (qsac_ecc_keygen(3, pubkey) != QSAC_OK) {
        hal_uart_print("  ERROR: Keypair generation failed\r\n");
        return 0;
    }

    /* Sign digest */
    if (qsac_ecdsa_sign(3, digest, sig) != QSAC_OK) {
        hal_uart_print("  ERROR: ECDSA sign failed\r\n");
        return 0;
    }

    hal_uart_print("  ECDSA signature (r): ");
    hal_print_hex(sig, 32);
    hal_uart_print("\r\n  ECDSA signature (s): ");
    hal_print_hex(sig + 32, 32);
    hal_uart_print("\r\n");

    /* Verify signature */
    if (qsac_ecdsa_verify(pubkey, digest, sig) != QSAC_OK) {
        hal_uart_print("  ERROR: ECDSA verify failed for valid signature\r\n");
        return 0;
    }

    /* Verify rejection with corrupted signature */
    sig[0] ^= 0xFF;
    if (qsac_ecdsa_verify(pubkey, digest, sig) == QSAC_OK) {
        hal_uart_print("  ERROR: ECDSA verify accepted corrupted signature!\r\n");
        return 0;
    }

    hal_uart_print("  Signature verify: OK (valid accepted, corrupted rejected)\r\n");
    return 1;
}

static int test_hkdf(void)
{
    /* Test the HKDF combiner with known inputs */
    uint8_t ecdh_secret[QSAC_ECC_SHARED_SECRET_SIZE];
    uint8_t mlkem_secret[QSAC_MLKEM_SHARED_SECRET_SIZE];
    uint8_t session_key[QSAC_SESSION_KEY_SIZE];

    /* Fill with deterministic test data */
    for (int i = 0; i < QSAC_ECC_SHARED_SECRET_SIZE; i++)
        ecdh_secret[i] = (uint8_t)i;
    for (int i = 0; i < QSAC_MLKEM_SHARED_SECRET_SIZE; i++)
        mlkem_secret[i] = (uint8_t)(0x80 + i);

    const char *info = "QSAC hybrid session key v1";
    qsac_status_t status = qsac_hkdf_combine(ecdh_secret, mlkem_secret,
                                               (const uint8_t *)info,
                                               strlen(info),
                                               session_key);
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: HKDF returned %d\r\n", status);
        return 0;
    }

    hal_uart_print("  Session key: ");
    hal_print_hex(session_key, QSAC_SESSION_KEY_SIZE);
    hal_uart_print("\r\n");

    /* Verify determinism: same inputs → same output */
    uint8_t session_key2[QSAC_SESSION_KEY_SIZE];
    qsac_hkdf_combine(ecdh_secret, mlkem_secret,
                       (const uint8_t *)info, strlen(info), session_key2);
    if (memcmp(session_key, session_key2, QSAC_SESSION_KEY_SIZE) != 0) {
        hal_uart_print("  ERROR: HKDF not deterministic!\r\n");
        return 0;
    }
    hal_uart_print("  Deterministic: YES\r\n");
    return 1;
}

#ifdef QSAC_PQC_ENABLED
static int test_mlkem(void)
{
    static uint8_t pk[QSAC_MLKEM_PUBKEY_SIZE];
    static uint8_t sk[QSAC_MLKEM_PRIVKEY_SIZE];
    static uint8_t ct[QSAC_MLKEM_CIPHERTEXT_SIZE];
    uint8_t ss_alice[QSAC_MLKEM_SHARED_SECRET_SIZE];
    uint8_t ss_bob[QSAC_MLKEM_SHARED_SECRET_SIZE];

    hal_uart_print("  Generating ML-KEM-512 keypair...\r\n");
    uint32_t t0 = hal_cycle_count();
    qsac_status_t status = qsac_mlkem_keygen(pk, sk);
    uint32_t t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_mlkem_keygen returned %d\r\n", status);
        return 0;
    }
    hal_uart_printf("  KeyGen: %lu cycles\r\n", (unsigned long)(t1 - t0));

    hal_uart_print("  Encapsulating shared secret...\r\n");
    t0 = hal_cycle_count();
    status = qsac_mlkem_encaps(pk, ct, ss_alice);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_mlkem_encaps returned %d\r\n", status);
        return 0;
    }
    hal_uart_printf("  Encaps: %lu cycles\r\n", (unsigned long)(t1 - t0));

    hal_uart_print("  Decapsulating shared secret...\r\n");
    t0 = hal_cycle_count();
    status = qsac_mlkem_decaps(sk, ct, ss_bob);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_mlkem_decaps returned %d\r\n", status);
        return 0;
    }
    hal_uart_printf("  Decaps: %lu cycles\r\n", (unsigned long)(t1 - t0));

    if (memcmp(ss_alice, ss_bob, QSAC_MLKEM_SHARED_SECRET_SIZE) != 0) {
        hal_uart_print("  ERROR: Shared secret mismatch!\r\n");
        return 0;
    }
    hal_uart_print("  Shared secret match: YES (");
    hal_print_hex(ss_alice, 16);
    hal_uart_print("...)\r\n");

    /* Test implicit rejection on corrupted ciphertext */
    uint8_t ss_corrupt[QSAC_MLKEM_SHARED_SECRET_SIZE];
    ct[0] ^= 0xFF;
    qsac_mlkem_decaps(sk, ct, ss_corrupt);
    if (memcmp(ss_alice, ss_corrupt, QSAC_MLKEM_SHARED_SECRET_SIZE) == 0) {
        hal_uart_print("  ERROR: Corrupted ciphertext did not produce different secret!\r\n");
        return 0;
    }
    hal_uart_print("  Implicit rejection on corrupt ciphertext: PASS\r\n");
    return 1;
}

static int test_mldsa(void)
{
    static uint8_t pk[QSAC_MLDSA_PUBKEY_SIZE];
    static uint8_t sk[QSAC_MLDSA_PRIVKEY_SIZE];
    static uint8_t sig[QSAC_MLDSA_SIG_SIZE];
    const char *msg = "QSAC Post-Quantum Access Control Token";
    size_t msg_len = strlen(msg);

    hal_uart_print("  Generating ML-DSA-44 keypair...\r\n");
    uint32_t t0 = hal_cycle_count();
    qsac_status_t status = qsac_mldsa_keygen(pk, sk);
    uint32_t t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_mldsa_keygen returned %d\r\n", status);
        return 0;
    }
    hal_uart_printf("  KeyGen: %lu cycles\r\n", (unsigned long)(t1 - t0));

    hal_uart_print("  Signing message...\r\n");
    t0 = hal_cycle_count();
    status = qsac_mldsa_sign(sk, (const uint8_t *)msg, msg_len, sig);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_mldsa_sign returned %d\r\n", status);
        return 0;
    }
    hal_uart_printf("  Sign: %lu cycles\r\n", (unsigned long)(t1 - t0));

    hal_uart_print("  Verifying signature...\r\n");
    t0 = hal_cycle_count();
    status = qsac_mldsa_verify(pk, (const uint8_t *)msg, msg_len, sig);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: qsac_mldsa_verify failed (%d)\r\n", status);
        return 0;
    }
    hal_uart_printf("  Verify: %lu cycles (PASS)\r\n", (unsigned long)(t1 - t0));

    /* Test corrupted signature rejection */
    sig[0] ^= 0x55;
    status = qsac_mldsa_verify(pk, (const uint8_t *)msg, msg_len, sig);
    if (status == QSAC_OK) {
        hal_uart_print("  ERROR: Corrupted signature passed verification!\r\n");
        return 0;
    }
    hal_uart_print("  Corrupt signature rejection: PASS\r\n");

    /* Test modified message rejection */
    sig[0] ^= 0x55; // restore signature
    const char *tampered_msg = "QSAC Post-Quantum Access Control Fake!";
    status = qsac_mldsa_verify(pk, (const uint8_t *)tampered_msg, strlen(tampered_msg), sig);
    if (status == QSAC_OK) {
        hal_uart_print("  ERROR: Tampered message passed verification!\r\n");
        return 0;
    }
    hal_uart_print("  Tampered message rejection: PASS\r\n");
    return 1;
}

static int test_hybrid_handshake(void)
{
    static qsac_handshake_client_ctx_t client_ctx;
    static qsac_handshake_server_ctx_t server_ctx;
    static qsac_client_hello_t client_hello;
    static qsac_server_hello_t server_hello;
    static qsac_client_finished_t client_finished;
    static uint8_t server_mldsa_pk[QSAC_MLDSA_PUBKEY_SIZE];
    static uint8_t server_mldsa_sk[QSAC_MLDSA_PRIVKEY_SIZE];

    hal_uart_print("  Provisioning Server ML-DSA-44 Identity...\r\n");
    uint32_t t0 = hal_cycle_count();
    qsac_status_t status = qsac_mldsa_keygen(server_mldsa_pk, server_mldsa_sk);
    uint32_t t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: Server ML-DSA keygen failed (%d)\r\n", status);
        return 0;
    }
    hal_uart_printf("  Server Identity KeyGen: %lu cycles\r\n", (unsigned long)(t1 - t0));

    /* 1. Client creates ClientHello (ECDH + ML-KEM ephemeral keys) */
    hal_uart_print("  1. Client generating ClientHello (ECDH + ML-KEM-512)...\r\n");
    qsac_handshake_client_init(&client_ctx, 0x10);
    t0 = hal_cycle_count();
    status = qsac_handshake_client_create_hello(&client_ctx, &client_hello);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: ClientHello creation failed (%d)\r\n", status);
        return 0;
    }
    hal_uart_printf("  ClientHello: %lu cycles\r\n", (unsigned long)(t1 - t0));

    /* 2. Server processes ClientHello and creates ServerHello (ECDH + ML-KEM Encaps + ML-DSA Sign) */
    hal_uart_print("  2. Server processing Hello & generating ServerHello (Encaps + ML-DSA-44 Sign)...\r\n");
    t0 = hal_cycle_count();
    status = qsac_handshake_server_process_hello_and_respond(
        &server_ctx, 0x11, server_mldsa_sk, &client_hello, &server_hello);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: ServerHello creation failed (%d)\r\n", status);
        return 0;
    }
    hal_uart_printf("  ServerHello & Derivation: %lu cycles\r\n", (unsigned long)(t1 - t0));

    /* 3. Client processes ServerHello (Verify ML-DSA Sign + Decaps + HKDF Derivation + ClientFinished AES-GCM) */
    hal_uart_print("  3. Client verifying Server Signature, decapsulating, and deriving session key...\r\n");
    t0 = hal_cycle_count();
    status = qsac_handshake_client_process_server_hello(
        &client_ctx, server_mldsa_pk, &server_hello, &client_finished);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: Client processing ServerHello failed (%d)\r\n", status);
        return 0;
    }
    hal_uart_printf("  Client Process & Derivation: %lu cycles\r\n", (unsigned long)(t1 - t0));

    /* 4. Server verifies ClientFinished */
    hal_uart_print("  4. Server verifying ClientFinished confirmation...\r\n");
    t0 = hal_cycle_count();
    status = qsac_handshake_server_process_finished(&server_ctx, &client_finished);
    t1 = hal_cycle_count();
    if (status != QSAC_OK) {
        hal_uart_printf("  ERROR: Server ClientFinished verification failed (%d)\r\n", status);
        return 0;
    }
    hal_uart_printf("  Server Verify Finished: %lu cycles\r\n", (unsigned long)(t1 - t0));

    /* Verify derived session keys match identically */
    if (memcmp(client_ctx.session_key, server_ctx.session_key, QSAC_SESSION_KEY_SIZE) != 0) {
        hal_uart_print("  ERROR: Client and Server session keys do not match!\r\n");
        return 0;
    }

    hal_uart_print("  Derived Hybrid Session Key: ");
    hal_print_hex(client_ctx.session_key, 16);
    hal_uart_print("...\r\n");
    hal_uart_print("  Hybrid Mutual Authentication: PASS\r\n");
    return 1;
}

static int test_state_machine_and_tokens(void)
{
    static qsac_state_machine_t sm;
    static qsac_access_token_t token;
    static uint8_t auth_pk[QSAC_MLDSA_PUBKEY_SIZE];
    static uint8_t auth_sk[QSAC_MLDSA_PRIVKEY_SIZE];
    static uint8_t dummy_session_key[QSAC_SESSION_KEY_SIZE];
    static uint8_t iv[QSAC_AES_IV_SIZE];
    static uint8_t ct[64];
    static uint8_t pt[64];
    static uint8_t tag[QSAC_AES_TAG_SIZE];

    hal_uart_print("  Initializing Access Control State Machine...\r\n");
    qsac_sm_init(&sm);
    if (qsac_sm_get_state(&sm) != QSAC_SM_STATE_IDLE) {
        hal_uart_print("  ERROR: SM not in IDLE state\r\n");
        return 0;
    }
    hal_uart_printf("  Initial State: %s\r\n", qsac_sm_get_state_name(qsac_sm_get_state(&sm)));

    /* Trigger connect */
    qsac_sm_process_event(&sm, QSAC_EVT_CONNECT_TRIGGER, NULL);
    if (qsac_sm_get_state(&sm) != QSAC_SM_STATE_HANDSHAKING) {
        hal_uart_print("  ERROR: SM transition to HANDSHAKING failed\r\n");
        return 0;
    }
    hal_uart_printf("  State -> %s\r\n", qsac_sm_get_state_name(qsac_sm_get_state(&sm)));

    /* Establish session */
    qsac_random_bytes(dummy_session_key, sizeof(dummy_session_key));
    qsac_sm_process_event(&sm, QSAC_EVT_HANDSHAKE_OK, dummy_session_key);
    if (qsac_sm_get_state(&sm) != QSAC_SM_STATE_SESSION_ESTABLISHED) {
        hal_uart_print("  ERROR: SM transition to SESSION_ESTABLISHED failed\r\n");
        return 0;
    }
    hal_uart_printf("  State -> %s\r\n", qsac_sm_get_state_name(qsac_sm_get_state(&sm)));

    /* Test encrypted session communication */
    const char *telemetry = "Pico Sensor: Secure Door Access Request #42";
    size_t tel_len = strlen(telemetry);
    qsac_status_t status = qsac_sm_encrypt_payload(&sm, (const uint8_t *)telemetry, tel_len, iv, ct, tag);
    if (status != QSAC_OK) {
        hal_uart_print("  ERROR: SM Encrypt payload failed\r\n");
        return 0;
    }
    status = qsac_sm_decrypt_payload(&sm, iv, ct, tel_len, tag, pt);
    if (status != QSAC_OK || memcmp(telemetry, pt, tel_len) != 0) {
        hal_uart_print("  ERROR: SM Decrypt payload mismatch\r\n");
        return 0;
    }
    hal_uart_print("  Encrypted Session Frame Exchange: PASS\r\n");

    /* Issue and verify ML-DSA Access Token */
    hal_uart_print("  Generating Authority ML-DSA-44 Keypair...\r\n");
    qsac_mldsa_keygen(auth_pk, auth_sk);
    qsac_token_load_authority_key(auth_pk);

    qsac_token_payload_t payload = {
        .device_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
        .issued_at = 1700000000,
        .expires_at = 1700003600, // valid for 1 hour
        .permissions = QSAC_PERM_ACCESS_DOOR | QSAC_PERM_READ_TELEMETRY
    };

    hal_uart_print("  Issuing ML-DSA-44 Signed Access Token...\r\n");
    status = qsac_token_issue(auth_sk, &payload, &token);
    if (status != QSAC_OK) {
        hal_uart_print("  ERROR: Token issuance failed\r\n");
        return 0;
    }

    /* Request Access */
    qsac_sm_process_event(&sm, QSAC_EVT_ACCESS_REQUEST, NULL);
    hal_uart_printf("  State -> %s\r\n", qsac_sm_get_state_name(qsac_sm_get_state(&sm)));

    /* Verify Token at valid time (1700001000) */
    uint32_t granted_perms = 0;
    status = qsac_token_verify(&token, 1700001000, &granted_perms);
    if (status != QSAC_OK) {
        hal_uart_print("  ERROR: Valid token verification failed\r\n");
        return 0;
    }
    qsac_sm_process_event(&sm, QSAC_EVT_TOKEN_VALID, &granted_perms);
    if (qsac_sm_get_state(&sm) != QSAC_SM_STATE_ACCESS_GRANTED) {
        hal_uart_print("  ERROR: SM not in ACCESS_GRANTED state\r\n");
        return 0;
    }
    hal_uart_printf("  State -> %s (Permissions: 0x%08lX)\r\n",
                    qsac_sm_get_state_name(qsac_sm_get_state(&sm)), (unsigned long)granted_perms);

    /* Test Expired Token Rejection */
    status = qsac_token_verify(&token, 1700009999, &granted_perms); // expired
    if (status == QSAC_OK) {
        hal_uart_print("  ERROR: Expired token passed verification!\r\n");
        return 0;
    }
    hal_uart_print("  Expired Token Rejection: PASS\r\n");

    /* Terminate session */
    qsac_sm_terminate(&sm);
    if (qsac_sm_get_state(&sm) != QSAC_SM_STATE_IDLE) {
        hal_uart_print("  ERROR: SM terminate failed\r\n");
        return 0;
    }
    hal_uart_printf("  State -> %s (Session Zeroized)\r\n", qsac_sm_get_state_name(qsac_sm_get_state(&sm)));

    return 1;
}
#endif

/* ----------------------------------------------
 * Main
 * ---------------------------------------------- */

int main(void)
{
    hal_system_init();
    hal_cycle_counter_init();

    hal_uart_print("\r\n");
    hal_uart_print("╔══════════════════════════════════════════╗\r\n");
    hal_uart_print("║  QSAC — Quantum-Secure Access Control   ║\r\n");
    hal_uart_printf("║  Firmware v%d.%d.%d",
                    QSAC_VERSION_MAJOR, QSAC_VERSION_MINOR, QSAC_VERSION_PATCH);
    hal_uart_print("                        ║\r\n");
    hal_uart_printf("║  Clock: %lu MHz", (unsigned long)(hal_get_sysclk_hz() / 1000000));
    hal_uart_print("                           ║\r\n");
    hal_uart_print("╚══════════════════════════════════════════╝\r\n\r\n");

    /* Initialize crypto subsystem */
    hal_uart_print("[INIT] Initializing crypto subsystem...\r\n");
    qsac_status_t status = qsac_crypto_init();
    if (status != QSAC_OK) {
        hal_uart_printf("[FAIL] Crypto init returned %d\r\n", status);
        hal_led_set(1); /* solid LED = error */
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1); /* GP16: Error */
        while (1) {}
    }
    hal_status_pin_set(QSAC_STATUS_PIN_SYS_READY, 1); /* GP6: System Ready */
    hal_uart_print("[INIT] Crypto subsystem ready.\r\n\r\n");

#ifdef QSAC_PLATFORM_PICO
#if QSAC_FEATURE_ATECC608B
    const atecc608b_info_t *atecc_info = atecc608b_get_info();
    if (atecc_info && atecc_info->present) {
        hal_uart_print("╔══════════════════════════════════════════╗\r\n");
        hal_uart_print("║  ATECC608B Hardware Security Module     ║\r\n");
        hal_uart_print("╚══════════════════════════════════════════╝\r\n");
        hal_uart_printf("  Bus: I2C0 (GP4 SDA / GP5 SCL @ 0x%02X)\r\n", ATECC_I2C_ADDR_DEFAULT);
        hal_uart_printf("  Device Revision: 0x%08lX\r\n", (unsigned long)atecc_info->revision);
        hal_uart_print("  Hardware Serial Number: ");
        hal_print_hex(atecc_info->serial_number, ATECC_SERIAL_NUM_SIZE);
        hal_uart_print("\r\n");
        hal_uart_printf("  Config Zone: %s\r\n", atecc_info->config_locked ? "LOCKED" : "UNLOCKED");
        hal_uart_printf("  Data Zone:   %s\r\n", atecc_info->data_locked ? "LOCKED" : "UNLOCKED");
        hal_uart_print("  Hardware Acceleration: ACTIVE (TRNG, Key Vault, ECC P-256)\r\n\r\n");
    } else {
        hal_uart_print("[INFO] ATECC608B HSM not detected on I2C bus (operating in software emulation)\r\n\r\n");
    }
#else
    hal_uart_print("[CONFIG] ATECC608B feature switch DISABLED in qsac_features.h (pure software mode)\r\n\r\n");
#endif
#endif

    /* -- Phase 1, 2, 3, 4: Crypto & Protocol Self-Tests -- */

    int pass = 0, fail = 0;

    hal_uart_print("-- Cryptographic Subsystem Self-Tests --\r\n\r\n");

    /* Test 1: RNG */
    hal_uart_print("[TEST 1/12] Hardware RNG (ATECC608B TRNG / ROSC) [GP7 (Pin 10)]\r\n");
    uint32_t t0 = hal_cycle_count();
    if (test_rng()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] RNG (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_RNG_OK, 1); /* GP7 (Pin 10): RNG OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] RNG\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 2: SHA-256 */
    hal_uart_print("[TEST 2/12] SHA-256 (NIST Vector) [GP8 (Pin 11)]\r\n");
    t0 = hal_cycle_count();
    if (test_sha256()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] SHA-256 (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_SHA256_OK, 1); /* GP8 (Pin 11): SHA-256 OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] SHA-256\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 3: SHA-3-256 */
    hal_uart_print("[TEST 3/12] SHA-3-256 (FIPS 202) [GP9 (Pin 12)]\r\n");
    t0 = hal_cycle_count();
    if (test_sha3()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] SHA-3-256 (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_SHA3_OK, 1); /* GP9 (Pin 12): SHA-3-256 OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] SHA-3-256\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 4: AES-256-GCM */
    hal_uart_print("[TEST 4/12] AES-256-GCM (Authenticated Roundtrip) [GP10 (Pin 14)]\r\n");
    t0 = hal_cycle_count();
    if (test_aes_gcm()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] AES-256-GCM (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_AES_GCM_OK, 1); /* GP10 (Pin 14): AES-GCM OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] AES-256-GCM\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 5: ECC P-256 KeyGen */
    hal_uart_print("[TEST 5/12] ECC P-256 KeyGen [GP11 (Pin 15)]\r\n");
    t0 = hal_cycle_count();
    if (test_ecc_keygen()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] ECC KeyGen (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_ECC_KEYGEN, 1); /* GP11 (Pin 15): ECC KeyGen OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] ECC KeyGen\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 6: ECDH Key Agreement */
    hal_uart_print("[TEST 6/12] ECDH P-256 Key Agreement [GP12 (Pin 16)]\r\n");
    t0 = hal_cycle_count();
    if (test_ecdh()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] ECDH (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_ECDH_OK, 1); /* GP12 (Pin 16): ECDH OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] ECDH\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 7: ECDSA Sign & Verify */
    hal_uart_print("[TEST 7/12] ECDSA P-256 Sign & Verify [GP13 (Pin 17)]\r\n");
    t0 = hal_cycle_count();
    if (test_ecdsa()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] ECDSA (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_ECDSA_OK, 1); /* GP13 (Pin 17): ECDSA OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] ECDSA\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

    /* Test 8: HKDF Combiner */
    hal_uart_print("[TEST 8/12] HKDF-SHA-256 Combiner [GP14 (Pin 19)]\r\n");
    t0 = hal_cycle_count();
    if (test_hkdf()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] HKDF (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        hal_status_pin_set(QSAC_STATUS_PIN_HKDF_OK, 1); /* GP14 (Pin 19): HKDF OK */
        pass++;
    } else {
        hal_uart_print("[FAIL] HKDF\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }

#ifdef QSAC_PQC_ENABLED
#if QSAC_FEATURE_PQC_MLKEM
    /* Test 9: ML-KEM-512 */
    hal_uart_print("[TEST 9/12] ML-KEM-512 (FIPS 203 Encaps/Decaps Roundtrip)\r\n");
    t0 = hal_cycle_count();
    if (test_mlkem()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] ML-KEM-512 (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        pass++;
    } else {
        hal_uart_print("[FAIL] ML-KEM-512\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }
#endif

#if QSAC_FEATURE_PQC_MLDSA
    /* Test 10: ML-DSA-44 */
    hal_uart_print("[TEST 10/12] ML-DSA-44 (FIPS 204 Sign/Verify Roundtrip)\r\n");
    t0 = hal_cycle_count();
    if (test_mldsa()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] ML-DSA-44 (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        pass++;
    } else {
        hal_uart_print("[FAIL] ML-DSA-44\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }
#endif

#if QSAC_FEATURE_HYBRID_HANDSHAKE
    /* Test 11: Hybrid Handshake Roundtrip */
    hal_uart_print("[TEST 11/12] Hybrid Handshake Roundtrip (ECDH + ML-KEM-512 + ML-DSA-44 + HKDF)\r\n");
    t0 = hal_cycle_count();
    if (test_hybrid_handshake()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] Hybrid Handshake Protocol (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        pass++;
    } else {
        hal_uart_print("[FAIL] Hybrid Handshake Protocol\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }
#endif

#if QSAC_FEATURE_ACCESS_TOKENS
    /* Test 12: State Machine & Token Verification */
    hal_uart_print("[TEST 12/12] Access Control State Machine & ML-DSA Token Verification\r\n");
    t0 = hal_cycle_count();
    if (test_state_machine_and_tokens()) {
        uint32_t t1 = hal_cycle_count();
        hal_uart_printf("[PASS] State Machine & Tokens (%lu cycles)\r\n\r\n", (unsigned long)(t1 - t0));
        pass++;
    } else {
        hal_uart_print("[FAIL] State Machine & Tokens\r\n\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1);
        fail++;
    }
#endif
#endif

    /* Summary */
    hal_uart_print("------------------------------------------\r\n");
    hal_uart_printf("[RESULT] %d/%d tests passed", pass, pass + fail);
    if (fail == 0) {
        hal_uart_print(" ✓\r\n");
        hal_status_pin_set(QSAC_STATUS_PIN_SESSION_OK, 1); /* GP15: All checks nominal */
    } else {
        hal_uart_printf(", %d FAILED ✗\r\n", fail);
        hal_status_pin_set(QSAC_STATUS_PIN_ERROR, 1); /* GP16: Error */
    }
    hal_uart_print("------------------------------------------\r\n\r\n");

    if (fail > 0) {
        hal_uart_print("[HALT] Self-tests failed. Device halted.\r\n");
        hal_led_set(1);
        while (1) {}
    }

    hal_uart_print("[DONE] Phase 4 complete. Hybrid Handshake & Access Control State Machine nominal.\r\n");
    hal_uart_print("[STATUS PINS] GP6-GP15 (Physical Pins 9-20) asserted HIGH. GP4 (Pin 6) & GP5 (Pin 7) dedicated to I2C.\r\n");

#if QSAC_FEATURE_UART_GATEWAY
    hal_uart_print("[GATEWAY] Initializing Live Host UART Protocol Bridge...\r\n");
    qsac_uart_bridge_init();
    hal_uart_print("[GATEWAY] Listening for Host PC / Gateway commands over USB-UART...\r\n\r\n");
#else
    hal_uart_print("[CONFIG] UART Protocol Gateway feature disabled via switch.\r\n\r\n");
#endif

    /* Main loop: continuous polling for host frames + heartbeat */
    uint32_t last_heartbeat = hal_cycle_count();
    uint32_t heartbeat_interval_cycles = hal_get_sysclk_hz(); /* ~1 second */

    while (1) {
#if QSAC_FEATURE_UART_GATEWAY
        qsac_uart_bridge_poll();
#endif

        uint32_t now = hal_cycle_count();
        if (now - last_heartbeat >= heartbeat_interval_cycles) {
            last_heartbeat = now;
            hal_led_toggle();
        }

#ifdef QSAC_PLATFORM_HOST
        /* In host mode, exit after self-tests pass */
        hal_uart_print("[HOST] Exiting (host simulation complete).\r\n");
        return 0;
#endif
    }

    return 0;
}
