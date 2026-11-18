/**
 * @file hsm_backend.c
 * @brief HSM/secure-enclave backend for classical cryptographic operations.
 *
 * Implements the HSM-accelerated portion of the crypto_api:
 *   - ECC P-256 (ECDH, ECDSA) via PKA hardware
 *   - AES-256-GCM via CRYP hardware engine
 *   - SHA-256 / SHA-3 via HASH hardware engine
 *   - TRNG-based random number generation
 *
 * This file contains stubs that will be filled in during Phase 2
 * with vendor-specific HAL calls (e.g., STM32 PKA/CRYP/HASH HAL).
 *
 * All private keys are generated and stored within the HSM key vault;
 * they are never exposed to application-level RAM.
 */

#include "crypto_api.h"

/* ----------------------------------------------
 * Initialization
 * ---------------------------------------------- */

qsac_status_t qsac_crypto_init(void)
{
    /* TODO Phase 1: Initialize HSM peripherals (PKA, CRYP, HASH, RNG).
     * - Enable peripheral clocks
     * - Configure TrustZone secure/non-secure partitioning if applicable
     * - Self-test the RNG
     */
    return QSAC_ERR_NOT_IMPLEMENTED;
}

/* ----------------------------------------------
 * Random Number Generation
 * ---------------------------------------------- */

qsac_status_t qsac_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 1: Read from hardware TRNG.
     * Example for STM32:
     *   HAL_RNG_GenerateRandomNumber(&hrng, &random32);
     *   Fill buf in 4-byte chunks.
     */
    (void)buf;
    (void)len;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

/* ----------------------------------------------
 * ECC P-256
 * ---------------------------------------------- */

qsac_status_t qsac_ecc_keygen(uint32_t key_id, uint8_t *pubkey)
{
    if (!pubkey) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: Generate ECC P-256 keypair in HSM key vault.
     * - Private key stored in HSM slot `key_id`, never exported
     * - Public key (uncompressed x||y) written to `pubkey`
     */
    (void)key_id;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_ecdh(uint32_t key_id,
                         const uint8_t *peer_pubkey,
                         uint8_t *shared_secret)
{
    if (!peer_pubkey || !shared_secret) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: ECDH key agreement using HSM PKA.
     * - Use private key from HSM slot `key_id`
     * - Compute shared point, output x-coordinate to `shared_secret`
     */
    (void)key_id;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_ecdsa_sign(uint32_t key_id,
                               const uint8_t *digest,
                               uint8_t *sig)
{
    if (!digest || !sig) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: ECDSA P-256 sign using HSM PKA.
     * - Sign the 32-byte digest using private key from slot `key_id`
     * - Output fixed-length r||s to `sig`
     */
    (void)key_id;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_ecdsa_verify(const uint8_t *pubkey,
                                 const uint8_t *digest,
                                 const uint8_t *sig)
{
    if (!pubkey || !digest || !sig) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: ECDSA P-256 verify using HSM PKA.
     * - Verify signature `sig` over `digest` against `pubkey`
     * - Return QSAC_OK if valid, QSAC_ERR_VERIFY_FAIL if invalid
     */
    return QSAC_ERR_NOT_IMPLEMENTED;
}

/* ----------------------------------------------
 * AES-256-GCM
 * ---------------------------------------------- */

qsac_status_t qsac_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *plaintext, size_t pt_len,
                                     uint8_t *ciphertext, uint8_t *tag)
{
    if (!key || !iv || !plaintext || !ciphertext || !tag) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: AES-256-GCM encrypt using CRYP hardware engine.
     * Example for STM32:
     *   HAL_CRYP_Encrypt(&hcryp, plaintext, pt_len, ciphertext, timeout);
     */
    (void)aad; (void)aad_len; (void)pt_len;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ct_len,
                                     const uint8_t *tag,
                                     uint8_t *plaintext)
{
    if (!key || !iv || !ciphertext || !tag || !plaintext) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: AES-256-GCM decrypt + tag verification using CRYP HW. */
    (void)aad; (void)aad_len; (void)ct_len;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

/* ----------------------------------------------
 * Hashing
 * ---------------------------------------------- */

qsac_status_t qsac_sha256(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (!data || !digest) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: SHA-256 via HASH hardware engine. */
    (void)len;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_sha3_256(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (!data || !digest) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 2: SHA-3-256 via HASH engine (if supported) or software. */
    (void)len;
    return QSAC_ERR_NOT_IMPLEMENTED;
}

/* ----------------------------------------------
 * Key Derivation
 * ---------------------------------------------- */

qsac_status_t qsac_hkdf_combine(const uint8_t *ecdh_secret,
                                  const uint8_t *mlkem_secret,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *session_key)
{
    if (!ecdh_secret || !mlkem_secret || !session_key) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* TODO Phase 4: HKDF-SHA-256 combiner.
     * ikm = ecdh_secret || mlkem_secret  (64 bytes total)
     * salt = empty (or a nonce)
     * info = provided context string
     * output = session_key (32 bytes)
     */
    (void)info; (void)info_len;
    return QSAC_ERR_NOT_IMPLEMENTED;
}
