/**
 * @file crypto_api.h
 * @brief Unified cryptographic abstraction layer for QSAC.
 *
 * Provides a single API surface for both HSM-accelerated classical
 * crypto operations and software-executed PQC operations. Application
 * code calls these functions without needing to know whether the
 * underlying operation runs on the HSM hardware or in software.
 *
 * Backend selection is determined at compile time via the build
 * configuration (HSM_BACKEND and PQC_BACKEND defines).
 */

#ifndef QSAC_CRYPTO_API_H
#define QSAC_CRYPTO_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------
 * Return codes
 * ---------------------------------------------- */

typedef enum {
    QSAC_OK                  =  0,
    QSAC_ERR_INVALID_PARAM   = -1,
    QSAC_ERR_HSM_FAULT       = -2,
    QSAC_ERR_KEY_NOT_FOUND   = -3,
    QSAC_ERR_VERIFY_FAIL     = -4,
    QSAC_ERR_BUFFER_TOO_SMALL= -5,
    QSAC_ERR_RNG_FAIL        = -6,
    QSAC_ERR_NOT_IMPLEMENTED = -7,
    QSAC_ERR_REPLAY_DETECTED = -8,
    QSAC_ERR_INVALID_STATE   = -9,
} qsac_status_t;

/* ----------------------------------------------
 * Key / buffer size constants
 * ---------------------------------------------- */

/* ECC P-256 */
#define QSAC_ECC_PUBKEY_SIZE       64   /* uncompressed x||y, no 0x04 prefix */
#define QSAC_ECC_PRIVKEY_SIZE      32
#define QSAC_ECC_SHARED_SECRET_SIZE 32
#define QSAC_ECDSA_SIG_SIZE        64   /* r||s, fixed-length encoding */

/* ML-KEM-512 (FIPS 203) */
#define QSAC_MLKEM_PUBKEY_SIZE     800
#define QSAC_MLKEM_PRIVKEY_SIZE    1632
#define QSAC_MLKEM_CIPHERTEXT_SIZE 768
#define QSAC_MLKEM_SHARED_SECRET_SIZE 32

/* ML-DSA-2 / Dilithium2 (FIPS 204) */
#define QSAC_MLDSA_PUBKEY_SIZE     1312
#define QSAC_MLDSA_PRIVKEY_SIZE    2560
#define QSAC_MLDSA_SIG_SIZE        2420

/* SLH-DSA-128s / SPHINCS+-128s (FIPS 205) */
#define QSAC_SLHDSA_PUBKEY_SIZE    32
#define QSAC_SLHDSA_SIG_SIZE       7856

/* AES-256-GCM */
#define QSAC_AES_KEY_SIZE          32
#define QSAC_AES_IV_SIZE           12
#define QSAC_AES_TAG_SIZE          16

/* Session key (output of HKDF combiner) */
#define QSAC_SESSION_KEY_SIZE      32

/* ----------------------------------------------
 * Initialization
 * ---------------------------------------------- */

/**
 * @brief Initialize all crypto backends (HSM + PQC).
 *        Must be called once before any other crypto_api function.
 */
qsac_status_t qsac_crypto_init(void);

/* ----------------------------------------------
 * Random number generation
 * ---------------------------------------------- */

/**
 * @brief Fill buffer with cryptographically secure random bytes from the HW TRNG.
 */
qsac_status_t qsac_random_bytes(uint8_t *buf, size_t len);

/* ----------------------------------------------
 * ECC P-256 (HSM-accelerated)
 * ---------------------------------------------- */

/**
 * @brief Generate an ECC P-256 keypair inside the HSM key vault.
 * @param key_id  HSM slot identifier for the generated key.
 * @param pubkey  Output buffer for the public key (QSAC_ECC_PUBKEY_SIZE bytes).
 */
qsac_status_t qsac_ecc_keygen(uint32_t key_id, uint8_t *pubkey);

/**
 * @brief Perform ECDH P-256 key agreement.
 * @param key_id          HSM slot holding the device private key.
 * @param peer_pubkey     Peer's public key (QSAC_ECC_PUBKEY_SIZE bytes).
 * @param shared_secret   Output buffer (QSAC_ECC_SHARED_SECRET_SIZE bytes).
 */
qsac_status_t qsac_ecdh(uint32_t key_id,
                         const uint8_t *peer_pubkey,
                         uint8_t *shared_secret);

/**
 * @brief Sign a message digest with ECDSA P-256.
 * @param key_id    HSM slot holding the signing key.
 * @param digest    SHA-256 digest to sign (32 bytes).
 * @param sig       Output signature buffer (QSAC_ECDSA_SIG_SIZE bytes).
 */
qsac_status_t qsac_ecdsa_sign(uint32_t key_id,
                               const uint8_t *digest,
                               uint8_t *sig);

/**
 * @brief Verify an ECDSA P-256 signature.
 * @param pubkey    Signer's public key (QSAC_ECC_PUBKEY_SIZE bytes).
 * @param digest    SHA-256 digest (32 bytes).
 * @param sig       Signature to verify (QSAC_ECDSA_SIG_SIZE bytes).
 */
qsac_status_t qsac_ecdsa_verify(const uint8_t *pubkey,
                                 const uint8_t *digest,
                                 const uint8_t *sig);

/* ----------------------------------------------
 * ML-KEM-512 (Software / PQC backend)
 * ---------------------------------------------- */

/**
 * @brief Generate an ML-KEM-512 keypair.
 * @param pubkey   Output public key (QSAC_MLKEM_PUBKEY_SIZE bytes).
 * @param privkey  Output private key (QSAC_MLKEM_PRIVKEY_SIZE bytes).
 */
qsac_status_t qsac_mlkem_keygen(uint8_t *pubkey, uint8_t *privkey);

/**
 * @brief Encapsulate: produce a ciphertext and shared secret from a public key.
 * @param pubkey         Recipient's public key.
 * @param ciphertext     Output ciphertext (QSAC_MLKEM_CIPHERTEXT_SIZE bytes).
 * @param shared_secret  Output shared secret (QSAC_MLKEM_SHARED_SECRET_SIZE bytes).
 */
qsac_status_t qsac_mlkem_encaps(const uint8_t *pubkey,
                                 uint8_t *ciphertext,
                                 uint8_t *shared_secret);

/**
 * @brief Decapsulate: recover the shared secret from a ciphertext.
 * @param privkey        Recipient's private key.
 * @param ciphertext     Ciphertext (QSAC_MLKEM_CIPHERTEXT_SIZE bytes).
 * @param shared_secret  Output shared secret (QSAC_MLKEM_SHARED_SECRET_SIZE bytes).
 */
qsac_status_t qsac_mlkem_decaps(const uint8_t *privkey,
                                 const uint8_t *ciphertext,
                                 uint8_t *shared_secret);

/* ----------------------------------------------
 * ML-DSA-2 / Dilithium2 (Software / PQC backend)
 * ---------------------------------------------- */

/**
 * @brief Generate an ML-DSA-2 keypair.
 * @param pubkey   Output public key (QSAC_MLDSA_PUBKEY_SIZE bytes).
 * @param privkey  Output private key (QSAC_MLDSA_PRIVKEY_SIZE bytes).
 */
qsac_status_t qsac_mldsa_keygen(uint8_t *pubkey, uint8_t *privkey);

/**
 * @brief Sign a message with ML-DSA-2.
 * @param privkey  Signing private key.
 * @param msg      Message to sign.
 * @param msg_len  Length of message.
 * @param sig      Output signature (QSAC_MLDSA_SIG_SIZE bytes).
 */
qsac_status_t qsac_mldsa_sign(const uint8_t *privkey,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig);

/**
 * @brief Verify an ML-DSA-2 signature.
 * @param pubkey   Signer's public key.
 * @param msg      Original message.
 * @param msg_len  Length of message.
 * @param sig      Signature to verify (QSAC_MLDSA_SIG_SIZE bytes).
 * @return QSAC_OK if valid, QSAC_ERR_VERIFY_FAIL if invalid.
 */
qsac_status_t qsac_mldsa_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig);

/* ----------------------------------------------
 * AES-256-GCM (HSM-accelerated)
 * ---------------------------------------------- */

/**
 * @brief Encrypt with AES-256-GCM.
 * @param key         Encryption key (QSAC_AES_KEY_SIZE bytes).
 * @param iv          Initialization vector (QSAC_AES_IV_SIZE bytes).
 * @param aad         Additional authenticated data (may be NULL).
 * @param aad_len     Length of AAD.
 * @param plaintext   Input plaintext.
 * @param pt_len      Length of plaintext.
 * @param ciphertext  Output ciphertext (same length as plaintext).
 * @param tag         Output authentication tag (QSAC_AES_TAG_SIZE bytes).
 */
qsac_status_t qsac_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *plaintext, size_t pt_len,
                                     uint8_t *ciphertext, uint8_t *tag);

/**
 * @brief Decrypt with AES-256-GCM.
 * @param key         Decryption key.
 * @param iv          Initialization vector.
 * @param aad         Additional authenticated data (may be NULL).
 * @param aad_len     Length of AAD.
 * @param ciphertext  Input ciphertext.
 * @param ct_len      Length of ciphertext.
 * @param tag         Authentication tag to verify.
 * @param plaintext   Output plaintext (same length as ciphertext).
 * @return QSAC_ERR_VERIFY_FAIL if tag verification fails.
 */
qsac_status_t qsac_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ct_len,
                                     const uint8_t *tag,
                                     uint8_t *plaintext);

/* ----------------------------------------------
 * Hashing (HSM-accelerated where available)
 * ---------------------------------------------- */

/**
 * @brief Compute SHA-256 hash.
 */
qsac_status_t qsac_sha256(const uint8_t *data, size_t len, uint8_t *digest);

/**
 * @brief Compute SHA-3-256 hash.
 */
qsac_status_t qsac_sha3_256(const uint8_t *data, size_t len, uint8_t *digest);

/* ----------------------------------------------
 * Key Derivation (HKDF-SHA-256)
 * ---------------------------------------------- */

/**
 * @brief Derive a session key from combined ECDH + ML-KEM shared secrets.
 *
 * Concatenates the two input key materials and runs HKDF-SHA-256 to
 * produce a single session key. This is the core combiner for the
 * hybrid key establishment protocol (Section IV-A of the paper).
 *
 * @param ecdh_secret    ECDH shared secret (QSAC_ECC_SHARED_SECRET_SIZE bytes).
 * @param mlkem_secret   ML-KEM shared secret (QSAC_MLKEM_SHARED_SECRET_SIZE bytes).
 * @param info           Context info string for HKDF (e.g., "QSAC session key").
 * @param info_len       Length of info string.
 * @param session_key    Output session key (QSAC_SESSION_KEY_SIZE bytes).
 */
qsac_status_t qsac_hkdf_combine(const uint8_t *ecdh_secret,
                                  const uint8_t *mlkem_secret,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *session_key);

#ifdef __cplusplus
}
#endif

#endif /* QSAC_CRYPTO_API_H */
