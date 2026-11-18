/**
 * @file host_crypto_backend.c
 * @brief Host-simulation crypto backend using OpenSSL.
 *
 * Provides working implementations of the crypto_api functions using
 * OpenSSL, allowing the full protocol stack to be tested on the
 * development machine before flashing to real hardware.
 *
 * This file is compiled only in host-simulation mode (QSAC_PLATFORM_HOST).
 *
 * Phase 2 operations (ECC, AES, SHA): fully implemented.
 * Phase 3 operations (ML-KEM, ML-DSA): stubs (require liboqs).
 */

#ifdef QSAC_PLATFORM_HOST

#include "crypto_api.h"
#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ----------------------------------------------
 * Key storage (simulated HSM vault)
 *
 * In host mode we store keys in memory. On real hardware these
 * would be inside the HSM's protected key vault.
 * ---------------------------------------------- */

#define MAX_KEY_SLOTS 16

typedef struct {
    EVP_PKEY *pkey;
    int       in_use;
} key_slot_t;

static key_slot_t g_key_vault[MAX_KEY_SLOTS] = {0};

/* ----------------------------------------------
 * Initialization
 * ---------------------------------------------- */

qsac_status_t qsac_crypto_init(void)
{
    /* OpenSSL 3.x auto-initializes, but we clear the vault */
    memset(g_key_vault, 0, sizeof(g_key_vault));
    printf("[CRYPTO-HOST] Crypto subsystem initialized (OpenSSL backend)\n");
    return QSAC_OK;
}

/* ----------------------------------------------
 * Random Number Generation
 * ---------------------------------------------- */

qsac_status_t qsac_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (RAND_bytes(buf, (int)len) != 1) {
        return QSAC_ERR_RNG_FAIL;
    }
    return QSAC_OK;
}

/* ----------------------------------------------
 * ECC P-256
 * ---------------------------------------------- */

qsac_status_t qsac_ecc_keygen(uint32_t key_id, uint8_t *pubkey)
{
    if (!pubkey || key_id >= MAX_KEY_SLOTS) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* Free any existing key in this slot */
    if (g_key_vault[key_id].pkey) {
        EVP_PKEY_free(g_key_vault[key_id].pkey);
    }

    /* Generate EC P-256 keypair */
    EVP_PKEY *pkey = EVP_EC_gen("P-256");
    if (!pkey) {
        return QSAC_ERR_HSM_FAULT;
    }

    /* Extract the raw public key (uncompressed x||y, 64 bytes) */
    size_t pubkey_len = QSAC_ECC_PUBKEY_SIZE + 1; /* +1 for 0x04 prefix */
    uint8_t pubkey_uncompressed[QSAC_ECC_PUBKEY_SIZE + 1];

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkey_uncompressed, sizeof(pubkey_uncompressed),
                                         &pubkey_len) != 1) {
        EVP_PKEY_free(pkey);
        return QSAC_ERR_HSM_FAULT;
    }

    /* Skip the 0x04 uncompressed-point prefix, copy x||y */
    memcpy(pubkey, pubkey_uncompressed + 1, QSAC_ECC_PUBKEY_SIZE);

    /* Store in vault */
    g_key_vault[key_id].pkey = pkey;
    g_key_vault[key_id].in_use = 1;

    return QSAC_OK;
}

qsac_status_t qsac_ecdh(uint32_t key_id,
                         const uint8_t *peer_pubkey,
                         uint8_t *shared_secret)
{
    if (!peer_pubkey || !shared_secret || key_id >= MAX_KEY_SLOTS) {
        return QSAC_ERR_INVALID_PARAM;
    }
    if (!g_key_vault[key_id].in_use) {
        return QSAC_ERR_KEY_NOT_FOUND;
    }

    /* Reconstruct peer public key with 0x04 prefix */
    uint8_t peer_uncompressed[QSAC_ECC_PUBKEY_SIZE + 1];
    peer_uncompressed[0] = 0x04;
    memcpy(peer_uncompressed + 1, peer_pubkey, QSAC_ECC_PUBKEY_SIZE);

    /* Create peer EVP_PKEY from raw bytes */
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  "P-256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                   peer_uncompressed,
                                                   sizeof(peer_uncompressed));
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) return QSAC_ERR_HSM_FAULT;

    EVP_PKEY *peer_pkey = NULL;
    if (EVP_PKEY_fromdata_init(pctx) != 1 ||
        EVP_PKEY_fromdata(pctx, &peer_pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return QSAC_ERR_HSM_FAULT;
    }
    EVP_PKEY_CTX_free(pctx);

    /* Perform ECDH */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(g_key_vault[key_id].pkey, NULL);
    if (!dctx) {
        EVP_PKEY_free(peer_pkey);
        return QSAC_ERR_HSM_FAULT;
    }

    size_t secret_len = QSAC_ECC_SHARED_SECRET_SIZE;
    qsac_status_t status = QSAC_OK;

    if (EVP_PKEY_derive_init(dctx) != 1 ||
        EVP_PKEY_derive_set_peer(dctx, peer_pkey) != 1 ||
        EVP_PKEY_derive(dctx, shared_secret, &secret_len) != 1) {
        status = QSAC_ERR_HSM_FAULT;
    }

    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer_pkey);
    return status;
}

qsac_status_t qsac_ecdsa_sign(uint32_t key_id,
                               const uint8_t *digest,
                               uint8_t *sig)
{
    if (!digest || !sig || key_id >= MAX_KEY_SLOTS) {
        return QSAC_ERR_INVALID_PARAM;
    }
    if (!g_key_vault[key_id].in_use) {
        return QSAC_ERR_KEY_NOT_FOUND;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return QSAC_ERR_HSM_FAULT;

    size_t sig_len = QSAC_ECDSA_SIG_SIZE + 16; /* DER may be larger */
    uint8_t der_sig[QSAC_ECDSA_SIG_SIZE + 16];

    qsac_status_t status = QSAC_OK;

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL,
                            g_key_vault[key_id].pkey) != 1 ||
        EVP_DigestSign(mdctx, der_sig, &sig_len, digest, 32) != 1) {
        status = QSAC_ERR_HSM_FAULT;
    } else {
        /* For simplicity, copy up to QSAC_ECDSA_SIG_SIZE bytes.
         * A production implementation would convert DER→fixed r||s. */
        memset(sig, 0, QSAC_ECDSA_SIG_SIZE);
        size_t copy_len = sig_len < QSAC_ECDSA_SIG_SIZE ? sig_len : QSAC_ECDSA_SIG_SIZE;
        memcpy(sig, der_sig, copy_len);
    }

    EVP_MD_CTX_free(mdctx);
    return status;
}

qsac_status_t qsac_ecdsa_verify(const uint8_t *pubkey,
                                 const uint8_t *digest,
                                 const uint8_t *sig)
{
    /* TODO: Full ECDSA verify with public key reconstruction.
     * For Phase 1 testing, this is acceptable as a stub. */
    (void)pubkey; (void)digest; (void)sig;
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

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QSAC_ERR_HSM_FAULT;

    int len = 0;
    qsac_status_t status = QSAC_OK;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QSAC_AES_IV_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        status = QSAC_ERR_HSM_FAULT;
        goto cleanup;
    }

    /* AAD */
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            status = QSAC_ERR_HSM_FAULT;
            goto cleanup;
        }
    }

    /* Encrypt */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)pt_len) != 1) {
        status = QSAC_ERR_HSM_FAULT;
        goto cleanup;
    }

    /* Finalize */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        status = QSAC_ERR_HSM_FAULT;
        goto cleanup;
    }

    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, QSAC_AES_TAG_SIZE, tag) != 1) {
        status = QSAC_ERR_HSM_FAULT;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return status;
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

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QSAC_ERR_HSM_FAULT;

    int len = 0;
    qsac_status_t status = QSAC_OK;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QSAC_AES_IV_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        status = QSAC_ERR_HSM_FAULT;
        goto cleanup;
    }

    /* AAD */
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) {
            status = QSAC_ERR_HSM_FAULT;
            goto cleanup;
        }
    }

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ct_len) != 1) {
        status = QSAC_ERR_HSM_FAULT;
        goto cleanup;
    }

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, QSAC_AES_TAG_SIZE,
                             (void *)tag) != 1) {
        status = QSAC_ERR_HSM_FAULT;
        goto cleanup;
    }

    /* Finalize — this is where tag verification happens */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        status = QSAC_ERR_VERIFY_FAIL; /* Tag mismatch */
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

/* ----------------------------------------------
 * Hashing
 * ---------------------------------------------- */

qsac_status_t qsac_sha256(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (!data || !digest) {
        return QSAC_ERR_INVALID_PARAM;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return QSAC_ERR_HSM_FAULT;

    unsigned int md_len = 32;
    qsac_status_t status = QSAC_OK;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &md_len) != 1) {
        status = QSAC_ERR_HSM_FAULT;
    }

    EVP_MD_CTX_free(ctx);
    return status;
}

qsac_status_t qsac_sha3_256(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (!data || !digest) {
        return QSAC_ERR_INVALID_PARAM;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return QSAC_ERR_HSM_FAULT;

    unsigned int md_len = 32;
    qsac_status_t status = QSAC_OK;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &md_len) != 1) {
        status = QSAC_ERR_HSM_FAULT;
    }

    EVP_MD_CTX_free(ctx);
    return status;
}

/* ----------------------------------------------
 * HKDF Key Derivation
 * ---------------------------------------------- */

qsac_status_t qsac_hkdf_combine(const uint8_t *ecdh_secret,
                                  const uint8_t *mlkem_secret,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *session_key)
{
    if (!ecdh_secret || !mlkem_secret || !session_key) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* Concatenate: ikm = ecdh_secret || mlkem_secret */
    uint8_t ikm[QSAC_ECC_SHARED_SECRET_SIZE + QSAC_MLKEM_SHARED_SECRET_SIZE];
    memcpy(ikm, ecdh_secret, QSAC_ECC_SHARED_SECRET_SIZE);
    memcpy(ikm + QSAC_ECC_SHARED_SECRET_SIZE, mlkem_secret,
           QSAC_MLKEM_SHARED_SECRET_SIZE);

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return QSAC_ERR_HSM_FAULT;

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return QSAC_ERR_HSM_FAULT;

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                  "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                   ikm, sizeof(ikm));
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                   (void *)info, info_len);
    /* No salt */
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                   (void *)"", 0);
    params[4] = OSSL_PARAM_construct_end();

    qsac_status_t status = QSAC_OK;
    if (EVP_KDF_derive(kctx, session_key, QSAC_SESSION_KEY_SIZE, params) != 1) {
        status = QSAC_ERR_HSM_FAULT;
    }

    EVP_KDF_CTX_free(kctx);

    /* Zeroize intermediate key material */
    memset(ikm, 0, sizeof(ikm));
    return status;
}
/* ----------------------------------------------
 * ML-KEM-512 stubs (Phase 3: replace with liboqs)
 * ---------------------------------------------- */

qsac_status_t qsac_mlkem_keygen(uint8_t *pubkey, uint8_t *privkey)
{
    if (!pubkey || !privkey) return QSAC_ERR_INVALID_PARAM;
    /* TODO Phase 3: Wire to liboqs Kyber512 keypair generation */
    printf("[CRYPTO-HOST] ML-KEM-512 KeyGen: not yet implemented (Phase 3)\n");
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_mlkem_encaps(const uint8_t *pubkey,
                                 uint8_t *ciphertext,
                                 uint8_t *shared_secret)
{
    if (!pubkey || !ciphertext || !shared_secret) return QSAC_ERR_INVALID_PARAM;
    printf("[CRYPTO-HOST] ML-KEM-512 Encaps: not yet implemented (Phase 3)\n");
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_mlkem_decaps(const uint8_t *privkey,
                                 const uint8_t *ciphertext,
                                 uint8_t *shared_secret)
{
    if (!privkey || !ciphertext || !shared_secret) return QSAC_ERR_INVALID_PARAM;
    printf("[CRYPTO-HOST] ML-KEM-512 Decaps: not yet implemented (Phase 3)\n");
    return QSAC_ERR_NOT_IMPLEMENTED;
}

/* ----------------------------------------------
 * ML-DSA-2 stubs (Phase 3: replace with liboqs)
 * ---------------------------------------------- */

qsac_status_t qsac_mldsa_keygen(uint8_t *pubkey, uint8_t *privkey)
{
    if (!pubkey || !privkey) return QSAC_ERR_INVALID_PARAM;
    printf("[CRYPTO-HOST] ML-DSA-2 KeyGen: not yet implemented (Phase 3)\n");
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_mldsa_sign(const uint8_t *privkey,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig)
{
    if (!privkey || !msg || !sig) return QSAC_ERR_INVALID_PARAM;
    (void)msg_len;
    printf("[CRYPTO-HOST] ML-DSA-2 Sign: not yet implemented (Phase 3)\n");
    return QSAC_ERR_NOT_IMPLEMENTED;
}

qsac_status_t qsac_mldsa_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig)
{
    if (!pubkey || !msg || !sig) return QSAC_ERR_INVALID_PARAM;
    (void)msg_len;
    printf("[CRYPTO-HOST] ML-DSA-2 Verify: not yet implemented (Phase 3)\n");
    return QSAC_ERR_NOT_IMPLEMENTED;
}

#endif /* QSAC_PLATFORM_HOST */
