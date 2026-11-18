/**
 * @file pico_crypto_backend.c
 * @brief Software crypto backend for the Raspberry Pi Pico (RP2040).
 *
 * The RP2040 has NO hardware crypto engine and NO HSM/secure enclave.
 * All cryptographic operations run in software on the Cortex-M0+ core.
 *
 * Phase 2 Implementation:
 *   - RNG via RP2040 ring oscillator (ROSC)
 *   - Software ECC P-256 via micro-ecc (ECDH, ECDSA)
 *   - Software AES-256-GCM AEAD
 *   - Software SHA-256, HMAC-SHA-256, and HKDF-SHA-256
 *   - Software SHA-3-256 (FIPS 202)
 *   - Key isolation simulated via software-managed SRAM key vault
 *
 * Phase 3 PQC (ML-KEM-512, ML-DSA-2) remains stubbed until Phase 3.
 */

#ifdef QSAC_PLATFORM_PICO

#include "qsac_features.h"
#include "crypto_api.h"
#include "sha256.h"
#include "sha3.h"
#include "aes_gcm.h"
#include "uECC.h"
#include "atecc608b.h"

#include "pico/stdlib.h"
#include "hardware/structs/rosc.h"

#include <string.h>
#include <stdio.h>

static bool g_atecc_active = false;

/* ----------------------------------------------
 * Key Vault (Simulated HSM on SRAM / Hardware Slot Mirror)
 * ---------------------------------------------- */

#define MAX_KEY_SLOTS 32

typedef struct {
    uint8_t privkey[QSAC_ECC_PRIVKEY_SIZE];
    uint8_t pubkey[QSAC_ECC_PUBKEY_SIZE];
    int     in_use;
    int     hw_slot; /* 1 if stored directly in ATECC608B slot */
} pico_key_slot_t;

static pico_key_slot_t g_key_vault[MAX_KEY_SLOTS] = {0};

/* ----------------------------------------------
 * Random Number Generation
 * ---------------------------------------------- */

static uint8_t rosc_random_byte(void)
{
    uint8_t byte = 0;
    for (int i = 0; i < 8; i++) {
        /* Read the ROSC RANDOMBIT register */
        uint32_t bit = rosc_hw->randombit & 1;
        byte = (byte << 1) | (uint8_t)bit;
        /* Small delay for entropy accumulation */
        for (volatile int j = 0; j < 10; j++) {}
    }
    return byte;
}

qsac_status_t qsac_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (g_atecc_active) {
        size_t offset = 0;
        uint8_t rand32[ATECC_RANDOM_SIZE];
        while (offset < len) {
            if (atecc608b_random(rand32) == 0) {
                size_t chunk = (len - offset < ATECC_RANDOM_SIZE) ? (len - offset) : ATECC_RANDOM_SIZE;
                memcpy(&buf[offset], rand32, chunk);
                offset += chunk;
            } else {
                /* Hardware TRNG read failed, fallback to ROSC for remainder */
                break;
            }
        }
        if (offset == len) {
            return QSAC_OK;
        }
        /* Fill remainder with ROSC */
        for (size_t i = offset; i < len; i++) {
            buf[i] = rosc_random_byte();
        }
        return QSAC_OK;
    }

    for (size_t i = 0; i < len; i++) {
        buf[i] = rosc_random_byte();
    }
    return QSAC_OK;
}

static int pico_uecc_rng(uint8_t *dest, unsigned size)
{
    return (qsac_random_bytes(dest, (size_t)size) == QSAC_OK) ? 1 : 0;
}

/* ----------------------------------------------
 * Initialization
 * ---------------------------------------------- */

qsac_status_t qsac_crypto_init(void)
{
    memset(g_key_vault, 0, sizeof(g_key_vault));
    uECC_set_rng(&pico_uecc_rng);

#if QSAC_FEATURE_ATECC608B
    /* Probe and initialize ATECC608B Cryptographic Co-Processor */
    atecc608b_info_t info;
    if (atecc608b_init(&info) == 0 && info.present) {
        g_atecc_active = true;
        printf("[CRYPTO-PICO] ATECC608B HSM active (Hardware TRNG, Key Vault, ECC P-256, Revision: 0x%08lX)\n",
               (unsigned long)info.revision);
    } else {
        g_atecc_active = false;
        printf("[CRYPTO-PICO] ATECC608B not detected; operating in software emulation (micro-ecc, ROSC)\n");
    }
#else
    g_atecc_active = false;
    printf("[CRYPTO-PICO] ATECC608B feature switch DISABLED; operating in software emulation\n");
#endif

    return QSAC_OK;
}

/* ----------------------------------------------
 * ECC P-256 (ATECC608B Hardware + micro-ecc Fallback)
 * ---------------------------------------------- */

qsac_status_t qsac_ecc_keygen(uint32_t key_id, uint8_t *pubkey)
{
    if (!pubkey || key_id >= MAX_KEY_SLOTS) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (g_atecc_active && key_id < 16) {
        /* Attempt hardware key generation in ATECC608B slot */
        if (atecc608b_genkey((uint16_t)key_id, pubkey) == 0) {
            memcpy(g_key_vault[key_id].pubkey, pubkey, QSAC_ECC_PUBKEY_SIZE);
            g_key_vault[key_id].in_use = 1;
            g_key_vault[key_id].hw_slot = 1;
            return QSAC_OK;
        }
    }

    /* Software keygen via micro-ecc */
    if (!uECC_make_key(g_key_vault[key_id].pubkey,
                       g_key_vault[key_id].privkey,
                       uECC_secp256r1())) {
        return QSAC_ERR_HSM_FAULT;
    }

    memcpy(pubkey, g_key_vault[key_id].pubkey, QSAC_ECC_PUBKEY_SIZE);
    g_key_vault[key_id].in_use = 1;
    g_key_vault[key_id].hw_slot = 0;
    return QSAC_OK;
}

qsac_status_t qsac_ecdh(uint32_t key_id, const uint8_t *peer_pubkey,
                         uint8_t *shared_secret)
{
    if (!peer_pubkey || !shared_secret || key_id >= MAX_KEY_SLOTS) {
        return QSAC_ERR_INVALID_PARAM;
    }
    if (!g_key_vault[key_id].in_use) {
        return QSAC_ERR_KEY_NOT_FOUND;
    }

    if (g_atecc_active && g_key_vault[key_id].hw_slot && key_id < 16) {
        if (atecc608b_ecdh((uint16_t)key_id, peer_pubkey, shared_secret) == 0) {
            return QSAC_OK;
        }
    }

    if (!uECC_shared_secret(peer_pubkey,
                            g_key_vault[key_id].privkey,
                            shared_secret,
                            uECC_secp256r1())) {
        return QSAC_ERR_HSM_FAULT;
    }

    return QSAC_OK;
}

qsac_status_t qsac_ecdsa_sign(uint32_t key_id, const uint8_t *digest,
                               uint8_t *sig)
{
    if (!digest || !sig || key_id >= MAX_KEY_SLOTS) {
        return QSAC_ERR_INVALID_PARAM;
    }
    if (!g_key_vault[key_id].in_use) {
        return QSAC_ERR_KEY_NOT_FOUND;
    }

    if (g_atecc_active && g_key_vault[key_id].hw_slot && key_id < 16) {
        if (atecc608b_sign((uint16_t)key_id, digest, sig) == 0) {
            return QSAC_OK;
        }
    }

    if (!uECC_sign(g_key_vault[key_id].privkey,
                   digest,
                   32,
                   sig,
                   uECC_secp256r1())) {
        return QSAC_ERR_HSM_FAULT;
    }

    return QSAC_OK;
}

qsac_status_t qsac_ecdsa_verify(const uint8_t *pubkey, const uint8_t *digest,
                                 const uint8_t *sig)
{
    if (!pubkey || !digest || !sig) {
        return QSAC_ERR_INVALID_PARAM;
    }

    if (g_atecc_active) {
        if (atecc608b_verify(pubkey, digest, sig) == 0) {
            return QSAC_OK;
        }
    }

    if (!uECC_verify(pubkey,
                     digest,
                     32,
                     sig,
                     uECC_secp256r1())) {
        return QSAC_ERR_VERIFY_FAIL;
    }

    return QSAC_OK;
}

/* ----------------------------------------------
 * AES-256-GCM (Software)
 * ---------------------------------------------- */

qsac_status_t qsac_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *plaintext, size_t pt_len,
                                     uint8_t *ciphertext, uint8_t *tag)
{
    if (!key || !iv || (!plaintext && pt_len > 0) ||
        (!ciphertext && pt_len > 0) || !tag) {
        return QSAC_ERR_INVALID_PARAM;
    }

    int ret = qsac_aes256_gcm_encrypt(key, iv, QSAC_AES_IV_SIZE,
                                      aad, aad_len,
                                      plaintext, pt_len,
                                      ciphertext, tag);
    if (ret != 0) {
        return QSAC_ERR_HSM_FAULT;
    }

    return QSAC_OK;
}

qsac_status_t qsac_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ct_len,
                                     const uint8_t *tag, uint8_t *plaintext)
{
    if (!key || !iv || (!ciphertext && ct_len > 0) ||
        !tag || (!plaintext && ct_len > 0)) {
        return QSAC_ERR_INVALID_PARAM;
    }

    int ret = qsac_aes256_gcm_decrypt(key, iv, QSAC_AES_IV_SIZE,
                                      aad, aad_len,
                                      ciphertext, ct_len,
                                      tag, plaintext);
    if (ret == -2) {
        return QSAC_ERR_VERIFY_FAIL;
    }
    if (ret != 0) {
        return QSAC_ERR_HSM_FAULT;
    }

    return QSAC_OK;
}

/* ----------------------------------------------
 * Hashing
 * ---------------------------------------------- */

qsac_status_t qsac_sha256(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (!data || !digest) {
        return QSAC_ERR_INVALID_PARAM;
    }

    qsac_sha256_hash(data, len, digest);
    return QSAC_OK;
}

qsac_status_t qsac_sha3_256(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (!data || !digest) {
        return QSAC_ERR_INVALID_PARAM;
    }

    qsac_sha3_256_hash(data, len, digest);
    return QSAC_OK;
}

/* ----------------------------------------------
 * HKDF-SHA-256
 * ---------------------------------------------- */

qsac_status_t qsac_hkdf_combine(const uint8_t *ecdh_secret,
                                  const uint8_t *mlkem_secret,
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *session_key)
{
    if (!ecdh_secret || !mlkem_secret || !session_key) {
        return QSAC_ERR_INVALID_PARAM;
    }

    /* Concatenate: IKM = ecdh_secret || mlkem_secret (64 bytes) */
    uint8_t ikm[QSAC_ECC_SHARED_SECRET_SIZE + QSAC_MLKEM_SHARED_SECRET_SIZE];
    memcpy(ikm, ecdh_secret, QSAC_ECC_SHARED_SECRET_SIZE);
    memcpy(ikm + QSAC_ECC_SHARED_SECRET_SIZE, mlkem_secret, QSAC_MLKEM_SHARED_SECRET_SIZE);

    qsac_hkdf_sha256(NULL, 0, ikm, sizeof(ikm), info, info_len, session_key, QSAC_SESSION_KEY_SIZE);
    return QSAC_OK;
}

#endif /* QSAC_PLATFORM_PICO */
