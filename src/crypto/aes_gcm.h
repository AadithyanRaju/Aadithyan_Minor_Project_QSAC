/**
 * @file aes_gcm.h
 * @brief Standalone AES-256-GCM AEAD encryption and decryption implementation.
 */

#ifndef QSAC_AES_GCM_H
#define QSAC_AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_BLOCK_SIZE  16

int qsac_aes256_gcm_encrypt(const uint8_t *key,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext,
                            uint8_t *tag);

int qsac_aes256_gcm_decrypt(const uint8_t *key,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *tag,
                            uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* QSAC_AES_GCM_H */
