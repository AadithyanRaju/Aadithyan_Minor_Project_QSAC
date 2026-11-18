/**
 * @file sha256.h
 * @brief Standalone SHA-256, HMAC-SHA-256, and HKDF-SHA-256 implementation.
 */

#ifndef QSAC_SHA256_H
#define QSAC_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[SHA256_BLOCK_SIZE];
} qsac_sha256_ctx_t;

void qsac_sha256_init(qsac_sha256_ctx_t *ctx);
void qsac_sha256_update(qsac_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void qsac_sha256_final(qsac_sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);

void qsac_sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]);

void qsac_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[SHA256_DIGEST_SIZE]);

void qsac_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* QSAC_SHA256_H */
