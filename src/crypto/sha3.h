/**
 * @file sha3.h
 * @brief Standalone FIPS 202 SHA-3-256 implementation.
 */

#ifndef QSAC_SHA3_H
#define QSAC_SHA3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA3_256_DIGEST_SIZE 32
#define SHA3_256_RATE        136

typedef struct {
    uint64_t state[25];
    uint8_t  buffer[SHA3_256_RATE];
    size_t   buf_len;
} qsac_sha3_256_ctx_t;

void qsac_sha3_256_init(qsac_sha3_256_ctx_t *ctx);
void qsac_sha3_256_update(qsac_sha3_256_ctx_t *ctx, const uint8_t *data, size_t len);
void qsac_sha3_256_final(qsac_sha3_256_ctx_t *ctx, uint8_t digest[SHA3_256_DIGEST_SIZE]);

void qsac_sha3_256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* QSAC_SHA3_H */
