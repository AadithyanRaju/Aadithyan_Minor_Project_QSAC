/**
 * @file fips202.h
 * @brief FIPS 202 Keccak-based hashing and extendable output functions (SHAKE/SHA-3).
 */

#ifndef QSAC_FIPS202_H
#define QSAC_FIPS202_H

#include <stdint.h>
#include <stddef.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
    uint64_t s[25];
    size_t pos;
} shake128incctx;

typedef struct {
    uint64_t s[25];
    size_t pos;
} shake256incctx;

typedef struct {
    uint64_t s[25];
    size_t pos;
} shake128ctx;

typedef struct {
    uint64_t s[25];
    size_t pos;
} shake256ctx;

/* Incremental SHAKE128 */
void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);

/* Incremental SHAKE256 */
void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);

/* Block-based SHAKE128 */
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen);
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);

/* Block-based SHAKE256 */
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen);
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);

/* One-shot SHAKE */
void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

/* One-shot SHA3 */
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);

#endif /* QSAC_FIPS202_H */
