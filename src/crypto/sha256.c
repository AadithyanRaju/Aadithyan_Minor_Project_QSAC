/**
 * @file sha256.c
 * @brief Portable pure-C SHA-256, HMAC-SHA-256, and HKDF-SHA-256 implementation.
 */

#include "sha256.h"
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sig0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sig1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(qsac_sha256_ctx_t *ctx, const uint8_t *data) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    for (int t = 0; t < 16; ++t) {
        W[t] = ((uint32_t)data[t * 4] << 24) |
               ((uint32_t)data[t * 4 + 1] << 16) |
               ((uint32_t)data[t * 4 + 2] << 8) |
               ((uint32_t)data[t * 4 + 3]);
    }

    for (int t = 16; t < 64; ++t) {
        W[t] = sig1(W[t - 2]) + W[t - 7] + sig0(W[t - 15]) + W[t - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int t = 0; t < 64; ++t) {
        T1 = h + SIG1(e) + CH(e, f, g) + K[t] + W[t];
        T2 = SIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void qsac_sha256_init(qsac_sha256_ctx_t *ctx) {
    if (!ctx) return;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void qsac_sha256_update(qsac_sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len == 0) return;

    size_t buffer_index = (size_t)(ctx->count % SHA256_BLOCK_SIZE);
    ctx->count += len;

    size_t part_len = SHA256_BLOCK_SIZE - buffer_index;
    size_t i = 0;

    if (len >= part_len) {
        memcpy(&ctx->buffer[buffer_index], data, part_len);
        sha256_transform(ctx, ctx->buffer);
        for (i = part_len; i + SHA256_BLOCK_SIZE <= len; i += SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, &data[i]);
        }
        buffer_index = 0;
    }

    if (i < len) {
        memcpy(&ctx->buffer[buffer_index], &data[i], len - i);
    }
}

void qsac_sha256_final(qsac_sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    if (!ctx || !digest) return;

    uint64_t total_bits = ctx->count * 8;
    size_t buffer_index = (size_t)(ctx->count % SHA256_BLOCK_SIZE);

    ctx->buffer[buffer_index++] = 0x80;

    if (buffer_index > 56) {
        memset(&ctx->buffer[buffer_index], 0, SHA256_BLOCK_SIZE - buffer_index);
        sha256_transform(ctx, ctx->buffer);
        buffer_index = 0;
    }

    memset(&ctx->buffer[buffer_index], 0, 56 - buffer_index);

    /* Big-endian 64-bit length */
    for (int i = 0; i < 8; ++i) {
        ctx->buffer[56 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }

    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; ++i) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void qsac_sha256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    qsac_sha256_ctx_t ctx;
    qsac_sha256_init(&ctx);
    qsac_sha256_update(&ctx, data, len);
    qsac_sha256_final(&ctx, digest);
}

void qsac_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[SHA256_DIGEST_SIZE]) {
    uint8_t k[SHA256_BLOCK_SIZE];
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];

    memset(k, 0, sizeof(k));
    if (key_len > SHA256_BLOCK_SIZE) {
        qsac_sha256_hash(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }

    qsac_sha256_ctx_t ctx;
    qsac_sha256_init(&ctx);
    qsac_sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    qsac_sha256_update(&ctx, data, data_len);
    qsac_sha256_final(&ctx, inner_hash);

    qsac_sha256_init(&ctx);
    qsac_sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    qsac_sha256_update(&ctx, inner_hash, SHA256_DIGEST_SIZE);
    qsac_sha256_final(&ctx, out);
}

void qsac_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *okm, size_t okm_len) {
    uint8_t default_salt[SHA256_DIGEST_SIZE] = {0};
    if (!salt || salt_len == 0) {
        salt = default_salt;
        salt_len = SHA256_DIGEST_SIZE;
    }

    /* Extract step: PRK = HMAC-SHA256(salt, IKM) */
    uint8_t prk[SHA256_DIGEST_SIZE];
    qsac_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* Expand step */
    size_t n = (okm_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    uint8_t t[SHA256_DIGEST_SIZE];
    size_t t_len = 0;
    size_t bytes_written = 0;

    for (size_t i = 1; i <= n; ++i) {
        qsac_sha256_ctx_t hmac_inner, hmac_outer;
        uint8_t k_ipad[SHA256_BLOCK_SIZE], k_opad[SHA256_BLOCK_SIZE];

        for (int j = 0; j < SHA256_BLOCK_SIZE; ++j) {
            uint8_t key_byte = (j < SHA256_DIGEST_SIZE) ? prk[j] : 0;
            k_ipad[j] = key_byte ^ 0x36;
            k_opad[j] = key_byte ^ 0x5c;
        }

        qsac_sha256_init(&hmac_inner);
        qsac_sha256_update(&hmac_inner, k_ipad, SHA256_BLOCK_SIZE);
        if (t_len > 0) {
            qsac_sha256_update(&hmac_inner, t, t_len);
        }
        if (info && info_len > 0) {
            qsac_sha256_update(&hmac_inner, info, info_len);
        }
        uint8_t c = (uint8_t)i;
        qsac_sha256_update(&hmac_inner, &c, 1);
        qsac_sha256_final(&hmac_inner, t);

        qsac_sha256_init(&hmac_outer);
        qsac_sha256_update(&hmac_outer, k_opad, SHA256_BLOCK_SIZE);
        qsac_sha256_update(&hmac_outer, t, SHA256_DIGEST_SIZE);
        qsac_sha256_final(&hmac_outer, t);
        t_len = SHA256_DIGEST_SIZE;

        size_t to_copy = (okm_len - bytes_written < SHA256_DIGEST_SIZE) ?
                         (okm_len - bytes_written) : SHA256_DIGEST_SIZE;
        memcpy(okm + bytes_written, t, to_copy);
        bytes_written += to_copy;
    }
}
