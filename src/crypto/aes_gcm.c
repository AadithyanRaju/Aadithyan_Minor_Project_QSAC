/**
 * @file aes_gcm.c
 * @brief Portable pure-C AES-256-GCM AEAD implementation conforming to NIST SP 800-38D.
 */

#include "aes_gcm.h"
#include <string.h>
#include "tiny_aes.h"

/* ----------------------------------------------
 * GHASH Core (Galois Field GF(2^128) Multiplication)
 * ---------------------------------------------- */

static void ghash_mult(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t v[16];
    uint8_t z[16] = {0};
    memcpy(v, y, 16);

    for (int i = 0; i < 128; ++i) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if ((x[byte_idx] >> bit_idx) & 1) {
            for (int j = 0; j < 16; ++j) {
                z[j] ^= v[j];
            }
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; --j) {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xe1;
        }
    }
    memcpy(out, z, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len) {
    size_t blocks = len / 16;
    for (size_t b = 0; b < blocks; ++b) {
        for (int i = 0; i < 16; ++i) {
            y[i] ^= data[b * 16 + i];
        }
        ghash_mult(y, h, y);
    }
    size_t rem = len % 16;
    if (rem > 0) {
        for (size_t i = 0; i < rem; ++i) {
            y[i] ^= data[blocks * 16 + i];
        }
        ghash_mult(y, h, y);
    }
}

/* ----------------------------------------------
 * GCM Mode
 * ---------------------------------------------- */

static void inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++block[i] != 0) break;
    }
}

int qsac_aes256_gcm_encrypt(const uint8_t *key,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext,
                            uint8_t *tag) {
    if (!key || !iv || iv_len != 12 || (!plaintext && pt_len > 0) ||
        (!ciphertext && pt_len > 0) || !tag) {
        return -1;
    }

    struct AES_ctx aes;
    AES_init_ctx(&aes, key);

    /* H = AES_K(0^128) */
    uint8_t H[16] = {0};
    AES_ECB_encrypt(&aes, H);

    /* J0 = IV || 0^31 || 1 */
    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    /* CTR Mode Encryption starting at J0 + 1 */
    uint8_t CB[16];
    memcpy(CB, J0, 16);

    uint8_t stream[16];
    size_t offset = 0;
    while (offset < pt_len) {
        inc32(CB);
        memcpy(stream, CB, 16);
        AES_ECB_encrypt(&aes, stream);
        size_t chunk = (pt_len - offset < 16) ? (pt_len - offset) : 16;
        for (size_t i = 0; i < chunk; ++i) {
            ciphertext[offset + i] = plaintext[offset + i] ^ stream[i];
        }
        offset += chunk;
    }

    /* GHASH over AAD and Ciphertext */
    uint8_t S[16] = {0};
    if (aad && aad_len > 0) {
        ghash_update(S, H, aad, aad_len);
    }
    if (ciphertext && pt_len > 0) {
        ghash_update(S, H, ciphertext, pt_len);
    }

    /* Append bit lengths [len(A)]64 || [len(C)]64 */
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t pt_bits  = (uint64_t)pt_len * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i]     = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[8 + i] = (uint8_t)(pt_bits >> (56 - i * 8));
    }
    ghash_update(S, H, len_block, 16);

    /* Tag = S ^ AES_K(J0) */
    uint8_t enc_J0[16];
    memcpy(enc_J0, J0, 16);
    AES_ECB_encrypt(&aes, enc_J0);
    for (int i = 0; i < 16; ++i) {
        tag[i] = S[i] ^ enc_J0[i];
    }

    return 0;
}

int qsac_aes256_gcm_decrypt(const uint8_t *key,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *tag,
                            uint8_t *plaintext) {
    if (!key || !iv || iv_len != 12 || (!ciphertext && ct_len > 0) ||
        !tag || (!plaintext && ct_len > 0)) {
        return -1;
    }

    struct AES_ctx aes;
    AES_init_ctx(&aes, key);

    /* H = AES_K(0^128) */
    uint8_t H[16] = {0};
    AES_ECB_encrypt(&aes, H);

    /* J0 = IV || 0^31 || 1 */
    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    /* Compute expected GHASH tag over AAD and Ciphertext */
    uint8_t S[16] = {0};
    if (aad && aad_len > 0) {
        ghash_update(S, H, aad, aad_len);
    }
    if (ciphertext && ct_len > 0) {
        ghash_update(S, H, ciphertext, ct_len);
    }

    /* Append bit lengths */
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i]     = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[8 + i] = (uint8_t)(ct_bits >> (56 - i * 8));
    }
    ghash_update(S, H, len_block, 16);

    /* Expected Tag = S ^ AES_K(J0) */
    uint8_t enc_J0[16];
    memcpy(enc_J0, J0, 16);
    AES_ECB_encrypt(&aes, enc_J0);
    uint8_t expected_tag[16];
    for (int i = 0; i < 16; ++i) {
        expected_tag[i] = S[i] ^ enc_J0[i];
    }

    /* Constant-time tag check */
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (expected_tag[i] ^ tag[i]);
    }
    if (diff != 0) {
        return -2; /* Tag verification failed */
    }

    /* Decrypt CTR */
    uint8_t CB[16];
    memcpy(CB, J0, 16);

    uint8_t stream[16];
    size_t offset = 0;
    while (offset < ct_len) {
        inc32(CB);
        memcpy(stream, CB, 16);
        AES_ECB_encrypt(&aes, stream);
        size_t chunk = (ct_len - offset < 16) ? (ct_len - offset) : 16;
        for (size_t i = 0; i < chunk; ++i) {
            plaintext[offset + i] = ciphertext[offset + i] ^ stream[i];
        }
        offset += chunk;
    }

    return 0;
}
