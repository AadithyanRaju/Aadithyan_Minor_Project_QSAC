/**
 * @file BENCHMARKS_runner.c
 * @brief High-precision hardware benchmarking and stack profiling suite for QSAC.
 */

#include "BENCHMARKS_runner.h"
#include "crypto/crypto_api.h"
#include "crypto/aes_gcm.h"
#include "crypto/sha256.h"
#include "crypto/sha3.h"
#include "protocol/PROTOCOL_handshake.h"
#include "protocol/PROTOCOL_token_verify.h"
#include "hal/hal.h"
#include <string.h>
#include <stdio.h>

#if defined(QSAC_PLATFORM_PICO)
#include "pico/stdlib.h"
#include "hardware/timer.h"
#include "hardware/clocks.h"
#define GET_TIME_US() time_us_64()
#define CLOCK_MHZ 125
#else
#include <time.h>
static uint64_t get_host_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}
#define GET_TIME_US() get_host_time_us()
#define CLOCK_MHZ 125
#endif

#define STACK_CANARY_WORD 0xA5A5A5A5
#define STACK_PAINT_WORDS 4096

static void paint_stack(void) {
    volatile uint32_t *sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    for (int i = 16; i < STACK_PAINT_WORDS; i++) {
        *(sp - i) = STACK_CANARY_WORD;
    }
}

static uint32_t measure_stack_usage(void) {
    volatile uint32_t *sp;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    uint32_t untouched = 0;
    for (int i = STACK_PAINT_WORDS - 1; i >= 16; i--) {
        if (*(sp - i) == STACK_CANARY_WORD) {
            untouched++;
        } else {
            break;
        }
    }
    return (STACK_PAINT_WORDS - untouched) * sizeof(uint32_t);
}

/* Static workspace */
static uint8_t g_bench_buf1[1024];
static uint8_t g_bench_buf2[1024];
static uint8_t g_bench_buf3[1024];
static uint8_t g_bench_key[64];
static uint8_t g_bench_iv[16];
static uint8_t g_bench_tag[16];
static uint8_t g_bench_hash[32];

static uint8_t g_kem_pk[QSAC_MLKEM_PUBKEY_SIZE];
static uint8_t g_kem_sk[QSAC_MLKEM_PRIVKEY_SIZE];
static uint8_t g_kem_ct[QSAC_MLKEM_CIPHERTEXT_SIZE];
static uint8_t g_kem_ss1[QSAC_MLKEM_SHARED_SECRET_SIZE];
static uint8_t g_kem_ss2[QSAC_MLKEM_SHARED_SECRET_SIZE];

static uint8_t g_dsa_pk[QSAC_MLDSA_PUBKEY_SIZE];
static uint8_t g_dsa_sk[QSAC_MLDSA_PRIVKEY_SIZE];
static uint8_t g_dsa_sig[QSAC_MLDSA_SIG_SIZE];

static uint8_t g_ecc_pk[QSAC_ECC_PUBKEY_SIZE];
static uint8_t g_ecc_ss[QSAC_ECC_SHARED_SECRET_SIZE];
static uint8_t g_ecc_sig[QSAC_ECDSA_SIG_SIZE];

static void run_and_report(const char *name, uint32_t iters, uint32_t data_size,
                           void (*init_fn)(void), void (*op_fn)(void),
                           qsac_benchmark_callback_t callback) {
    qsac_benchmark_record_t rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.name, name, sizeof(rec.name) - 1);
    rec.iterations = iters;
    rec.data_size_bytes = data_size;
    rec.min_cycles = UINT64_MAX;
    rec.max_cycles = 0;

    uint64_t total_cycles = 0;
    uint64_t total_time_us = 0;

    if (init_fn) {
        init_fn();
    }

    paint_stack();

    for (uint32_t i = 0; i < iters; i++) {
        uint64_t t_start = GET_TIME_US();
        op_fn();
        uint64_t t_end = GET_TIME_US();

        uint64_t elapsed_us = t_end - t_start;
        uint64_t cycles = elapsed_us * CLOCK_MHZ;

        total_time_us += elapsed_us;
        total_cycles += cycles;

        if (cycles < rec.min_cycles) rec.min_cycles = cycles;
        if (cycles > rec.max_cycles) rec.max_cycles = cycles;
    }

    rec.avg_cycles = total_cycles / iters;
    rec.avg_time_us = (uint32_t)(total_time_us / iters);
    rec.stack_usage_bytes = measure_stack_usage();

    if (callback) {
        callback(&rec);
    }
}

/* Benchmark Op Functions */
static void op_rng(void) {
    qsac_random_bytes(g_bench_buf1, 32);
}

static void op_sha256_1k(void) {
    qsac_sha256(g_bench_buf1, 1024, g_bench_hash);
}

static void op_sha3_1k(void) {
    qsac_sha3_256(g_bench_buf1, 1024, g_bench_hash);
}

static void op_hkdf(void) {
    qsac_hkdf_sha256(g_bench_buf1, 32, g_bench_buf2, 64, (const uint8_t *)"info", 4, g_bench_key, 32);
}

static void op_aes_gcm_enc_1k(void) {
    qsac_aes_gcm_encrypt(g_bench_key, g_bench_iv, g_bench_iv, 4, g_bench_buf1, 1024, g_bench_buf2, g_bench_tag);
}

static void op_aes_gcm_dec_1k(void) {
    qsac_aes_gcm_decrypt(g_bench_key, g_bench_iv, g_bench_iv, 4, g_bench_buf2, 1024, g_bench_tag, g_bench_buf3);
}

static void op_ecdh_keygen(void) {
    qsac_ecc_keygen(1, g_ecc_pk);
}

static void op_ecdh_secret(void) {
    qsac_ecdh(1, g_ecc_pk, g_ecc_ss);
}

static void op_ecdsa_sign(void) {
    qsac_ecdsa_sign(1, g_bench_hash, g_ecc_sig);
}

static void op_ecdsa_verify(void) {
    qsac_ecdsa_verify(g_ecc_pk, g_bench_hash, g_ecc_sig);
}

static void op_mlkem_keygen(void) {
    qsac_mlkem_keygen(g_kem_pk, g_kem_sk);
}

static void op_mlkem_encaps(void) {
    qsac_mlkem_encaps(g_kem_pk, g_kem_ct, g_kem_ss1);
}

static void op_mlkem_decaps(void) {
    qsac_mlkem_decaps(g_kem_sk, g_kem_ct, g_kem_ss2);
}

static void op_mldsa_keygen(void) {
    qsac_mldsa_keygen(g_dsa_pk, g_dsa_sk);
}

static void op_mldsa_sign(void) {
    qsac_mldsa_sign(g_dsa_sk, g_bench_hash, 32, g_dsa_sig);
}

static void op_mldsa_verify(void) {
    qsac_mldsa_verify(g_dsa_pk, g_bench_hash, 32, g_dsa_sig);
}

static void init_token_bench(void) {
    qsac_mldsa_keygen(g_dsa_pk, g_dsa_sk);
    qsac_token_load_authority_key(g_dsa_pk);
    qsac_access_token_t token;
    memset(&token, 0, sizeof(token));
    token.payload.issued_at = 100;
    token.payload.expires_at = 200;
    token.payload.permissions = 3;
    qsac_mldsa_sign(g_dsa_sk, (const uint8_t *)&token.payload, sizeof(token.payload), g_dsa_sig);
}

static void op_token_verify(void) {
    qsac_access_token_t token;
    memset(&token, 0, sizeof(token));
    token.payload.issued_at = 100;
    token.payload.expires_at = 200;
    token.payload.permissions = 3;
    memcpy(token.signature, g_dsa_sig, sizeof(token.signature));
    uint32_t perms = 0;
    qsac_token_verify(&token, 150, &perms);
}

void qsac_benchmarks_run_all(qsac_benchmark_callback_t callback) {
    memset(g_bench_buf1, 0x5A, sizeof(g_bench_buf1));
    memset(g_bench_buf2, 0xA5, sizeof(g_bench_buf2));
    memset(g_bench_key, 0x1F, sizeof(g_bench_key));
    memset(g_bench_iv, 0x01, sizeof(g_bench_iv));
    qsac_sha256((const uint8_t *)"QSAC-BENCHMARK", 14, g_bench_hash);

    /* Setup initial ECC key */
    qsac_ecc_keygen(1, g_ecc_pk);

    /* 1. Symmetric & Hash Primitives */
    run_and_report("RNG ROSC (32B)", 50, 32, NULL, op_rng, callback);
    run_and_report("SHA-256 (1KB)", 20, 1024, NULL, op_sha256_1k, callback);
    run_and_report("SHA-3-256 (1KB)", 20, 1024, NULL, op_sha3_1k, callback);
    run_and_report("HKDF-SHA-256", 50, 64, NULL, op_hkdf, callback);
    run_and_report("AES-256-GCM Enc (1KB)", 20, 1024, NULL, op_aes_gcm_enc_1k, callback);
    run_and_report("AES-256-GCM Dec (1KB)", 20, 1024, NULL, op_aes_gcm_dec_1k, callback);

    /* 2. Classical Asymmetric (ECC P-256) */
    run_and_report("ECDH P-256 KeyGen", 5, 0, NULL, op_ecdh_keygen, callback);
    run_and_report("ECDH P-256 SharedSecret", 5, 0, NULL, op_ecdh_secret, callback);
    run_and_report("ECDSA P-256 Sign", 5, 32, NULL, op_ecdsa_sign, callback);
    run_and_report("ECDSA P-256 Verify", 5, 32, NULL, op_ecdsa_verify, callback);

    /* 3. Post-Quantum KEM (FIPS 203 ML-KEM-512) */
    run_and_report("ML-KEM-512 KeyGen", 10, 0, NULL, op_mlkem_keygen, callback);
    run_and_report("ML-KEM-512 Encaps", 10, 0, NULL, op_mlkem_encaps, callback);
    run_and_report("ML-KEM-512 Decaps", 10, 0, NULL, op_mlkem_decaps, callback);

    /* 4. Post-Quantum Signature (FIPS 204 ML-DSA-44) */
    run_and_report("ML-DSA-44 KeyGen", 3, 0, NULL, op_mldsa_keygen, callback);
    run_and_report("ML-DSA-44 Sign", 3, 32, NULL, op_mldsa_sign, callback);
    run_and_report("ML-DSA-44 Verify", 5, 32, NULL, op_mldsa_verify, callback);

    /* 5. Access Control Token Verification */
    run_and_report("Access Token Verify", 5, sizeof(qsac_token_payload_t), init_token_bench, op_token_verify, callback);
}

void qsac_tvla_run(uint8_t primitive_id, uint8_t class_id, uint16_t count, qsac_tvla_callback_t callback)
{
    if (!callback || count == 0) return;

    if (primitive_id == QSAC_TVLA_PRIMITIVE_MLKEM_DECAPS) {
        static uint8_t pk[QSAC_MLKEM_PUBKEY_SIZE];
        static uint8_t sk[QSAC_MLKEM_PRIVKEY_SIZE];
        static uint8_t ct_valid[QSAC_MLKEM_CIPHERTEXT_SIZE];
        static uint8_t ct_test[QSAC_MLKEM_CIPHERTEXT_SIZE];
        static uint8_t ss[QSAC_MLKEM_SHARED_SECRET_SIZE];

        qsac_mlkem_keygen(pk, sk);
        qsac_mlkem_encaps(pk, ct_valid, ss);

        for (uint16_t i = 0; i < count; i++) {
            if (class_id == 0) {
                memcpy(ct_test, ct_valid, sizeof(ct_test));
            } else {
                memcpy(ct_test, ct_valid, sizeof(ct_test));
                ct_test[i % sizeof(ct_test)] ^= (uint8_t)(0xAA ^ (i & 0xFF));
            }

            uint64_t t0 = GET_TIME_US();
            qsac_mlkem_decaps(sk, ct_test, ss);
            uint64_t t1 = GET_TIME_US();

            uint32_t elapsed_us = (uint32_t)(t1 - t0);
            qsac_tvla_sample_t sample;
            sample.primitive_id = primitive_id;
            sample.class_id = class_id;
            sample.sample_index = i;
            sample.execution_time_us = elapsed_us;
            sample.cpu_cycles = (uint64_t)elapsed_us * CLOCK_MHZ;
            callback(&sample);
        }
    } else if (primitive_id == QSAC_TVLA_PRIMITIVE_MLDSA_VERIFY) {
        static uint8_t pk[QSAC_MLDSA_PUBKEY_SIZE];
        static uint8_t sk[QSAC_MLDSA_PRIVKEY_SIZE];
        static uint8_t sig_valid[QSAC_MLDSA_SIG_SIZE];
        static uint8_t sig_test[QSAC_MLDSA_SIG_SIZE];
        static uint8_t msg[32];
        memset(msg, 0x42, sizeof(msg));

        qsac_mldsa_keygen(pk, sk);
        qsac_mldsa_sign(sk, msg, sizeof(msg), sig_valid);

        for (uint16_t i = 0; i < count; i++) {
            if (class_id == 0) {
                memcpy(sig_test, sig_valid, sizeof(sig_test));
            } else {
                memcpy(sig_test, sig_valid, sizeof(sig_test));
                sig_test[i % sizeof(sig_test)] ^= (uint8_t)(0x55 ^ (i & 0xFF));
            }

            uint64_t t0 = GET_TIME_US();
            qsac_mldsa_verify(pk, msg, sizeof(msg), sig_test);
            uint64_t t1 = GET_TIME_US();

            uint32_t elapsed_us = (uint32_t)(t1 - t0);
            qsac_tvla_sample_t sample;
            sample.primitive_id = primitive_id;
            sample.class_id = class_id;
            sample.sample_index = i;
            sample.execution_time_us = elapsed_us;
            sample.cpu_cycles = (uint64_t)elapsed_us * CLOCK_MHZ;
            callback(&sample);
        }
    } else if (primitive_id == QSAC_TVLA_PRIMITIVE_AES_GCM_DEC) {
        static uint8_t key[32];
        static uint8_t iv[12];
        static uint8_t aad[4];
        static uint8_t pt[256];
        static uint8_t ct[256];
        static uint8_t tag_valid[16];
        static uint8_t tag_test[16];
        static uint8_t out[256];

        memset(key, 0x11, sizeof(key));
        memset(iv, 0x22, sizeof(iv));
        memset(aad, 0x33, sizeof(aad));
        memset(pt, 0x44, sizeof(pt));

        qsac_aes_gcm_encrypt(key, iv, aad, sizeof(aad), pt, sizeof(pt), ct, tag_valid);

        for (uint16_t i = 0; i < count; i++) {
            if (class_id == 0) {
                memcpy(tag_test, tag_valid, sizeof(tag_test));
            } else {
                memcpy(tag_test, tag_valid, sizeof(tag_test));
                tag_test[i % sizeof(tag_test)] ^= (uint8_t)(0x01 ^ (i & 0x07));
            }

            uint64_t t0 = GET_TIME_US();
            qsac_aes_gcm_decrypt(key, iv, aad, sizeof(aad), ct, sizeof(pt), tag_test, out);
            uint64_t t1 = GET_TIME_US();

            uint32_t elapsed_us = (uint32_t)(t1 - t0);
            qsac_tvla_sample_t sample;
            sample.primitive_id = primitive_id;
            sample.class_id = class_id;
            sample.sample_index = i;
            sample.execution_time_us = elapsed_us;
            sample.cpu_cycles = (uint64_t)elapsed_us * CLOCK_MHZ;
            callback(&sample);
        }
    }
}
