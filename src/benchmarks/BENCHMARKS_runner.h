/**
 * @file BENCHMARKS_runner.h
 * @brief High-precision hardware benchmarking and stack profiling suite for QSAC.
 */

#ifndef BENCHMARKS_RUNNER_H
#define BENCHMARKS_RUNNER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QSAC_BENCHMARK_NAME_LEN 32

typedef struct {
    char     name[QSAC_BENCHMARK_NAME_LEN];
    uint32_t iterations;
    uint64_t avg_cycles;
    uint64_t min_cycles;
    uint64_t max_cycles;
    uint32_t avg_time_us;
    uint32_t stack_usage_bytes;
    uint32_t data_size_bytes;
} __attribute__((packed)) qsac_benchmark_record_t;

typedef void (*qsac_benchmark_callback_t)(const qsac_benchmark_record_t *record);

void qsac_benchmarks_run_all(qsac_benchmark_callback_t callback);

typedef enum {
    QSAC_TVLA_PRIMITIVE_MLKEM_DECAPS = 0,
    QSAC_TVLA_PRIMITIVE_MLDSA_VERIFY = 1,
    QSAC_TVLA_PRIMITIVE_AES_GCM_DEC  = 2,
    QSAC_TVLA_PRIMITIVE_ECDSA_VERIFY = 3
} qsac_tvla_primitive_t;

typedef struct {
    uint8_t  primitive_id;
    uint8_t  class_id;     /* 0 = Fixed / Valid, 1 = Random / Invalid */
    uint16_t sample_index;
    uint32_t execution_time_us;
    uint64_t cpu_cycles;
} __attribute__((packed)) qsac_tvla_sample_t;

typedef void (*qsac_tvla_callback_t)(const qsac_tvla_sample_t *sample);

void qsac_tvla_run(uint8_t primitive_id, uint8_t class_id, uint16_t count, qsac_tvla_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif /* BENCHMARKS_RUNNER_H */
