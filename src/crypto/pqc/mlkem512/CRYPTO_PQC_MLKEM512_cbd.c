/**
 * @file CRYPTO_PQC_MLKEM512_cbd.c
 * @brief Centered Binomial Distribution sampling implementation for Kyber.
 */

#include "CRYPTO_PQC_MLKEM512_cbd.h"
#include <stddef.h>

static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

static uint32_t load24_littleendian(const uint8_t x[3]) {
    uint32_t r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}

void cbd2(int16_t r[256], const uint8_t buf[2 * KYBER_N / 4]) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
        uint32_t t = load32_littleendian(buf + 4 * i);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (size_t j = 0; j < 8; ++j) {
            int16_t a = (int16_t)((d >> (4 * j + 0)) & 0x3);
            int16_t b = (int16_t)((d >> (4 * j + 2)) & 0x3);
            r[8 * i + j] = (int16_t)(a - b);
        }
    }
}

void cbd3(int16_t r[256], const uint8_t buf[3 * KYBER_N / 4]) {
    for (size_t i = 0; i < KYBER_N / 4; ++i) {
        uint32_t t = load24_littleendian(buf + 3 * i);
        uint32_t d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (size_t j = 0; j < 4; ++j) {
            int16_t a = (int16_t)((d >> (6 * j + 0)) & 0x7);
            int16_t b = (int16_t)((d >> (6 * j + 3)) & 0x7);
            r[4 * i + j] = (int16_t)(a - b);
        }
    }
}
