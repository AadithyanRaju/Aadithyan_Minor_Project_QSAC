/**
 * @file CRYPTO_PQC_MLKEM512_ntt.c
 * @brief Number Theoretic Transform implementation for Kyber.
 */

#include "CRYPTO_PQC_MLKEM512_ntt.h"
#include "CRYPTO_PQC_MLKEM512_reduce.h"

const int16_t kyber_zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
     -171,   622,  1577,   182,   962, -1202, -1474,  1468,
      573, -1325,   264,   383,  -829,  1458, -1602,  -130,
     -681,  1017,   732,   608, -1542,   411,  -205, -1571,
     1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
      516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
     -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
     -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
      422,   587,   177,  -235,  -291,  -460,  1574,  1653,
     -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
      817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
     -108,  -308,   996,   991,   958, -1460,  1522,  1628,
};

const int16_t kyber_zetas_inv[128] = {
    -1044,   758,  1517,   359,  -202,  -287, -1422, -1493,
    -1468,  1474,  1202,  -962,  -182, -1577,  -622,   171,
     1571,   205,  -411,  1542,  -608,  -732, -1017,   681,
      130,  1602, -1458,   829,  -383,  -264,  1325,  -573,
     1275,  -677,  1065,  -448,   725,  1508,  -961,   398,
      951,   247,  1421,  -107,  -830,   271,    90,   853,
    -1469,  -126,  1162,  1618,   666,   320,     8,  -516,
     1544,   282, -1491,  1293, -1015,   552,  -652, -1223,
    -1628, -1522,  1460,  -958,  -991,  -996,   308,   108,
     -478,   870,   854,  1510,  -794,  1278,  1530,  1185,
     1659,  1187,  -220,   874,  1335, -1218,   136,  1215,
     -384,  1465,  1285, -1322,  -610,  -603, -1097,  -817,
       75,   156,  -329,  -418,  -349,   872,  -644,  1590,
    -1119,   602, -1483,   777,   147, -1159,  -778,   246,
    -1653, -1574,   460,   291,   235,  -177,  -587,  -422,
     -105, -1550,  -871,  1251,  -843,  -555,  -430,  1103,
};

void kyber_ntt(int16_t poly[256]) {
    int len, start, j, k;
    int16_t zeta, t;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = kyber_zetas[k++];
            for (j = start; j < start + len; ++j) {
                t = kyber_montgomery_reduce((int32_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }
}

void kyber_invntt(int16_t poly[256]) {
    int len, start, j, k;
    int16_t zeta_inv, t;
    const int16_t f = 512;

    for (len = 2; len <= 128; len <<= 1) {
        k = 128 / len;
        for (start = 0; start < 256; start = j + len) {
            zeta_inv = kyber_zetas_inv[k++];
            for (j = start; j < start + len; ++j) {
                t = poly[j];
                poly[j] = kyber_barrett_reduce(t + poly[j + len]);
                poly[j + len] = kyber_montgomery_reduce((int32_t)zeta_inv * (t - poly[j + len]));
            }
        }
    }

    for (j = 0; j < 256; ++j) {
        poly[j] = kyber_montgomery_reduce((int32_t)poly[j] * f);
    }
}

void kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    int32_t t0 = kyber_montgomery_reduce((int32_t)a[1] * b[1]);
    t0 = kyber_montgomery_reduce((int32_t)t0 * zeta);
    t0 += kyber_montgomery_reduce((int32_t)a[0] * b[0]);

    int32_t t1 = kyber_montgomery_reduce((int32_t)a[0] * b[1]);
    t1 += kyber_montgomery_reduce((int32_t)a[1] * b[0]);

    r[0] = (int16_t)t0;
    r[1] = (int16_t)t1;
}
