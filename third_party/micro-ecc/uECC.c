/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include <string.h>

#define uECC_WORD_SIZE 4
#define uECC_WORDS 8
#define uECC_N_WORDS 8

typedef uint32_t uECC_word_t;
typedef uint64_t uECC_dword_t;
typedef int32_t  uECC_sword_t;
typedef int64_t  uECC_sdword_t;

#define HIGH_BIT_SET(word) ((word) & 0x80000000)

struct uECC_Curve_t {
    uECC_word_t p[uECC_WORDS];
    uECC_word_t n[uECC_N_WORDS];
    uECC_word_t G[uECC_WORDS * 2];
    uECC_word_t b[uECC_WORDS];
};

typedef struct uECC_Curve_t uECC_Curve_t;

/* secp256r1 curve constants in little-endian 32-bit words */
static const uECC_Curve_t curve_secp256r1 = {
    { /* p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF */
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
    },
    { /* n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 */
        0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
        0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
    },
    { /* Gx */
        0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
        0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2,
      /* Gy */
        0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
        0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2
    },
    { /* b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B */
        0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
        0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
    }
};

static uECC_RNG_Function g_rng_function = 0;

void uECC_set_rng(uECC_RNG_Function rng_function) {
    g_rng_function = rng_function;
}

uECC_RNG_Function uECC_get_rng(void) {
    return g_rng_function;
}

uECC_Curve uECC_secp256r1(void) {
    return &curve_secp256r1;
}

int uECC_curve_private_key_size(uECC_Curve curve) {
    (void)curve;
    return 32;
}

int uECC_curve_public_key_size(uECC_Curve curve) {
    (void)curve;
    return 64;
}

/* ──────────────────────────────────────────────
 * Big-integer math operations (little-endian arrays of 32-bit words)
 * ────────────────────────────────────────────── */

static void vli_clear(uECC_word_t *vli) {
    for (int i = 0; i < uECC_WORDS; ++i) {
        vli[i] = 0;
    }
}

static int vli_isZero(const uECC_word_t *vli) {
    for (int i = 0; i < uECC_WORDS; ++i) {
        if (vli[i] != 0) return 0;
    }
    return 1;
}

static uECC_word_t vli_testBit(const uECC_word_t *vli, unsigned int bit) {
    return (vli[bit / 32] & ((uECC_word_t)1 << (bit % 32)));
}

static unsigned int vli_numBits(const uECC_word_t *vli, unsigned int max_words) {
    int i;
    for (i = (int)max_words - 1; i >= 0 && vli[i] == 0; --i) {}
    if (i < 0) return 0;

    uECC_word_t word = vli[i];
    unsigned int bits = 0;
    while (word != 0) {
        bits++;
        word >>= 1;
    }
    return ((unsigned int)i * 32) + bits;
}

static void vli_set(uECC_word_t *dest, const uECC_word_t *src) {
    for (int i = 0; i < uECC_WORDS; ++i) {
        dest[i] = src[i];
    }
}

static int vli_cmp(const uECC_word_t *left, const uECC_word_t *right) {
    for (int i = uECC_WORDS - 1; i >= 0; --i) {
        if (left[i] > right[i]) return 1;
        if (left[i] < right[i]) return -1;
    }
    return 0;
}

static uECC_word_t vli_add(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t carry = 0;
    for (int i = 0; i < uECC_WORDS; ++i) {
        uECC_dword_t sum = (uECC_dword_t)left[i] + right[i] + carry;
        result[i] = (uECC_word_t)sum;
        carry = (uECC_word_t)(sum >> 32);
    }
    return carry;
}

static uECC_word_t vli_sub(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t borrow = 0;
    for (int i = 0; i < uECC_WORDS; ++i) {
        uECC_dword_t diff = (uECC_dword_t)left[i] - right[i] - borrow;
        result[i] = (uECC_word_t)diff;
        borrow = (diff >> 32) & 1;
    }
    return borrow;
}

/* Modulo operations with prime p */
static void vli_madd(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right, const uECC_word_t *mod) {
    uECC_word_t carry = vli_add(result, left, right);
    if (carry || vli_cmp(result, mod) >= 0) {
        vli_sub(result, result, mod);
    }
}

static void vli_msub(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right, const uECC_word_t *mod) {
    uECC_word_t borrow = vli_sub(result, left, right);
    if (borrow) {
        vli_add(result, result, mod);
    }
}

/* Fast multiplication */
static void vli_mult(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_dword_t r0 = 0, r1 = 0, r2 = 0;

    for (int k = 0; k < uECC_WORDS * 2 - 1; ++k) {
        int min = (k < uECC_WORDS ? 0 : (k - uECC_WORDS + 1));
        int max = (k < uECC_WORDS ? k : uECC_WORDS - 1);
        for (int i = min; i <= max; ++i) {
            uECC_dword_t prod = (uECC_dword_t)left[i] * right[k - i];
            r0 += (uECC_word_t)prod;
            r1 += (prod >> 32) + (r0 >> 32);
            r0 = (uECC_word_t)r0;
            r2 += (r1 >> 32);
            r1 = (uECC_word_t)r1;
        }
        result[k] = (uECC_word_t)r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_WORDS * 2 - 1] = (uECC_word_t)r0;
}

/* NIST P-256 fast modular reduction using special prime structure */
static void vli_mmod_fast_secp256r1(uECC_word_t *result, uECC_word_t *product) {
    uECC_word_t tmp[uECC_WORDS];
    uECC_sword_t carry;

    vli_set(result, product);

    /* s2 */
    tmp[0] = tmp[1] = tmp[2] = 0;
    tmp[3] = product[11];
    tmp[4] = product[12];
    tmp[5] = product[13];
    tmp[6] = product[14];
    tmp[7] = product[15];
    carry = (uECC_sword_t)vli_add(result, result, tmp);
    carry += (uECC_sword_t)vli_add(result, result, tmp);

    /* s3 */
    tmp[3] = product[12];
    tmp[4] = product[13];
    tmp[5] = product[14];
    tmp[6] = product[15];
    tmp[7] = 0;
    carry += (uECC_sword_t)vli_add(result, result, tmp);
    carry += (uECC_sword_t)vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = product[8];
    tmp[1] = product[9];
    tmp[2] = product[10];
    tmp[3] = 0;
    tmp[4] = 0;
    tmp[5] = 0;
    tmp[6] = product[14];
    tmp[7] = product[15];
    carry += (uECC_sword_t)vli_add(result, result, tmp);

    /* s5 */
    tmp[0] = product[9];
    tmp[1] = product[10];
    tmp[2] = product[11];
    tmp[3] = product[13];
    tmp[4] = product[14];
    tmp[5] = product[15];
    tmp[6] = product[13];
    tmp[7] = product[8];
    carry += (uECC_sword_t)vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[11];
    tmp[1] = product[12];
    tmp[2] = product[13];
    tmp[3] = 0;
    tmp[4] = 0;
    tmp[5] = 0;
    tmp[6] = product[8];
    tmp[7] = product[10];
    carry -= (uECC_sword_t)vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[12];
    tmp[1] = product[13];
    tmp[2] = product[14];
    tmp[3] = product[15];
    tmp[4] = 0;
    tmp[5] = 0;
    tmp[6] = product[9];
    tmp[7] = product[11];
    carry -= (uECC_sword_t)vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = product[13];
    tmp[1] = product[14];
    tmp[2] = product[15];
    tmp[3] = product[8];
    tmp[4] = product[9];
    tmp[5] = product[10];
    tmp[6] = 0;
    tmp[7] = product[12];
    carry -= (uECC_sword_t)vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[14];
    tmp[1] = product[15];
    tmp[2] = 0;
    tmp[3] = product[9];
    tmp[4] = product[10];
    tmp[5] = product[11];
    tmp[6] = 0;
    tmp[7] = product[13];
    carry -= (uECC_sword_t)vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += (uECC_sword_t)vli_add(result, result, curve_secp256r1.p);
        } while (carry < 0);
    } else {
        while (carry || vli_cmp(result, curve_secp256r1.p) >= 0) {
            carry -= (uECC_sword_t)vli_sub(result, result, curve_secp256r1.p);
        }
    }
}

static void vli_modMult_fast(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t product[uECC_WORDS * 2];
    vli_mult(product, left, right);
    vli_mmod_fast_secp256r1(result, product);
}

static void vli_modSquare_fast(uECC_word_t *result, const uECC_word_t *left) {
    vli_modMult_fast(result, left, left);
}

static void vli_modInv(uECC_word_t *result, const uECC_word_t *input, const uECC_word_t *mod) {
    uECC_word_t a[uECC_WORDS], b[uECC_WORDS], u[uECC_WORDS], v[uECC_WORDS];
    uECC_word_t carry;

    vli_set(a, input);
    vli_set(b, mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);

    while (!vli_isZero(a)) {
        while ((a[0] & 1) == 0) {
            /* a is even */
            for (int i = 0; i < uECC_WORDS - 1; ++i) {
                a[i] = (a[i] >> 1) | (a[i + 1] << 31);
            }
            a[uECC_WORDS - 1] >>= 1;

            if (u[0] & 1) {
                carry = vli_add(u, u, mod);
                for (int i = 0; i < uECC_WORDS - 1; ++i) {
                    u[i] = (u[i] >> 1) | (u[i + 1] << 31);
                }
                u[uECC_WORDS - 1] = (u[uECC_WORDS - 1] >> 1) | (carry << 31);
            } else {
                for (int i = 0; i < uECC_WORDS - 1; ++i) {
                    u[i] = (u[i] >> 1) | (u[i + 1] << 31);
                }
                u[uECC_WORDS - 1] >>= 1;
            }
        }

        while ((b[0] & 1) == 0) {
            /* b is even */
            for (int i = 0; i < uECC_WORDS - 1; ++i) {
                b[i] = (b[i] >> 1) | (b[i + 1] << 31);
            }
            b[uECC_WORDS - 1] >>= 1;

            if (v[0] & 1) {
                carry = vli_add(v, v, mod);
                for (int i = 0; i < uECC_WORDS - 1; ++i) {
                    v[i] = (v[i] >> 1) | (v[i + 1] << 31);
                }
                v[uECC_WORDS - 1] = (v[uECC_WORDS - 1] >> 1) | (carry << 31);
            } else {
                for (int i = 0; i < uECC_WORDS - 1; ++i) {
                    v[i] = (v[i] >> 1) | (v[i + 1] << 31);
                }
                v[uECC_WORDS - 1] >>= 1;
            }
        }

        if (vli_cmp(a, b) >= 0) {
            vli_sub(a, a, b);
            vli_msub(u, u, v, mod);
        } else {
            vli_sub(b, b, a);
            vli_msub(v, v, u, mod);
        }
    }

    vli_set(result, v);
}

/* Modulo reduction by order n */
static void vli_mmod_n(uECC_word_t *result, uECC_word_t *product) {
    uECC_word_t rem[uECC_WORDS * 2];
    vli_set(rem, product);
    vli_set(rem + uECC_WORDS, product + uECC_WORDS);

    unsigned int num_bits = vli_numBits(rem, uECC_WORDS * 2);
    unsigned int n_bits = 256;

    if (num_bits < n_bits) {
        vli_set(result, rem);
        return;
    }

    uECC_word_t shifted_n[uECC_WORDS * 2];
    vli_clear(shifted_n);
    vli_clear(shifted_n + uECC_WORDS);

    int shift = (int)num_bits - (int)n_bits;
    int word_shift = shift / 32;
    int bit_shift = shift % 32;

    for (int i = 0; i < uECC_WORDS; ++i) {
        if (bit_shift == 0) {
            shifted_n[i + word_shift] = curve_secp256r1.n[i];
        } else {
            shifted_n[i + word_shift] |= curve_secp256r1.n[i] << bit_shift;
            shifted_n[i + word_shift + 1] = curve_secp256r1.n[i] >> (32 - bit_shift);
        }
    }

    while (shift >= 0) {
        int cmp = 0;
        for (int i = uECC_WORDS * 2 - 1; i >= 0; --i) {
            if (rem[i] > shifted_n[i]) { cmp = 1; break; }
            if (rem[i] < shifted_n[i]) { cmp = -1; break; }
        }
        if (cmp >= 0) {
            /* rem -= shifted_n */
            uECC_word_t borrow = 0;
            for (int i = 0; i < uECC_WORDS * 2; ++i) {
                uECC_dword_t diff = (uECC_dword_t)rem[i] - shifted_n[i] - borrow;
                rem[i] = (uECC_word_t)diff;
                borrow = (diff >> 32) & 1;
            }
        }

        /* shifted_n >>= 1 */
        for (int i = 0; i < uECC_WORDS * 2 - 1; ++i) {
            shifted_n[i] = (shifted_n[i] >> 1) | (shifted_n[i + 1] << 31);
        }
        shifted_n[uECC_WORDS * 2 - 1] >>= 1;
        shift--;
    }

    vli_set(result, rem);
}

static void vli_modMult_n(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t product[uECC_WORDS * 2];
    vli_mult(product, left, right);
    vli_mmod_n(result, product);
}

/* ──────────────────────────────────────────────
 * Elliptic curve point operations (Jacobian projective coordinates)
 * ────────────────────────────────────────────── */

/* Unified projective addition & point multiplication */
static void point_double(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *Z1) {
    if (vli_isZero(Z1)) return;

    uECC_word_t A[uECC_WORDS], B[uECC_WORDS], C[uECC_WORDS], D[uECC_WORDS], E[uECC_WORDS];
    uECC_word_t t1[uECC_WORDS], t2[uECC_WORDS];

    vli_modSquare_fast(A, X1); /* A = X1^2 */
    vli_modSquare_fast(B, Y1); /* B = Y1^2 */
    vli_modSquare_fast(C, B);  /* C = B^2 = Y1^4 */

    vli_madd(t1, X1, B, curve_secp256r1.p);
    vli_modSquare_fast(t1, t1); /* (X1+B)^2 */
    vli_msub(t1, t1, A, curve_secp256r1.p);
    vli_msub(t1, t1, C, curve_secp256r1.p);
    vli_madd(D, t1, t1, curve_secp256r1.p); /* D = 2*((X1+B)^2 - A - C) */

    vli_modSquare_fast(t1, Z1); /* Z1^2 */
    vli_msub(t2, X1, t1, curve_secp256r1.p); /* X1 - Z1^2 */
    vli_madd(t1, X1, t1, curve_secp256r1.p); /* X1 + Z1^2 */
    vli_modMult_fast(E, t1, t2); /* (X1-Z1^2)*(X1+Z1^2) */
    vli_madd(t1, E, E, curve_secp256r1.p);
    vli_madd(E, t1, E, curve_secp256r1.p); /* E = 3*(X1-Z1^2)*(X1+Z1^2) */

    /* X3 = E^2 - 2*D */
    vli_modSquare_fast(X1, E);
    vli_msub(X1, X1, D, curve_secp256r1.p);
    vli_msub(X1, X1, D, curve_secp256r1.p);

    /* Z3 = 2*Y1*Z1 */
    vli_modMult_fast(t1, Y1, Z1);
    vli_madd(Z1, t1, t1, curve_secp256r1.p);

    /* Y3 = E*(D - X3) - 8*C */
    vli_msub(D, D, X1, curve_secp256r1.p);
    vli_modMult_fast(Y1, E, D);
    vli_madd(C, C, C, curve_secp256r1.p); /* 2*C */
    vli_madd(C, C, C, curve_secp256r1.p); /* 4*C */
    vli_madd(C, C, C, curve_secp256r1.p); /* 8*C */
    vli_msub(Y1, Y1, C, curve_secp256r1.p);
}

/* Add Jacobian (X1, Y1, Z1) + Affine (X2, Y2) -> Jacobian (X1, Y1, Z1) */
static void point_add_affine(uECC_word_t *X1, uECC_word_t *Y1, uECC_word_t *Z1,
                             const uECC_word_t *X2, const uECC_word_t *Y2) {
    if (vli_isZero(Z1)) {
        vli_set(X1, X2);
        vli_set(Y1, Y2);
        vli_clear(Z1);
        Z1[0] = 1;
        return;
    }

    uECC_word_t Z1Z1[uECC_WORDS], U2[uECC_WORDS], S2[uECC_WORDS], H[uECC_WORDS], r[uECC_WORDS];
    uECC_word_t HH[uECC_WORDS], HHH[uECC_WORDS], V[uECC_WORDS];

    vli_modSquare_fast(Z1Z1, Z1);          /* Z1Z1 = Z1^2 */
    vli_modMult_fast(U2, X2, Z1Z1);        /* U2 = X2 * Z1^2 */
    vli_modMult_fast(S2, Y2, Z1Z1);
    vli_modMult_fast(S2, S2, Z1);          /* S2 = Y2 * Z1^3 */

    vli_msub(H, U2, X1, curve_secp256r1.p); /* H = U2 - X1 */
    vli_msub(r, S2, Y1, curve_secp256r1.p); /* r = S2 - Y1 */

    if (vli_isZero(H)) {
        if (vli_isZero(r)) {
            point_double(X1, Y1, Z1);
            return;
        }
        /* Point at infinity */
        vli_clear(Z1);
        return;
    }

    vli_modSquare_fast(HH, H);             /* HH = H^2 */
    vli_modMult_fast(HHH, HH, H);          /* HHH = H^3 */
    vli_modMult_fast(V, X1, HH);           /* V = X1 * H^2 */

    /* X3 = r^2 - HHH - 2*V */
    vli_modSquare_fast(X1, r);
    vli_msub(X1, X1, HHH, curve_secp256r1.p);
    vli_msub(X1, X1, V, curve_secp256r1.p);
    vli_msub(X1, X1, V, curve_secp256r1.p);

    /* Z3 = Z1 * H */
    vli_modMult_fast(Z1, Z1, H);

    /* Y3 = r*(V - X3) - Y1*HHH */
    uECC_word_t Y1_HHH[uECC_WORDS];
    vli_modMult_fast(Y1_HHH, Y1, HHH);
    vli_msub(V, V, X1, curve_secp256r1.p);
    vli_modMult_fast(Y1, r, V);
    vli_msub(Y1, Y1, Y1_HHH, curve_secp256r1.p);
}

/* Simple Montgomery ladder or standard double-and-add scalar mult */
static void point_mult(uECC_word_t *result_x, uECC_word_t *result_y,
                       const uECC_word_t *point_x, const uECC_word_t *point_y,
                       const uECC_word_t *scalar) {
    uECC_word_t X[uECC_WORDS], Y[uECC_WORDS], Z[uECC_WORDS];
    vli_clear(Z);

    unsigned int num_bits = vli_numBits(scalar, uECC_WORDS);
    if (num_bits == 0) {
        vli_clear(result_x);
        vli_clear(result_y);
        return;
    }

    for (int i = (int)num_bits - 1; i >= 0; --i) {
        point_double(X, Y, Z);
        if (vli_testBit(scalar, (unsigned int)i)) {
            point_add_affine(X, Y, Z, point_x, point_y);
        }
    }

    /* Convert Jacobian (X, Y, Z) to Affine (x = X/Z^2, y = Y/Z^3) */
    if (vli_isZero(Z)) {
        vli_clear(result_x);
        vli_clear(result_y);
        return;
    }

    uECC_word_t z_inv[uECC_WORDS], z_inv2[uECC_WORDS], z_inv3[uECC_WORDS];
    vli_modInv(z_inv, Z, curve_secp256r1.p);
    vli_modSquare_fast(z_inv2, z_inv);
    vli_modMult_fast(z_inv3, z_inv2, z_inv);

    vli_modMult_fast(result_x, X, z_inv2);
    vli_modMult_fast(result_y, Y, z_inv3);
}

/* ──────────────────────────────────────────────
 * Byte serialization helpers (big-endian wire format <-> little-endian uECC_word_t)
 * ────────────────────────────────────────────── */

static void vli_bytesToNative(uECC_word_t *dest, const uint8_t *src) {
    for (int i = 0; i < uECC_WORDS; ++i) {
        int src_idx = (uECC_WORDS - 1 - i) * 4;
        dest[i] = ((uECC_word_t)src[src_idx] << 24) |
                  ((uECC_word_t)src[src_idx + 1] << 16) |
                  ((uECC_word_t)src[src_idx + 2] << 8) |
                  ((uECC_word_t)src[src_idx + 3]);
    }
}

static void vli_nativeToBytes(uint8_t *dest, const uECC_word_t *src) {
    for (int i = 0; i < uECC_WORDS; ++i) {
        int dest_idx = (uECC_WORDS - 1 - i) * 4;
        dest[dest_idx]     = (uint8_t)(src[i] >> 24);
        dest[dest_idx + 1] = (uint8_t)(src[i] >> 16);
        dest[dest_idx + 2] = (uint8_t)(src[i] >> 8);
        dest[dest_idx + 3] = (uint8_t)(src[i]);
    }
}

/* ──────────────────────────────────────────────
 * Public API implementations
 * ────────────────────────────────────────────── */

int uECC_make_key(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve) {
    if (!public_key || !private_key || !curve || !g_rng_function) return 0;

    uECC_word_t priv[uECC_WORDS];
    uECC_word_t pub_x[uECC_WORDS], pub_y[uECC_WORDS];

    int tries = 0;
    do {
        if (!g_rng_function(private_key, 32)) return 0;
        vli_bytesToNative(priv, private_key);
        tries++;
        if (tries > 64) return 0;
    } while (vli_isZero(priv) || vli_cmp(priv, curve_secp256r1.n) >= 0);

    /* Compute Public Key Q = priv * G */
    point_mult(pub_x, pub_y, curve_secp256r1.G, curve_secp256r1.G + uECC_WORDS, priv);

    vli_nativeToBytes(public_key, pub_x);
    vli_nativeToBytes(public_key + 32, pub_y);

    return 1;
}

int uECC_shared_secret(const uint8_t *public_key,
                       const uint8_t *private_key,
                       uint8_t *secret,
                       uECC_Curve curve) {
    if (!public_key || !private_key || !secret || !curve) return 0;

    uECC_word_t pub_x[uECC_WORDS], pub_y[uECC_WORDS];
    uECC_word_t priv[uECC_WORDS];
    uECC_word_t res_x[uECC_WORDS], res_y[uECC_WORDS];

    vli_bytesToNative(pub_x, public_key);
    vli_bytesToNative(pub_y, public_key + 32);
    vli_bytesToNative(priv, private_key);

    /* Basic point validation on curve: y^2 == x^3 + ax + b */
    uECC_word_t y2[uECC_WORDS], x3[uECC_WORDS], ax[uECC_WORDS];
    vli_modSquare_fast(y2, pub_y);
    vli_modSquare_fast(x3, pub_x);
    vli_modMult_fast(x3, x3, pub_x); /* x^3 */
    /* ax = -3x */
    vli_madd(ax, pub_x, pub_x, curve_secp256r1.p);
    vli_madd(ax, ax, pub_x, curve_secp256r1.p); /* 3x */
    vli_msub(x3, x3, ax, curve_secp256r1.p);    /* x^3 - 3x */
    vli_madd(x3, x3, curve_secp256r1.b, curve_secp256r1.p); /* x^3 - 3x + b */

    if (vli_cmp(y2, x3) != 0) {
        return 0; /* Not on curve */
    }

    point_mult(res_x, res_y, pub_x, pub_y, priv);
    if (vli_isZero(res_x) && vli_isZero(res_y)) {
        return 0;
    }

    vli_nativeToBytes(secret, res_x);
    return 1;
}

int uECC_sign(const uint8_t *private_key,
              const uint8_t *message_hash,
              unsigned hash_size,
              uint8_t *signature,
              uECC_Curve curve) {
    if (!private_key || !message_hash || !signature || !curve || !g_rng_function) return 0;
    if (hash_size != 32) return 0;

    uECC_word_t d[uECC_WORDS], k[uECC_WORDS], e[uECC_WORDS];
    uECC_word_t r[uECC_WORDS], s[uECC_WORDS];
    uECC_word_t p_x[uECC_WORDS], p_y[uECC_WORDS];
    uECC_word_t k_inv[uECC_WORDS], tmp[uECC_WORDS];
    uint8_t k_bytes[32];

    vli_bytesToNative(d, private_key);
    vli_bytesToNative(e, message_hash);

    while (1) {
        if (!g_rng_function(k_bytes, 32)) return 0;
        vli_bytesToNative(k, k_bytes);
        if (vli_isZero(k) || vli_cmp(k, curve_secp256r1.n) >= 0) continue;

        /* P = k * G */
        point_mult(p_x, p_y, curve_secp256r1.G, curve_secp256r1.G + uECC_WORDS, k);

        /* r = p_x mod n */
        uECC_word_t p_x_wide[uECC_WORDS * 2];
        vli_set(p_x_wide, p_x);
        vli_clear(p_x_wide + uECC_WORDS);
        vli_mmod_n(r, p_x_wide);
        if (vli_isZero(r)) continue;

        /* s = k^-1 * (e + r * d) mod n */
        vli_modInv(k_inv, k, curve_secp256r1.n);
        vli_modMult_n(tmp, r, d);
        vli_madd(tmp, e, tmp, curve_secp256r1.n);
        vli_modMult_n(s, k_inv, tmp);

        if (vli_isZero(s)) continue;

        break;
    }

    vli_nativeToBytes(signature, r);
    vli_nativeToBytes(signature + 32, s);
    return 1;
}

int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature,
                uECC_Curve curve) {
    if (!public_key || !message_hash || !signature || !curve) return 0;
    if (hash_size != 32) return 0;

    uECC_word_t pub_x[uECC_WORDS], pub_y[uECC_WORDS];
    uECC_word_t r[uECC_WORDS], s[uECC_WORDS], e[uECC_WORDS];
    uECC_word_t w[uECC_WORDS], u1[uECC_WORDS], u2[uECC_WORDS];
    uECC_word_t p1_x[uECC_WORDS], p1_y[uECC_WORDS];
    uECC_word_t p2_x[uECC_WORDS], p2_y[uECC_WORDS];

    vli_bytesToNative(pub_x, public_key);
    vli_bytesToNative(pub_y, public_key + 32);
    vli_bytesToNative(r, signature);
    vli_bytesToNative(s, signature + 32);
    vli_bytesToNative(e, message_hash);

    if (vli_isZero(r) || vli_cmp(r, curve_secp256r1.n) >= 0) return 0;
    if (vli_isZero(s) || vli_cmp(s, curve_secp256r1.n) >= 0) return 0;

    /* w = s^-1 mod n */
    vli_modInv(w, s, curve_secp256r1.n);

    /* u1 = e * w mod n */
    vli_modMult_n(u1, e, w);

    /* u2 = r * w mod n */
    vli_modMult_n(u2, r, w);

    /* P1 = u1 * G */
    point_mult(p1_x, p1_y, curve_secp256r1.G, curve_secp256r1.G + uECC_WORDS, u1);

    /* P2 = u2 * Q */
    point_mult(p2_x, p2_y, pub_x, pub_y, u2);

    /* P = P1 + P2 */
    uECC_word_t Z[uECC_WORDS];
    vli_clear(Z);
    Z[0] = 1;
    point_add_affine(p1_x, p1_y, Z, p2_x, p2_y);

    if (vli_isZero(Z)) return 0;

    uECC_word_t z_inv[uECC_WORDS], z_inv2[uECC_WORDS], x[uECC_WORDS];
    vli_modInv(z_inv, Z, curve_secp256r1.p);
    vli_modSquare_fast(z_inv2, z_inv);
    vli_modMult_fast(x, p1_x, z_inv2);

    uECC_word_t x_mod_n[uECC_WORDS];
    uECC_word_t x_wide[uECC_WORDS * 2];
    vli_set(x_wide, x);
    vli_clear(x_wide + uECC_WORDS);
    vli_mmod_n(x_mod_n, x_wide);

    return (vli_cmp(x_mod_n, r) == 0);
}
