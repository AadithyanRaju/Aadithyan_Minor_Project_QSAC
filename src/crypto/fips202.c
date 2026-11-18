/**
 * @file fips202.c
 * @brief Standard FIPS 202 implementation of SHAKE128, SHAKE256, SHA3-256, SHA3-512.
 */

#include "fips202.h"
#include <string.h>

#define NROUNDS 24

static inline __attribute__((always_inline)) uint64_t ROL64(uint64_t a, unsigned int offset) {
    if (offset == 0) return a;
    uint32_t low = (uint32_t)a;
    uint32_t high = (uint32_t)(a >> 32);
    if (offset == 32) {
        return (((uint64_t)low) << 32) | (uint64_t)high;
    } else if (offset < 32) {
        uint32_t nlow = (low << offset) | (high >> (32 - offset));
        uint32_t nhigh = (high << offset) | (low >> (32 - offset));
        return (((uint64_t)nhigh) << 32) | (uint64_t)nlow;
    } else {
        unsigned int k = offset - 32;
        uint32_t nlow = (high << k) | (low >> (32 - k));
        uint32_t nhigh = (low << k) | (high >> (32 - k));
        return (((uint64_t)nhigh) << 32) | (uint64_t)nlow;
    }
}
#define ROL(a, offset) ROL64((a), (offset))

static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static void __attribute__((optimize("O3"))) KeccakF1600_StatePermute(uint64_t state[25]) {
    int round;
    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    Aba = state[ 0]; Abe = state[ 1]; Abi = state[ 2]; Abo = state[ 3]; Abu = state[ 4];
    Aga = state[ 5]; Age = state[ 6]; Agi = state[ 7]; Ago = state[ 8]; Agu = state[ 9];
    Aka = state[10]; Ake = state[11]; Aki = state[12]; Ako = state[13]; Aku = state[14];
    Ama = state[15]; Ame = state[16]; Ami = state[17]; Amo = state[18]; Amu = state[19];
    Asa = state[20]; Ase = state[21]; Asi = state[22]; Aso = state[23]; Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2) {
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da; BCa = Aba;
        Age ^= De; BCe = ROL(Age, 44);
        Aki ^= Di; BCi = ROL(Aki, 43);
        Amo ^= Do; BCo = ROL(Amo, 21);
        Asu ^= Du; BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi); Eba ^= KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do; BCa = ROL(Abo, 28);
        Agu ^= Du; BCe = ROL(Agu, 20);
        Aka ^= Da; BCi = ROL(Aka, 3);
        Ame ^= De; BCo = ROL(Ame, 45);
        Asi ^= Di; BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De; BCa = ROL(Abe, 1);
        Agi ^= Di; BCe = ROL(Agi, 6);
        Ako ^= Do; BCi = ROL(Ako, 25);
        Amu ^= Du; BCo = ROL(Amu, 8);
        Asa ^= Da; BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du; BCa = ROL(Abu, 27);
        Aga ^= Da; BCe = ROL(Aga, 36);
        Ake ^= De; BCi = ROL(Ake, 10);
        Ami ^= Di; BCo = ROL(Ami, 15);
        Aso ^= Do; BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di; BCa = ROL(Abi, 62);
        Ago ^= Do; BCe = ROL(Ago, 55);
        Aku ^= Du; BCi = ROL(Aku, 39);
        Ama ^= Da; BCo = ROL(Ama, 41);
        Ase ^= De; BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        /* Round 2 */
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da; BCa = Eba;
        Ege ^= De; BCe = ROL(Ege, 44);
        Eki ^= Di; BCi = ROL(Eki, 43);
        Emo ^= Do; BCo = ROL(Emo, 21);
        Esu ^= Du; BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi); Aba ^= KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do; BCa = ROL(Ebo, 28);
        Egu ^= Du; BCe = ROL(Egu, 20);
        Eka ^= Da; BCi = ROL(Eka, 3);
        Eme ^= De; BCo = ROL(Eme, 45);
        Esi ^= Di; BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De; BCa = ROL(Ebe, 1);
        Egi ^= Di; BCe = ROL(Egi, 6);
        Eko ^= Do; BCi = ROL(Eko, 25);
        Emu ^= Du; BCo = ROL(Emu, 8);
        Esa ^= Da; BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du; BCa = ROL(Ebu, 27);
        Ega ^= Da; BCe = ROL(Ega, 36);
        Eke ^= De; BCi = ROL(Eke, 10);
        Emi ^= Di; BCo = ROL(Emi, 15);
        Eso ^= Do; BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di; BCa = ROL(Ebi, 62);
        Ego ^= Do; BCe = ROL(Ego, 55);
        Eku ^= Du; BCi = ROL(Eku, 39);
        Ema ^= Da; BCo = ROL(Ema, 41);
        Ese ^= De; BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    state[ 0] = Aba; state[ 1] = Abe; state[ 2] = Abi; state[ 3] = Abo; state[ 4] = Abu;
    state[ 5] = Aga; state[ 6] = Age; state[ 7] = Agi; state[ 8] = Ago; state[ 9] = Agu;
    state[10] = Aka; state[11] = Ake; state[12] = Aki; state[13] = Ako; state[14] = Aku;
    state[15] = Ama; state[16] = Ame; state[17] = Ami; state[18] = Amo; state[19] = Amu;
    state[20] = Asa; state[21] = Ase; state[22] = Asi; state[23] = Aso; state[24] = Asu;
}

static void keccak_absorb(uint64_t s[25], size_t r, const uint8_t *m, size_t mlen, uint8_t p) {
    uint8_t *s_bytes = (uint8_t *)s;
    while (mlen >= r) {
        for (size_t i = 0; i < r; ++i) {
            s_bytes[i] ^= m[i];
        }
        KeccakF1600_StatePermute(s);
        mlen -= r;
        m += r;
    }

    for (size_t i = 0; i < mlen; ++i) {
        s_bytes[i] ^= m[i];
    }
    s_bytes[mlen] ^= p;
    s_bytes[r - 1] ^= 0x80;
}

static void keccak_squeezeblocks(uint8_t *h, size_t nblocks, uint64_t s[25], size_t r) {
    const uint8_t *s_bytes = (const uint8_t *)s;
    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        memcpy(h, s_bytes, r);
        h += r;
        nblocks--;
    }
}

static void keccak_inc_init(uint64_t s[25]) {
    memset(s, 0, 25 * sizeof(uint64_t));
}

static void keccak_inc_absorb(uint64_t s[25], size_t *pos, size_t r, const uint8_t *m, size_t mlen) {
    uint8_t *s_bytes = (uint8_t *)s;
    while (mlen > 0) {
        if (*pos == 0 && mlen >= r) {
            for (size_t i = 0; i < r; ++i) {
                s_bytes[i] ^= m[i];
            }
            KeccakF1600_StatePermute(s);
            mlen -= r;
            m += r;
        } else {
            size_t take = (mlen < (r - *pos)) ? mlen : (r - *pos);
            for (size_t i = 0; i < take; ++i) {
                s_bytes[*pos + i] ^= m[i];
            }
            *pos += take;
            m += take;
            mlen -= take;
            if (*pos == r) {
                KeccakF1600_StatePermute(s);
                *pos = 0;
            }
        }
    }
}

static void keccak_inc_finalize(uint64_t s[25], size_t pos, size_t r, uint8_t p) {
    uint8_t *s_bytes = (uint8_t *)s;
    s_bytes[pos] ^= p;
    s_bytes[r - 1] ^= 0x80;
}

static void keccak_inc_squeeze(uint8_t *h, size_t outlen, uint64_t s[25], size_t *pos, size_t r) {
    const uint8_t *s_bytes = (const uint8_t *)s;
    while (outlen > 0) {
        if (*pos == r) {
            KeccakF1600_StatePermute(s);
            *pos = 0;
        }
        size_t take = (outlen < (r - *pos)) ? outlen : (r - *pos);
        memcpy(h, s_bytes + *pos, take);
        *pos += take;
        h += take;
        outlen -= take;
    }
}

/* Incremental SHAKE128 */
void shake128_inc_init(shake128incctx *state) {
    keccak_inc_init(state->s);
    state->pos = 0;
}

void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->s, &state->pos, SHAKE128_RATE, input, inlen);
}

void shake128_inc_finalize(shake128incctx *state) {
    keccak_inc_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
    state->pos = SHAKE128_RATE;
}

void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state) {
    keccak_inc_squeeze(output, outlen, state->s, &state->pos, SHAKE128_RATE);
}

/* Incremental SHAKE256 */
void shake256_inc_init(shake256incctx *state) {
    keccak_inc_init(state->s);
    state->pos = 0;
}

void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->s, &state->pos, SHAKE256_RATE, input, inlen);
}

void shake256_inc_finalize(shake256incctx *state) {
    keccak_inc_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
    state->pos = SHAKE256_RATE;
}

void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state) {
    keccak_inc_squeeze(output, outlen, state->s, &state->pos, SHAKE256_RATE);
}

/* Block-based SHAKE128 */
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_init(state->s);
    keccak_absorb(state->s, SHAKE128_RATE, input, inlen, 0x1F);
    state->pos = SHAKE128_RATE;
}

void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state) {
    keccak_squeezeblocks(output, nblocks, state->s, SHAKE128_RATE);
}

/* Block-based SHAKE256 */
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_init(state->s);
    keccak_absorb(state->s, SHAKE256_RATE, input, inlen, 0x1F);
    state->pos = SHAKE256_RATE;
}

void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state) {
    keccak_squeezeblocks(output, nblocks, state->s, SHAKE256_RATE);
}

/* One-shot SHAKE */
void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    shake128incctx ctx;
    shake128_inc_init(&ctx);
    shake128_inc_absorb(&ctx, input, inlen);
    shake128_inc_finalize(&ctx);
    shake128_inc_squeeze(output, outlen, &ctx);
}

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, input, inlen);
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(output, outlen, &ctx);
}

/* One-shot SHA3 */
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen) {
    uint64_t s[25];
    keccak_inc_init(s);
    keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    memcpy(output, s, 32);
}

void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen) {
    uint64_t s[25];
    keccak_inc_init(s);
    keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    memcpy(output, s, 64);
}
