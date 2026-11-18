"""
ML-DSA-44 (FIPS 204 / CRYSTALS-Dilithium-2) Pure Python Implementation.
Fully interoperable with the QSAC firmware C implementation.
"""

import hashlib
import os
import struct

DILITHIUM_K = 4
DILITHIUM_L = 4
DILITHIUM_N = 256
DILITHIUM_Q = 8380417
DILITHIUM_D = 13
DILITHIUM_ROOT_OF_UNITY = 1753

DILITHIUM_SEEDBYTES = 32
DILITHIUM_CRHBYTES = 64
DILITHIUM_TRBYTES = 64
DILITHIUM_RNDBYTES = 32

DILITHIUM_GAMMA1 = 1 << 17
DILITHIUM_GAMMA2 = (DILITHIUM_Q - 1) // 88  # 95232
DILITHIUM_BETA = 78
DILITHIUM_ETA = 2
DILITHIUM_TAU = 39
DILITHIUM_OMEGA = 80

DILITHIUM_POLYT1_PACKEDBYTES = 320
DILITHIUM_POLYT0_PACKEDBYTES = 416
DILITHIUM_POLYVECH_PACKEDBYTES = DILITHIUM_OMEGA + DILITHIUM_K
DILITHIUM_POLYZ_PACKEDBYTES = 576
DILITHIUM_POLYW1_PACKEDBYTES = 192
DILITHIUM_POLYETA_PACKEDBYTES = 96

DILITHIUM_PUBLICKEYBYTES = DILITHIUM_SEEDBYTES + DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES
DILITHIUM_SECRETKEYBYTES = (2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES +
                            DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES +
                            DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES +
                            DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES)
DILITHIUM_SIGNATUREBYTES = (DILITHIUM_SEEDBYTES +
                            DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES +
                            DILITHIUM_POLYVECH_PACKEDBYTES)

QINV = 58728449  # q^-1 mod 2^32
MONT = -4186625  # 2^32 mod q
R = (1 << 32) % DILITHIUM_Q

def bitrev8(n: int) -> int:
    res = 0
    for i in range(8):
        res = (res << 1) | ((n >> i) & 1)
    return res

DILITHIUM_ZETAS = [0] * 256
DILITHIUM_ZETAS_INV = [0] * 256
for i in range(256):
    br = bitrev8(i)
    z = pow(DILITHIUM_ROOT_OF_UNITY, br, DILITHIUM_Q)
    z_inv = pow(z, -1, DILITHIUM_Q)
    mz = (z * R) % DILITHIUM_Q
    if mz > DILITHIUM_Q // 2:
        mz -= DILITHIUM_Q
    mz_inv = (z_inv * R) % DILITHIUM_Q
    if mz_inv > DILITHIUM_Q // 2:
        mz_inv -= DILITHIUM_Q
    DILITHIUM_ZETAS[i] = mz
    DILITHIUM_ZETAS_INV[i] = mz_inv

def montgomery_reduce(a: int) -> int:
    t = (a * QINV) & 0xFFFFFFFF
    if t >= 0x80000000:
        t -= 0x100000000
    u = t * DILITHIUM_Q
    return (a - u) >> 32

def reduce32(a: int) -> int:
    t = (a + (1 << 22)) >> 23
    return a - t * DILITHIUM_Q

def csubq(a: int) -> int:
    a -= DILITHIUM_Q
    a += ((a >> 31) & DILITHIUM_Q)
    return a

def caddq(a: int) -> int:
    return a + ((a >> 31) & DILITHIUM_Q)

def ntt(p: list[int]) -> list[int]:
    r = list(p)
    k = 1
    length = 128
    while length >= 1:
        start = 0
        while start < 256:
            zeta = DILITHIUM_ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = montgomery_reduce(zeta * r[j + length])
                r[j + length] = r[j] - t
                r[j] = r[j] + t
            start += 2 * length
        length >>= 1
    return r

def invntt_tomont(p: list[int]) -> list[int]:
    r = list(p)
    length = 1
    while length <= 128:
        k = 128 // length
        start = 0
        while start < 256:
            zeta_inv = DILITHIUM_ZETAS_INV[k]
            k += 1
            for j in range(start, start + length):
                t = r[j]
                r[j] = t + r[j + length]
                r[j + length] = montgomery_reduce(zeta_inv * (t - r[j + length]))
            start += 2 * length
        length <<= 1
    f = 41978  # (256^-1 * R^2) mod q
    return [montgomery_reduce(x * f) for x in r]

def poly_pointwise_montgomery(a: list[int], b: list[int]) -> list[int]:
    return [montgomery_reduce(a[i] * b[i]) for i in range(256)]

def power2round(a: int) -> tuple[int, int]:
    a1 = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D
    a0 = a - (a1 << DILITHIUM_D)
    return a0, a1

def decompose(a: int) -> tuple[int, int]:
    a1 = (a + 127) >> 7
    a1 = (a1 * 11275 + (1 << 23)) >> 24
    a1 ^= ((43 - a1) >> 31) & a1
    a0 = a - a1 * 2 * DILITHIUM_GAMMA2
    a0 -= (((DILITHIUM_Q // 2 - a0) >> 31) & DILITHIUM_Q)
    return a0, a1

def make_hint(a0: int, a1: int) -> int:
    val = (a0 + a1 * 2 * DILITHIUM_GAMMA2) % DILITHIUM_Q
    if val < 0:
        val += DILITHIUM_Q
    t0, t1 = decompose(val)
    return 1 if t1 != a1 else 0

def use_hint(a: int, hint: int) -> int:
    a0, a1 = decompose(a)
    if hint == 0:
        return a1
    if a0 > 0:
        if a1 == (DILITHIUM_Q - 1) // (2 * DILITHIUM_GAMMA2) - 1:
            return 0
        else:
            return a1 + 1
    else:
        if a1 == 0:
            return (DILITHIUM_Q - 1) // (2 * DILITHIUM_GAMMA2) - 1
        else:
            return a1 - 1

def chknorm(poly_coeffs: list[int], B: int) -> int:
    if B > (DILITHIUM_Q - 1) // 8:
        return 1
    for x in poly_coeffs:
        t = x >> 31
        t = x - (t & (2 * x))
        if t >= B:
            return 1
    return 0

def rej_uniform(seed: bytes, nonce: int) -> list[int]:
    extseed = seed + struct.pack('<H', nonce)
    buf_len = 840  # 5 * 168
    buf = hashlib.shake_128(extseed).digest(buf_len)
    pos = 0
    r = []
    while len(r) < 256:
        if pos + 3 > len(buf):
            buf_len += 336
            buf = hashlib.shake_128(extseed).digest(buf_len)
        t = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16)
        pos += 3
        t &= 0x7FFFFF
        if t < DILITHIUM_Q:
            r.append(t)
    return r

def rej_eta(seed: bytes, nonce: int) -> list[int]:
    extseed = seed + struct.pack('<H', nonce)
    buf_len = 272  # 2 * 136
    buf = hashlib.shake_256(extseed).digest(buf_len)
    pos = 0
    r = []
    while len(r) < 256:
        if pos >= len(buf):
            buf_len += 136
            buf = hashlib.shake_256(extseed).digest(buf_len)
        b = buf[pos]
        pos += 1
        t0 = b & 0x0F
        t1 = b >> 4
        if t0 < 15:
            t = t0 - ((205 * t0) >> 10) * 5
            r.append(2 - t)
        if len(r) < 256 and t1 < 15:
            t = t1 - ((205 * t1) >> 10) * 5
            r.append(2 - t)
    return r

def polyz_unpack(buf: bytes) -> list[int]:
    r = [0] * 256
    for i in range(64):
        b = buf[9 * i: 9 * i + 9]
        c0 = ((b[0] >> 0) | (b[1] << 8) | (b[2] << 16)) & 0x3FFFF
        c1 = ((b[2] >> 2) | (b[3] << 6) | (b[4] << 14)) & 0x3FFFF
        c2 = ((b[4] >> 4) | (b[5] << 4) | (b[6] << 12)) & 0x3FFFF
        c3 = ((b[6] >> 6) | (b[7] << 2) | (b[8] << 10)) & 0x3FFFF
        r[4 * i + 0] = DILITHIUM_GAMMA1 - c0
        r[4 * i + 1] = DILITHIUM_GAMMA1 - c1
        r[4 * i + 2] = DILITHIUM_GAMMA1 - c2
        r[4 * i + 3] = DILITHIUM_GAMMA1 - c3
    return r

def poly_challenge(seed: bytes) -> list[int]:
    buf_len = 136
    buf = hashlib.shake_256(seed).digest(buf_len)
    signs = struct.unpack('<Q', buf[:8])[0]
    pos = 8
    c = [0] * 256
    for i in range(256 - DILITHIUM_TAU, 256):
        while True:
            if pos >= len(buf):
                buf_len += 136
                buf = hashlib.shake_256(seed).digest(buf_len)
            b = buf[pos]
            pos += 1
            if b <= i:
                break
        c[i] = c[b]
        c[b] = 1 - 2 * (signs & 1)
        signs >>= 1
    return c

def polyt1_pack(p: list[int]) -> bytes:
    r = bytearray(320)
    for i in range(64):
        c = [p[4 * i + j] for j in range(4)]
        r[5 * i + 0] = (c[0] >> 0) & 0xFF
        r[5 * i + 1] = ((c[0] >> 8) | (c[1] << 2)) & 0xFF
        r[5 * i + 2] = ((c[1] >> 6) | (c[2] << 4)) & 0xFF
        r[5 * i + 3] = ((c[2] >> 4) | (c[3] << 6)) & 0xFF
        r[5 * i + 4] = (c[3] >> 2) & 0xFF
    return bytes(r)

def polyt1_unpack(buf: bytes) -> list[int]:
    r = [0] * 256
    for i in range(64):
        b = buf[5 * i: 5 * i + 5]
        r[4 * i + 0] = (b[0] | (b[1] << 8)) & 0x3FF
        r[4 * i + 1] = ((b[1] >> 2) | (b[2] << 6)) & 0x3FF
        r[4 * i + 2] = ((b[2] >> 4) | (b[3] << 4)) & 0x3FF
        r[4 * i + 3] = ((b[3] >> 6) | (b[4] << 2)) & 0x3FF
    return r

def polyt0_pack(p: list[int]) -> bytes:
    r = bytearray(416)
    for i in range(32):
        t = [(1 << (DILITHIUM_D - 1)) - p[8 * i + j] for j in range(8)]
        r[13 * i +  0] = (t[0] >> 0) & 0xFF
        r[13 * i +  1] = ((t[0] >> 8) | (t[1] << 5)) & 0xFF
        r[13 * i +  2] = (t[1] >> 3) & 0xFF
        r[13 * i +  3] = ((t[1] >> 11) | (t[2] << 2)) & 0xFF
        r[13 * i +  4] = ((t[2] >> 6) | (t[3] << 7)) & 0xFF
        r[13 * i +  5] = (t[3] >> 1) & 0xFF
        r[13 * i +  6] = ((t[3] >> 9) | (t[4] << 4)) & 0xFF
        r[13 * i +  7] = (t[4] >> 4) & 0xFF
        r[13 * i +  8] = ((t[4] >> 12) | (t[5] << 1)) & 0xFF
        r[13 * i +  9] = ((t[5] >> 7) | (t[6] << 6)) & 0xFF
        r[13 * i + 10] = (t[6] >> 2) & 0xFF
        r[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)) & 0xFF
        r[13 * i + 12] = (t[7] >> 5) & 0xFF
    return bytes(r)

def polyt0_unpack(buf: bytes) -> list[int]:
    r = [0] * 256
    for i in range(32):
        b = buf[13 * i: 13 * i + 13]
        t = [
            (b[0] | (b[1] << 8)) & 0x1FFF,
            ((b[1] >> 5) | (b[2] << 3) | (b[3] << 11)) & 0x1FFF,
            ((b[3] >> 2) | (b[4] << 6)) & 0x1FFF,
            ((b[4] >> 7) | (b[5] << 1) | (b[6] << 9)) & 0x1FFF,
            ((b[6] >> 4) | (b[7] << 4) | (b[8] << 12)) & 0x1FFF,
            ((b[8] >> 1) | (b[9] << 7)) & 0x1FFF,
            ((b[9] >> 6) | (b[10] << 2) | (b[11] << 10)) & 0x1FFF,
            ((b[11] >> 3) | (b[12] << 5)) & 0x1FFF
        ]
        for j in range(8):
            r[8 * i + j] = (1 << (DILITHIUM_D - 1)) - t[j]
    return r

def polyeta_pack(p: list[int]) -> bytes:
    r = bytearray(96)
    for i in range(32):
        t = [2 - p[8 * i + j] for j in range(8)]
        r[3 * i + 0] = (t[0] | (t[1] << 3) | (t[2] << 6)) & 0xFF
        r[3 * i + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) & 0xFF
        r[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) & 0xFF
    return bytes(r)

def polyeta_unpack(buf: bytes) -> list[int]:
    r = [0] * 256
    for i in range(32):
        b = buf[3 * i: 3 * i + 3]
        r[8 * i + 0] = 2 - ((b[0] >> 0) & 7)
        r[8 * i + 1] = 2 - ((b[0] >> 3) & 7)
        r[8 * i + 2] = 2 - (((b[0] >> 6) | (b[1] << 2)) & 7)
        r[8 * i + 3] = 2 - ((b[1] >> 1) & 7)
        r[8 * i + 4] = 2 - ((b[1] >> 4) & 7)
        r[8 * i + 5] = 2 - (((b[1] >> 7) | (b[2] << 1)) & 7)
        r[8 * i + 6] = 2 - ((b[2] >> 2) & 7)
        r[8 * i + 7] = 2 - ((b[2] >> 5) & 7)
    return r

def polyz_pack(p: list[int]) -> bytes:
    r = bytearray(576)
    for i in range(64):
        t = [DILITHIUM_GAMMA1 - p[4 * i + j] for j in range(4)]
        r[9 * i + 0] = (t[0] >> 0) & 0xFF
        r[9 * i + 1] = (t[0] >> 8) & 0xFF
        r[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) & 0xFF
        r[9 * i + 3] = (t[1] >> 6) & 0xFF
        r[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) & 0xFF
        r[9 * i + 5] = (t[2] >> 4) & 0xFF
        r[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) & 0xFF
        r[9 * i + 7] = (t[3] >> 2) & 0xFF
        r[9 * i + 8] = (t[3] >> 10) & 0xFF
    return bytes(r)

def polyw1_pack(p: list[int]) -> bytes:
    r = bytearray(192)
    for i in range(64):
        c = [p[4 * i + j] for j in range(4)]
        r[3 * i + 0] = (c[0] | (c[1] << 6)) & 0xFF
        r[3 * i + 1] = ((c[1] >> 2) | (c[2] << 4)) & 0xFF
        r[3 * i + 2] = ((c[2] >> 4) | (c[3] << 2)) & 0xFF
    return bytes(r)

def pack_pk(rho: bytes, t1: list[list[int]]) -> bytes:
    return rho + b''.join(polyt1_pack(t1[i]) for i in range(DILITHIUM_K))

def unpack_pk(pk: bytes) -> tuple[bytes, list[list[int]]]:
    rho = pk[:32]
    t1 = [polyt1_unpack(pk[32 + i * 320: 32 + (i + 1) * 320]) for i in range(DILITHIUM_K)]
    return rho, t1

def pack_sk(rho: bytes, tr: bytes, key: bytes, t0: list[list[int]], s1: list[list[int]], s2: list[list[int]]) -> bytes:
    res = rho + key + tr
    for i in range(DILITHIUM_L):
        res += polyeta_pack(s1[i])
    for i in range(DILITHIUM_K):
        res += polyeta_pack(s2[i])
    for i in range(DILITHIUM_K):
        res += polyt0_pack(t0[i])
    return res

def unpack_sk(sk: bytes):
    offset = 0
    rho = sk[offset: offset + 32]
    offset += 32
    key = sk[offset: offset + 32]
    offset += 32
    tr = sk[offset: offset + 64]
    offset += 64
    s1 = []
    for _ in range(DILITHIUM_L):
        s1.append(polyeta_unpack(sk[offset: offset + 96]))
        offset += 96
    s2 = []
    for _ in range(DILITHIUM_K):
        s2.append(polyeta_unpack(sk[offset: offset + 96]))
        offset += 96
    t0 = []
    for _ in range(DILITHIUM_K):
        t0.append(polyt0_unpack(sk[offset: offset + 416]))
        offset += 416
    return rho, tr, key, t0, s1, s2

def pack_sig(c: bytes, z: list[list[int]], h: list[list[int]]) -> bytes:
    sig = bytearray(c)
    for i in range(DILITHIUM_L):
        sig += polyz_pack(z[i])
    sig_h = bytearray(DILITHIUM_OMEGA + DILITHIUM_K)
    k = 0
    for i in range(DILITHIUM_K):
        for j in range(256):
            if h[i][j] != 0:
                sig_h[k] = j
                k += 1
        sig_h[DILITHIUM_OMEGA + i] = k
    return bytes(sig + sig_h)

def unpack_sig(sig: bytes):
    c = sig[:32]
    offset = 32
    z = []
    for _ in range(DILITHIUM_L):
        z.append(polyz_unpack(sig[offset: offset + 576]))
        offset += 576
    sig_h = sig[offset:]
    h = [[0] * 256 for _ in range(DILITHIUM_K)]
    k = 0
    for i in range(DILITHIUM_K):
        if sig_h[DILITHIUM_OMEGA + i] < k or sig_h[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA:
            return None
        for j in range(k, sig_h[DILITHIUM_OMEGA + i]):
            if j > k and sig_h[j] <= sig_h[j - 1]:
                return None
            h[i][sig_h[j]] = 1
        k = sig_h[DILITHIUM_OMEGA + i]
    for j in range(k, DILITHIUM_OMEGA):
        if sig_h[j] != 0:
            return None
    return c, z, h

def expand_matrix(rho: bytes) -> list[list[list[int]]]:
    mat = [[None for _ in range(DILITHIUM_L)] for _ in range(DILITHIUM_K)]
    for i in range(DILITHIUM_K):
        for j in range(DILITHIUM_L):
            mat[i][j] = rej_uniform(rho, (i << 8) + j)
    return mat

# ──────────────────────────────────────────────
# Public API: KeyGen, Sign, Verify
# ──────────────────────────────────────────────

def mldsa44_keypair() -> tuple[bytes, bytes]:
    """Generates an ML-DSA-44 keypair (pk, sk)."""
    seedbuf = hashlib.shake_256(os.urandom(32)).digest(2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES)
    rho = seedbuf[:32]
    rhoprime = seedbuf[32: 32 + 64]
    key = seedbuf[32 + 64:]

    mat = expand_matrix(rho)

    s1 = [rej_eta(rhoprime, i) for i in range(DILITHIUM_L)]
    s2 = [rej_eta(rhoprime, DILITHIUM_L + i) for i in range(DILITHIUM_K)]

    s1_ntt = [ntt(p) for p in s1]

    t1 = []
    t0 = []
    for i in range(DILITHIUM_K):
        acc = [0] * 256
        for j in range(DILITHIUM_L):
            prod = poly_pointwise_montgomery(mat[i][j], s1_ntt[j])
            acc = [acc[k] + prod[k] for k in range(256)]
        acc = [reduce32(x) for x in acc]
        acc_inv = invntt_tomont(acc)
        acc_sum = [caddq(acc_inv[k] + s2[i][k]) for k in range(256)]
        t1_i = [0] * 256
        t0_i = [0] * 256
        for k in range(256):
            t0_i[k], t1_i[k] = power2round(acc_sum[k])
        t1.append(t1_i)
        t0.append(t0_i)

    pk = pack_pk(rho, t1)
    tr = hashlib.shake_256(pk).digest(DILITHIUM_TRBYTES)
    sk = pack_sk(rho, tr, key, t0, s1, s2)
    return pk, sk

def mldsa44_sign(sk: bytes, msg: bytes) -> bytes:
    """Signs a message using ML-DSA-44 private key."""
    rho, tr, key, t0, s1, s2 = unpack_sk(sk)

    mu = hashlib.shake_256(tr + msg).digest(DILITHIUM_CRHBYTES)
    rhoprime = hashlib.shake_256(key + mu).digest(DILITHIUM_CRHBYTES)

    mat = expand_matrix(rho)
    s1_ntt = [ntt(p) for p in s1]
    s2_ntt = [ntt(p) for p in s2]
    t0_ntt = [ntt(p) for p in t0]

    nonce = 0
    while True:
        y = []
        for i in range(DILITHIUM_L):
            buf = hashlib.shake_256(rhoprime + struct.pack('<H', DILITHIUM_L * nonce + i)).digest(576)
            y.append(polyz_unpack(buf))
        nonce += 1

        y_ntt = [ntt(p) for p in y]

        w1_packed = bytearray()
        w1_decomp = []
        w0_decomp = []
        for i in range(DILITHIUM_K):
            acc = [0] * 256
            for j in range(DILITHIUM_L):
                prod = poly_pointwise_montgomery(mat[i][j], y_ntt[j])
                acc = [acc[k] + prod[k] for k in range(256)]
            acc = [reduce32(x) for x in acc]
            acc_inv = invntt_tomont(acc)
            acc_cadd = [caddq(x) for x in acc_inv]
            w1_i = [0] * 256
            w0_i = [0] * 256
            for k in range(256):
                w0_i[k], w1_i[k] = decompose(acc_cadd[k])
            w1_decomp.append(w1_i)
            w0_decomp.append(w0_i)
            w1_packed += polyw1_pack(w1_i)

        c = hashlib.shake_256(mu + bytes(w1_packed)).digest(32)
        cp = poly_challenge(c)
        cp_ntt = ntt(cp)

        # z = y + c * s1
        z = []
        rej = False
        for i in range(DILITHIUM_L):
            prod = poly_pointwise_montgomery(cp_ntt, s1_ntt[i])
            prod_inv = invntt_tomont(prod)
            z_i = [reduce32(prod_inv[k] + y[i][k]) for k in range(256)]
            if chknorm(z_i, DILITHIUM_GAMMA1 - DILITHIUM_BETA):
                rej = True
                break
            z.append(z_i)
        if rej:
            continue

        # Check norm of w0 - c*s2
        w0_sub = []
        for i in range(DILITHIUM_K):
            prod = poly_pointwise_montgomery(cp_ntt, s2_ntt[i])
            prod_inv = invntt_tomont(prod)
            w0_i = [reduce32(w0_decomp[i][k] - prod_inv[k]) for k in range(256)]
            if chknorm(w0_i, DILITHIUM_GAMMA2 - DILITHIUM_BETA):
                rej = True
                break
            w0_sub.append(w0_i)
        if rej:
            continue

        # Compute hint
        h = []
        n_hints = 0
        for i in range(DILITHIUM_K):
            prod = poly_pointwise_montgomery(cp_ntt, t0_ntt[i])
            prod_inv = invntt_tomont(prod)
            h_i = [reduce32(prod_inv[k]) for k in range(256)]
            if chknorm(h_i, DILITHIUM_GAMMA2):
                rej = True
                break
            w0_add = [caddq(w0_sub[i][k] + h_i[k]) for k in range(256)]
            hint_poly = [make_hint(w0_add[k], w1_decomp[i][k]) for k in range(256)]
            n_hints += sum(hint_poly)
            h.append(hint_poly)
        if rej or n_hints > DILITHIUM_OMEGA:
            continue

        return pack_sig(c, z, h)

def mldsa44_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verifies an ML-DSA-44 signature against public key."""
    if len(sig) != DILITHIUM_SIGNATUREBYTES or len(pk) != DILITHIUM_PUBLICKEYBYTES:
        return False

    rho, t1 = unpack_pk(pk)
    unpacked = unpack_sig(sig)
    if unpacked is None:
        return False
    c, z, h = unpacked

    for i in range(DILITHIUM_L):
        if chknorm(z[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA):
            return False

    mu = hashlib.shake_256(hashlib.shake_256(pk).digest(DILITHIUM_TRBYTES) + msg).digest(DILITHIUM_CRHBYTES)
    cp = poly_challenge(c)
    mat = expand_matrix(rho)

    z_ntt = [ntt(p) for p in z]
    cp_ntt = ntt(cp)

    w1_packed = bytearray()
    for i in range(DILITHIUM_K):
        acc = [0] * 256
        for j in range(DILITHIUM_L):
            prod = poly_pointwise_montgomery(mat[i][j], z_ntt[j])
            acc = [acc[k] + prod[k] for k in range(256)]
        t1_shift = [(t1[i][k] << DILITHIUM_D) for k in range(256)]
        t1_ntt = ntt(t1_shift)
        t1_prod = poly_pointwise_montgomery(cp_ntt, t1_ntt)
        acc_sub = [reduce32(acc[k] - t1_prod[k]) for k in range(256)]
        acc_inv = invntt_tomont(acc_sub)
        acc_cadd = [caddq(x) for x in acc_inv]
        w1_i = [use_hint(acc_cadd[k], h[i][k]) for k in range(256)]
        w1_packed += polyw1_pack(w1_i)

    c2 = hashlib.shake_256(mu + bytes(w1_packed)).digest(32)
    return c == c2
