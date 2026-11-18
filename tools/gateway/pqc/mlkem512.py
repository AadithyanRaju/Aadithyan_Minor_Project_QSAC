"""
ML-KEM-512 (FIPS 203 / CRYSTALS-Kyber-512) Pure Python Implementation.
Fully interoperable with the QSAC firmware C implementation.
"""

import hashlib
import os
import struct

KYBER_K = 2
KYBER_N = 256
KYBER_Q = 3329
KYBER_ETA1 = 3
KYBER_ETA2 = 2
KYBER_DU = 10
KYBER_DV = 4
KYBER_SYMBYTES = 32
KYBER_SSBYTES = 32
KYBER_POLYBYTES = 384
KYBER_POLYVECBYTES = KYBER_K * KYBER_POLYBYTES
KYBER_POLYVECCOMPRESSEDBYTES_DU = KYBER_K * 320
KYBER_POLYCOMPRESSEDBYTES_DV = 128
KYBER_INDCPA_PUBLICKEYBYTES = KYBER_POLYVECBYTES + KYBER_SYMBYTES
KYBER_INDCPA_SECRETKEYBYTES = KYBER_POLYVECBYTES
KYBER_INDCPA_BYTES = KYBER_POLYVECCOMPRESSEDBYTES_DU + KYBER_POLYCOMPRESSEDBYTES_DV
KYBER_PUBLICKEYBYTES = KYBER_INDCPA_PUBLICKEYBYTES
KYBER_SECRETKEYBYTES = KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES
KYBER_CIPHERTEXTBYTES = KYBER_INDCPA_BYTES

MONT = -1044  # 2^16 mod q
QINV = -3327  # q^-1 mod 2^16

KYBER_ZETAS = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
]

KYBER_ZETAS_INV = [
    -1044, 758, 1517, 359, -202, -287, -1422, -1493,
    -1468, 1474, 1202, -962, -182, -1577, -622, 171,
    1571, 205, -411, 1542, -608, -732, -1017, 681,
    130, 1602, -1458, 829, -383, -264, 1325, -573,
    1275, -677, 1065, -448, 725, 1508, -961, 398,
    951, 247, 1421, -107, -830, 271, 90, 853,
    -1469, -126, 1162, 1618, 666, 320, 8, -516,
    1544, 282, -1491, 1293, -1015, 552, -652, -1223,
    -1628, -1522, 1460, -958, -991, -996, 308, 108,
    -478, 870, 854, 1510, -794, 1278, 1530, 1185,
    1659, 1187, -220, 874, 1335, -1218, 136, 1215,
    -384, 1465, 1285, -1322, -610, -603, -1097, -817,
    75, 156, -329, -418, -349, 872, -644, 1590,
    -1119, 602, -1483, 777, 147, -1159, -778, 246,
    -1653, -1574, 460, 291, 235, -177, -587, -422,
    -105, -1550, -871, 1251, -843, -555, -430, 1103
]

def montgomery_reduce(a: int) -> int:
    t = (a * QINV) & 0xFFFF
    if t >= 0x8000:
        t -= 0x10000
    u = t * KYBER_Q
    return (a - u) >> 16

def barrett_reduce(a: int) -> int:
    v = ((1 << 26) + KYBER_Q // 2) // KYBER_Q
    t = (v * a + (1 << 25)) >> 26
    return a - t * KYBER_Q

def csubq(a: int) -> int:
    a -= KYBER_Q
    a += ((a >> 15) & KYBER_Q)
    return a

def freeze(a: int) -> int:
    a = barrett_reduce(a)
    a += ((a >> 15) & KYBER_Q)
    return csubq(a)

def ntt(p: list[int]) -> list[int]:
    r = list(p)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = KYBER_ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = montgomery_reduce(zeta * r[j + length])
                r[j + length] = r[j] - t
                r[j] = r[j] + t
            start += 2 * length
        length >>= 1
    return [barrett_reduce(x) for x in r]

def invntt(p: list[int]) -> list[int]:
    r = list(p)
    length = 2
    while length <= 128:
        k = 128 // length
        start = 0
        while start < 256:
            zeta_inv = KYBER_ZETAS_INV[k]
            k += 1
            for j in range(start, start + length):
                t = r[j]
                r[j] = barrett_reduce(t + r[j + length])
                r[j + length] = montgomery_reduce(zeta_inv * (t - r[j + length]))
            start += 2 * length
        length <<= 1
    f = 512
    return [montgomery_reduce(x * f) for x in r]

def basemul(a: list[int], b: list[int], zeta: int) -> list[int]:
    t0 = montgomery_reduce(a[1] * b[1])
    t0 = montgomery_reduce(t0 * zeta)
    t0 += montgomery_reduce(a[0] * b[0])

    t1 = montgomery_reduce(a[0] * b[1])
    t1 += montgomery_reduce(a[1] * b[0])
    return [t0, t1]

def poly_basemul(a: list[int], b: list[int]) -> list[int]:
    r = [0] * 256
    for i in range(64):
        r[4 * i: 4 * i + 2] = basemul(a[4 * i: 4 * i + 2], b[4 * i: 4 * i + 2], KYBER_ZETAS[64 + i])
        r[4 * i + 2: 4 * i + 4] = basemul(a[4 * i + 2: 4 * i + 4], b[4 * i + 2: 4 * i + 4], -KYBER_ZETAS[64 + i])
    return r

def poly_tomont(p: list[int]) -> list[int]:
    f = ((1 << 32) % KYBER_Q)
    return [montgomery_reduce(x * f) for x in p]

def cbd2(buf: bytes) -> list[int]:
    r = [0] * 256
    for i in range(32):
        t = struct.unpack('<I', buf[4 * i: 4 * i + 4])[0]
        d = (t & 0x55555555) + ((t >> 1) & 0x55555555)
        for j in range(8):
            a = (d >> (4 * j + 0)) & 0x3
            b = (d >> (4 * j + 2)) & 0x3
            r[8 * i + j] = a - b
    return r

def cbd3(buf: bytes) -> list[int]:
    r = [0] * 256
    for i in range(64):
        b = buf[3 * i: 3 * i + 3]
        t = b[0] | (b[1] << 8) | (b[2] << 16)
        d = (t & 0x00249249) + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249)
        for j in range(4):
            a = (d >> (6 * j + 0)) & 0x7
            b = (d >> (6 * j + 3)) & 0x7
            r[4 * i + j] = a - b
    return r

def poly_getnoise_eta1(seed: bytes, nonce: int) -> list[int]:
    extseed = seed + bytes([nonce])
    buf = hashlib.shake_256(extseed).digest(KYBER_ETA1 * KYBER_N // 4)
    return cbd3(buf)

def poly_getnoise_eta2(seed: bytes, nonce: int) -> list[int]:
    extseed = seed + bytes([nonce])
    buf = hashlib.shake_256(extseed).digest(KYBER_ETA2 * KYBER_N // 4)
    return cbd2(buf)

def gen_matrix(seed: bytes, transposed: bool = False) -> list[list[list[int]]]:
    matrix = [[None for _ in range(KYBER_K)] for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        for j in range(KYBER_K):
            sep = bytes([i, j]) if transposed else bytes([j, i])
            buf_len = 672  # 4 * 168
            buf = hashlib.shake_128(seed + sep).digest(buf_len)
            pos = 0
            r = []
            while len(r) < 256:
                if pos + 3 > len(buf):
                    buf_len += 168
                    buf = hashlib.shake_128(seed + sep).digest(buf_len)
                val0 = (buf[pos] | (buf[pos + 1] << 8)) & 0xFFF
                val1 = ((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF
                pos += 3
                if val0 < KYBER_Q:
                    r.append(val0)
                if len(r) < 256 and val1 < KYBER_Q:
                    r.append(val1)
            matrix[i][j] = r
    return matrix

def poly_compress_dv(p: list[int]) -> bytes:
    r = bytearray(128)
    for i in range(32):
        t = [(((freeze(p[8 * i + j]) << 4) + KYBER_Q // 2) // KYBER_Q) & 15 for j in range(8)]
        r[4 * i + 0] = t[0] | (t[1] << 4)
        r[4 * i + 1] = t[2] | (t[3] << 4)
        r[4 * i + 2] = t[4] | (t[5] << 4)
        r[4 * i + 3] = t[6] | (t[7] << 4)
    return bytes(r)

def poly_decompress_dv(a: bytes) -> list[int]:
    r = [0] * 256
    for i in range(32):
        b = a[4 * i: 4 * i + 4]
        t = [b[0] & 15, b[0] >> 4, b[1] & 15, b[1] >> 4, b[2] & 15, b[2] >> 4, b[3] & 15, b[3] >> 4]
        for j in range(8):
            r[8 * i + j] = (t[j] * KYBER_Q + 8) >> 4
    return r

def polyvec_compress_du(pv: list[list[int]]) -> bytes:
    r = bytearray(KYBER_POLYVECCOMPRESSEDBYTES_DU)
    for i in range(KYBER_K):
        for j in range(64):
            t = [(((freeze(pv[i][4 * j + k]) << 10) + KYBER_Q // 2) // KYBER_Q) & 0x3FF for k in range(4)]
            r[320 * i + 5 * j + 0] = (t[0] >> 0) & 0xFF
            r[320 * i + 5 * j + 1] = ((t[0] >> 8) | (t[1] << 2)) & 0xFF
            r[320 * i + 5 * j + 2] = ((t[1] >> 6) | (t[2] << 4)) & 0xFF
            r[320 * i + 5 * j + 3] = ((t[2] >> 4) | (t[3] << 6)) & 0xFF
            r[320 * i + 5 * j + 4] = (t[3] >> 2) & 0xFF
    return bytes(r)

def polyvec_decompress_du(a: bytes) -> list[list[int]]:
    pv = [[0] * 256 for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        for j in range(64):
            b = a[320 * i + 5 * j: 320 * i + 5 * j + 5]
            t0 = (b[0] | (b[1] << 8)) & 0x3FF
            t1 = ((b[1] >> 2) | (b[2] << 6)) & 0x3FF
            t2 = ((b[2] >> 4) | (b[3] << 4)) & 0x3FF
            t3 = ((b[3] >> 6) | (b[4] << 2)) & 0x3FF
            pv[i][4 * j + 0] = (t0 * KYBER_Q + 512) >> 10
            pv[i][4 * j + 1] = (t1 * KYBER_Q + 512) >> 10
            pv[i][4 * j + 2] = (t2 * KYBER_Q + 512) >> 10
            pv[i][4 * j + 3] = (t3 * KYBER_Q + 512) >> 10
    return pv

def polyvec_tobytes(pv: list[list[int]]) -> bytes:
    r = bytearray()
    for i in range(KYBER_K):
        for j in range(128):
            t0 = freeze(pv[i][2 * j + 0]) & 0xFFF
            t1 = freeze(pv[i][2 * j + 1]) & 0xFFF
            r.append(t0 & 0xFF)
            r.append((t0 >> 8) | ((t1 & 0x0F) << 4))
            r.append((t1 >> 4) & 0xFF)
    return bytes(r)

def polyvec_frombytes(a: bytes) -> list[list[int]]:
    pv = [[0] * 256 for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        for j in range(128):
            b = a[384 * i + 3 * j: 384 * i + 3 * j + 3]
            pv[i][2 * j + 0] = (b[0] | (b[1] << 8)) & 0xFFF
            pv[i][2 * j + 1] = ((b[1] >> 4) | (b[2] << 4)) & 0xFFF
    return pv

def poly_frommsg(msg: bytes) -> list[int]:
    r = [0] * 256
    for i in range(32):
        for j in range(8):
            mask = -((msg[i] >> j) & 1)
            r[8 * i + j] = mask & ((KYBER_Q + 1) // 2)
    return r

def poly_tomsg(p: list[int]) -> bytes:
    msg = bytearray(32)
    for i in range(32):
        for j in range(8):
            t = freeze(p[8 * i + j])
            t = (((t << 1) + KYBER_Q // 2) // KYBER_Q) & 1
            msg[i] |= (t << j)
    return bytes(msg)

def indcpa_keypair(coins: bytes) -> tuple[bytes, bytes]:
    buf = hashlib.sha3_512(coins).digest()
    publicseed = buf[:32]
    noiseseed = buf[32:]

    a = gen_matrix(publicseed, transposed=False)
    skpv = [poly_getnoise_eta1(noiseseed, i) for i in range(KYBER_K)]
    e = [poly_getnoise_eta1(noiseseed, KYBER_K + i) for i in range(KYBER_K)]

    skpv_ntt = [ntt(p) for p in skpv]
    e_ntt = [ntt(p) for p in e]

    pkpv = [[0] * 256 for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        acc = [0] * 256
        for j in range(KYBER_K):
            prod = poly_basemul(a[i][j], skpv_ntt[j])
            acc = [(acc[k] + prod[k]) for k in range(256)]
        acc = poly_tomont(acc)
        pkpv[i] = [barrett_reduce(acc[k] + e_ntt[i][k]) for k in range(256)]

    pk = polyvec_tobytes(pkpv) + publicseed
    sk = polyvec_tobytes(skpv_ntt)
    return pk, sk

def indcpa_enc(m: bytes, pk: bytes, coins: bytes) -> bytes:
    seed = pk[KYBER_POLYVECBYTES: KYBER_POLYVECBYTES + 32]
    pkpv = polyvec_frombytes(pk[:KYBER_POLYVECBYTES])
    at = gen_matrix(seed, transposed=True)

    sp = [poly_getnoise_eta1(coins, i) for i in range(KYBER_K)]
    ep = [poly_getnoise_eta2(coins, KYBER_K + i) for i in range(KYBER_K)]
    epp = poly_getnoise_eta2(coins, 2 * KYBER_K)

    sp_ntt = [ntt(p) for p in sp]

    bp = [[0] * 256 for _ in range(KYBER_K)]
    for i in range(KYBER_K):
        acc = [0] * 256
        for j in range(KYBER_K):
            prod = poly_basemul(at[i][j], sp_ntt[j])
            acc = [(acc[k] + prod[k]) for k in range(256)]
        acc = poly_tomont(acc)
        bp_inv = invntt(acc)
        bp[i] = [barrett_reduce(bp_inv[k] + ep[i][k]) for k in range(256)]

    v_acc = [0] * 256
    for i in range(KYBER_K):
        prod = poly_basemul(pkpv[i], sp_ntt[i])
        v_acc = [(v_acc[k] + prod[k]) for k in range(256)]
    v_acc = poly_tomont(v_acc)
    v_inv = invntt(v_acc)
    k_poly = poly_frommsg(m)
    v = [barrett_reduce(v_inv[k] + epp[k] + k_poly[k]) for k in range(256)]

    return polyvec_compress_du(bp) + poly_compress_dv(v)

def indcpa_dec(c: bytes, sk: bytes) -> bytes:
    bp = polyvec_decompress_du(c[:KYBER_POLYVECCOMPRESSEDBYTES_DU])
    v = poly_decompress_dv(c[KYBER_POLYVECCOMPRESSEDBYTES_DU:])
    skpv = polyvec_frombytes(sk)

    bp_ntt = [ntt(p) for p in bp]
    mp_acc = [0] * 256
    for i in range(KYBER_K):
        prod = poly_basemul(skpv[i], bp_ntt[i])
        mp_acc = [(mp_acc[k] + prod[k]) for k in range(256)]
    mp_acc = poly_tomont(mp_acc)
    mp_inv = invntt(mp_acc)

    mp = [barrett_reduce(v[k] - mp_inv[k]) for k in range(256)]
    return poly_tomsg(mp)

# ──────────────────────────────────────────────
# CCA-Secure Public API
# ──────────────────────────────────────────────

def mlkem512_keypair() -> tuple[bytes, bytes]:
    """Generates an ML-KEM-512 (pk, sk) keypair."""
    coins = os.urandom(64)
    pk, indcpa_sk = indcpa_keypair(coins[:32])
    h_pk = hashlib.sha3_256(pk).digest()
    z = coins[32:]
    sk = indcpa_sk + pk + h_pk + z
    return pk, sk

def mlkem512_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Encapsulates a shared secret against recipient's public key (ct, ss)."""
    m = os.urandom(32)
    buf = m + hashlib.sha3_256(pk).digest()
    kr = hashlib.sha3_512(buf).digest()
    k = kr[:32]
    r = kr[32:]
    ct = indcpa_enc(m, pk, r)
    ss = hashlib.shake_256(k).digest(KYBER_SSBYTES)
    return ct, ss

def mlkem512_decaps(ct: bytes, sk: bytes) -> bytes:
    """Decapsulates shared secret with recipient's private key (implicit rejection)."""
    indcpa_sk = sk[:KYBER_INDCPA_SECRETKEYBYTES]
    pk = sk[KYBER_INDCPA_SECRETKEYBYTES: KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES]
    h_pk = sk[KYBER_SECRETKEYBYTES - 64: KYBER_SECRETKEYBYTES - 32]
    z = sk[KYBER_SECRETKEYBYTES - 32:]

    m_prime = indcpa_dec(ct, indcpa_sk)
    buf = m_prime + h_pk
    kr = hashlib.sha3_512(buf).digest()
    k_prime = kr[:32]
    r_prime = kr[32:]

    cmp_ct = indcpa_enc(m_prime, pk, r_prime)
    if ct == cmp_ct:
        return hashlib.shake_256(k_prime).digest(KYBER_SSBYTES)
    else:
        # Implicit rejection
        rk = hashlib.shake_256(z + ct).digest(KYBER_SYMBYTES)
        return hashlib.shake_256(rk).digest(KYBER_SSBYTES)
