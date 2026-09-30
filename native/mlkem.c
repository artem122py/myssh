/* mlkem.c — ML-KEM-768 (FIPS 203).
 * Структура основана на pq-crystals/kyber (public domain).
 * Все шаги соответствуют FIPS 203.
 */
#include "mlkem.h"
#include "sha3.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define Q        3329
#define MLKEM_K     3
#define QINV    (-3327)
#define MONT     2285
#define MONT2    1353

/* ─── Barrett reduce: int16_t → (-Q/2, Q/2] ──────────────── */
static inline int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + Q/2) / Q;
    t = (int16_t)(((int32_t)v * a + (1 << 25)) >> 26);
    t = (int16_t)(t * Q);
    return (int16_t)(a - t);
}

/* ─── Montgomery reduce: a * 2^-16 mod Q ─────────────────── */
static inline int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)a * QINV;
    t = (int16_t)((a - (int32_t)t * Q) >> 16);
    return t;
}

/* ─── Montgomery multiply ─────────────────────────────────── */
static inline int16_t fqmul(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}

/* ─── zetas (Montgomery): ζ^brv(i) * R mod Q ─────────────── */
static const int16_t zetas[128] = {
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
     -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/* ─── NTT (pq-crystals) ───────────────────────────────────── */
static void ntt(int16_t r[256]) {
    unsigned int len, start, j, k = 1;
    int16_t t, zeta;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = (int16_t)(r[j] - t);
                r[j] = (int16_t)(r[j] + t);
            }
        }
    }
}

/* ─── inverse NTT (pq-crystals) ───────────────────────────── */
static void invntt(int16_t r[256]) {
    unsigned int start, len, j, k = 127;
    int16_t t, zeta;
    const int16_t f = 1441;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = barrett_reduce((int16_t)(t + r[j + len]));
                r[j + len] = (int16_t)(r[j + len] - t);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }
    for (j = 0; j < 256; j++) {
        r[j] = fqmul(f, r[j]);
    }
}

/* ─── basemul (pq-crystals) ───────────────────────────────── */
/* Использует zetas[64+i] и -zetas[64+i] для пар (4i, 4i+1) и (4i+2, 4i+3).
 * Это эквивалентно FIPS 203 с gammas[2i] и gammas[2i+1]. */
static void basemul_pair(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] = (int16_t)(r[0] + fqmul(a[0], b[0]));
    r[1] = fqmul(a[0], b[1]);
    r[1] = (int16_t)(r[1] + fqmul(a[1], b[0]));
}

static void basemul(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    unsigned int i;
    for (i = 0; i < 64; i++) {
        int16_t zeta = zetas[64 + i];
        basemul_pair(&r[4*i], &a[4*i], &b[4*i], zeta);
        basemul_pair(&r[4*i + 2], &a[4*i + 2], &b[4*i + 2], -zeta);
    }
}

/* ─── полиномиальные операции ─────────────────────────────── */
static void poly_reduce(int16_t r[256]) {
    for (int i = 0; i < 256; i++) r[i] = barrett_reduce(r[i]);
}

static void poly_add(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    for (int i = 0; i < 256; i++) r[i] = (int16_t)(a[i] + b[i]);
}

static void poly_sub(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    for (int i = 0; i < 256; i++) r[i] = (int16_t)(a[i] - b[i]);
}

static void poly_ntt(int16_t r[256], const int16_t a[256]) {
    memcpy(r, a, 512);
    ntt(r);
    poly_reduce(r);
}

/* Умножить все коэффициенты на R = 2^16 mod q.
 * Используется для компенсации R^-1, которую даёт basemul. */
static void poly_tomont(int16_t r[256]) {
    for (int i = 0; i < 256; i++) {
        r[i] = fqmul(r[i], MONT2);   /* a * R^2 * R^-1 = a * R */
    }
}

static void poly_invntt(int16_t r[256]) {
    invntt(r);
}

/* ─── matrix from rho ─────────────────────────────────────── */
static void sample_ntt(int16_t a[256], const uint8_t rho[32], uint8_t j, uint8_t i) {
    uint8_t seed[34];
    memcpy(seed, rho, 32);
    seed[32] = j;
    seed[33] = i;
    uint8_t buf[840];
    myssh_shake128(seed, 34, buf, sizeof(buf));
    int count = 0;
    size_t pos = 0;
    while (count < 256 && pos + 3 <= sizeof(buf)) {
        uint16_t d1 = (uint16_t)buf[pos] + 256 * ((uint16_t)buf[pos+1] & 0x0F);
        uint16_t d2 = ((uint16_t)buf[pos+1] >> 4) + 16 * (uint16_t)buf[pos+2];
        pos += 3;
        if (d1 < Q) a[count++] = (int16_t)d1;
        if (count < 256 && d2 < Q) a[count++] = (int16_t)d2;
    }
}

static void gen_matrix(int16_t A[MLKEM_K * MLKEM_K][256], const uint8_t rho[32]) {
    for (int i = 0; i < MLKEM_K; i++)
        for (int j = 0; j < MLKEM_K; j++)
            sample_ntt(A[i * MLKEM_K + j], rho, (uint8_t)j, (uint8_t)i);
}

/* ─── CBD ─────────────────────────────────────────────────── */
static void sample_poly_cbd(int16_t r[256], const uint8_t sigma[32], uint8_t N) {
    const int eta = 2;
    uint8_t buf[128];
    uint8_t ext[33];
    memcpy(ext, sigma, 32);
    ext[32] = N;
    myssh_shake256(ext, 33, buf, 64 * eta);
    for (int i = 0; i < 256; i++) {
        int16_t x = 0, y = 0;
        for (int j = 0; j < eta; j++) {
            size_t bi = 2 * i * eta + j;
            x += (int16_t)((buf[bi / 8] >> (bi % 8)) & 1);
            bi = 2 * i * eta + eta + j;
            y += (int16_t)((buf[bi / 8] >> (bi % 8)) & 1);
        }
        r[i] = (int16_t)(x - y);
    }
}

/* ─── Compress / Decompress ───────────────────────────────── */
static uint16_t compress_d(uint16_t x, int d) {
    uint32_t t = ((uint32_t)x << d) + Q / 2;
    uint32_t r = t / Q;
    return (uint16_t)(r & ((1u << d) - 1));
}

static uint16_t decompress_d(uint16_t y, int d) {
    uint32_t t = ((uint32_t)y * Q) + (1u << (d - 1));
    return (uint16_t)(t >> d);
}

/* ─── Byte encode/decode ─────────────────────────────────── */
static void byte_encode_d(uint8_t *out, const uint16_t *a, int d) {
    memset(out, 0, 32 * d);
    if (d == 12) {
        for (int i = 0; i < 128; i++) {
            uint16_t x0 = a[2*i]     & 0xFFF;
            uint16_t x1 = a[2*i + 1] & 0xFFF;
            out[3*i]     = (uint8_t)(x0 & 0xFF);
            out[3*i + 1] = (uint8_t)((x0 >> 8) | ((x1 & 0x0F) << 4));
            out[3*i + 2] = (uint8_t)((x1 >> 4) & 0xFF);
        }
        return;
    }
    uint32_t bitpos = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t v = a[i] & ((1u << d) - 1);
        for (int b = 0; b < d; b++) {
            if ((v >> b) & 1) out[bitpos / 8] |= (uint8_t)(1u << (bitpos % 8));
            bitpos++;
        }
    }
}

static void byte_decode_d(uint16_t *a, const uint8_t *in, int d) {
    if (d == 12) {
        for (int i = 0; i < 128; i++) {
            uint16_t b0 = in[3*i], b1 = in[3*i+1], b2 = in[3*i+2];
            a[2*i]     = (uint16_t)((b0 | ((b1 & 0x0F) << 8)) & 0xFFF);
            a[2*i + 1] = (uint16_t)((((b1 >> 4) & 0x0F) | (b2 << 4)) & 0xFFF);
        }
        return;
    }
    memset(a, 0, 256 * sizeof(uint16_t));
    uint32_t bitpos = 0;
    for (int i = 0; i < 256; i++) {
        uint32_t v = 0;
        for (int b = 0; b < d; b++) {
            if (in[bitpos / 8] & (1u << (bitpos % 8))) v |= (1u << b);
            bitpos++;
        }
        a[i] = (uint16_t)v;
    }
}

/* ─── SHA3 helpers ───────────────────────────────────────── */
static void G_hash(uint8_t out[64], const uint8_t seed[32], uint8_t k) {
    uint8_t ext[33];
    memcpy(ext, seed, 32);
    ext[32] = k;
    myssh_sha3_512(ext, 33, out);
}

/* ═══════════════════════════════════════════════════════════
 * K-PKE (pq-crystals indcpa, адаптировано под FIPS 203)
 * ═══════════════════════════════════════════════════════════ */
static void kpke_keygen(uint8_t ek[1184], uint8_t dk[1152], const uint8_t d[32]) {
    uint8_t g[64];
    G_hash(g, d, MLKEM_K);
    const uint8_t *rho = g, *sigma = g + 32;

    int16_t A[MLKEM_K * MLKEM_K][256];
    gen_matrix(A, rho);

    int16_t s[MLKEM_K][256], e[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) {
        sample_poly_cbd(s[i], sigma, (uint8_t)i);
        sample_poly_cbd(e[i], sigma, (uint8_t)(i + MLKEM_K));
    }

    int16_t shat[MLKEM_K][256], ehat[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) {
        poly_ntt(shat[i], s[i]);
        poly_ntt(ehat[i], e[i]);
    }

    int16_t that[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) {
        int16_t sum[256];
        memset(sum, 0, sizeof(sum));
        for (int j = 0; j < MLKEM_K; j++) {
            int16_t prod[256];
            basemul(prod, A[i * MLKEM_K + j], shat[j]);
            poly_add(sum, sum, prod);
        }
        poly_tomont(sum);                 /* × R — компенсация R^-1 от basemul */
        poly_add(that[i], ehat[i], sum);
        poly_reduce(that[i]);
    }

    uint16_t tmp[256];
    for (int i = 0; i < MLKEM_K; i++) {
        for (int j = 0; j < 256; j++) {
            int16_t x = that[i][j] % Q;
            if (x < 0) x = (int16_t)(x + Q);
            tmp[j] = (uint16_t)x;
        }
        byte_encode_d(ek + i * 384, tmp, 12);

        for (int j = 0; j < 256; j++) {
            int16_t x = shat[i][j] % Q;
            if (x < 0) x = (int16_t)(x + Q);
            tmp[j] = (uint16_t)x;
        }
        byte_encode_d(dk + i * 384, tmp, 12);
    }
    memcpy(ek + 1152, rho, 32);
}

static void kpke_encrypt(uint8_t ct[1088], const uint8_t ek[1184],
                         const uint8_t m[32], const uint8_t rnd[32]) {
    int16_t that[MLKEM_K][256];
    uint16_t tmp[256];
    for (int i = 0; i < MLKEM_K; i++) {
        byte_decode_d(tmp, ek + i * 384, 12);
        for (int j = 0; j < 256; j++) that[i][j] = (int16_t)tmp[j];
    }
    const uint8_t *rho = ek + 1152;

    int16_t A[MLKEM_K * MLKEM_K][256];
    gen_matrix(A, rho);

    int16_t y[MLKEM_K][256], e1[MLKEM_K][256], e2[256];
    for (int i = 0; i < MLKEM_K; i++) {
        sample_poly_cbd(y[i], rnd, (uint8_t)i);
        sample_poly_cbd(e1[i], rnd, (uint8_t)(i + MLKEM_K));
    }
    sample_poly_cbd(e2, rnd, (uint8_t)(2 * MLKEM_K));

    int16_t yhat[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) poly_ntt(yhat[i], y[i]);

    /* u[i] = INTT(Σ_j A[j][i] ∘ ŷ[j]) + e1[i] */
    int16_t u[MLKEM_K][256];
    for (int i = 0; i < MLKEM_K; i++) {
        int16_t acc[256];
        memset(acc, 0, sizeof(acc));
        for (int j = 0; j < MLKEM_K; j++) {
            int16_t prod[256];
            basemul(prod, A[j * MLKEM_K + i], yhat[j]);
            poly_add(acc, acc, prod);
        }
        poly_reduce(acc);
        poly_invntt(acc);
        poly_add(u[i], acc, e1[i]);
        poly_reduce(u[i]);
    }

    /* μ = Decompress1(Decode1(m)) */
    uint16_t m_bits[256];
    byte_decode_d(m_bits, m, 1);
    int16_t mu[256];
    for (int i = 0; i < 256; i++) mu[i] = (int16_t)decompress_d(m_bits[i], 1);

    /* v = INTT(Σ t̂ ∘ ŷ) + e2 + μ */
    int16_t vacc[256];
    memset(vacc, 0, sizeof(vacc));
    for (int i = 0; i < MLKEM_K; i++) {
        int16_t prod[256];
        basemul(prod, that[i], yhat[i]);
        poly_add(vacc, vacc, prod);
    }
    poly_reduce(vacc);
    poly_invntt(vacc);
    int16_t v[256];
    poly_add(v, vacc, e2);
    poly_add(v, v, mu);
    poly_reduce(v);

    /* Упаковка */
    for (int i = 0; i < MLKEM_K; i++) {
        for (int j = 0; j < 256; j++) {
            int16_t x = u[i][j] % Q;
            if (x < 0) x = (int16_t)(x + Q);
            tmp[j] = compress_d((uint16_t)x, 10);
        }
        byte_encode_d(ct + i * 320, tmp, 10);
    }
    for (int j = 0; j < 256; j++) {
        int16_t x = v[j] % Q;
        if (x < 0) x = (int16_t)(x + Q);
        tmp[j] = compress_d((uint16_t)x, 4);
    }
    byte_encode_d(ct + MLKEM_K * 320, tmp, 4);
}

static void kpke_decrypt(uint8_t m[32], const uint8_t dk[1152], const uint8_t ct[1088]) {
    int16_t shat[MLKEM_K][256];
    uint16_t tmp[256];
    for (int i = 0; i < MLKEM_K; i++) {
        byte_decode_d(tmp, dk + i * 384, 12);
        for (int j = 0; j < 256; j++) shat[i][j] = (int16_t)tmp[j];
    }

    int16_t u[MLKEM_K][256];
    int16_t v[256];
    for (int i = 0; i < MLKEM_K; i++) {
        byte_decode_d(tmp, ct + i * 320, 10);
        for (int j = 0; j < 256; j++) u[i][j] = (int16_t)decompress_d(tmp[j], 10);
    }
    byte_decode_d(tmp, ct + MLKEM_K * 320, 4);
    for (int j = 0; j < 256; j++) v[j] = (int16_t)decompress_d(tmp[j], 4);

    /* w = v - INTT(Σ ŝ ∘ NTT(u)) */
    int16_t acc[256];
    memset(acc, 0, sizeof(acc));
    for (int i = 0; i < MLKEM_K; i++) {
        int16_t uhat[256];
        poly_ntt(uhat, u[i]);
        int16_t prod[256];
        basemul(prod, shat[i], uhat);
        poly_add(acc, acc, prod);
    }
    poly_reduce(acc);
    poly_invntt(acc);
    int16_t w[256];
    poly_sub(w, v, acc);
    poly_reduce(w);

    for (int j = 0; j < 256; j++) {
        int16_t x = w[j] % Q;
        if (x < 0) x = (int16_t)(x + Q);
        tmp[j] = compress_d((uint16_t)x, 1);
    }
    byte_encode_d(m, tmp, 1);
}

/* ═══════════════════════════════════════════════════════════
 * ML-KEM (FIPS 203) — FO-трансформ над K-PKE
 * ═══════════════════════════════════════════════════════════ */

/* H = SHA3-256, G = SHA3-512, J = SHAKE256(32) */
static void H_hash(uint8_t out[32], const uint8_t *in, size_t inlen) {
    myssh_sha3_256(in, inlen, out);
}

static void J_hash(uint8_t out[32], const uint8_t *in, size_t inlen) {
    myssh_shake256(in, inlen, out, 32);
}

/* ─── ML-KEM.KeyGen (Algorithm 19) ───────────────────────── */
int myssh_mlkem768_keygen(uint8_t ek[1184], uint8_t dk[2400],
                          const uint8_t coins[64]) {
    /* coins = d (32) || z (32) */
    const uint8_t *d = coins;
    const uint8_t *z = coins + 32;

    uint8_t ek_pke[1184], dk_pke[1152];
    kpke_keygen(ek_pke, dk_pke, d);

    /* dk = dk_PKE || ek || H(ek) || z */
    memcpy(dk, dk_pke, 1152);
    memcpy(dk + 1152, ek_pke, 1184);
    H_hash(dk + 1152 + 1184, ek_pke, 1184);
    memcpy(dk + 1152 + 1184 + 32, z, 32);

    memcpy(ek, ek_pke, 1184);
    return 0;
}

/* ─── ML-KEM.Encaps (Algorithm 20) ───────────────────────── */
int myssh_mlkem768_encaps(uint8_t ss[32], uint8_t ct[1088],
                          const uint8_t ek[1184],
                          const uint8_t coins[32]) {
    /* m = coins (raw random, 32 байта). ML-KEM убрал H(m) из Kyber. */
    const uint8_t *m = coins;

    /* (K, r) = G(m || H(ek)) */
    uint8_t h_ek[32];
    H_hash(h_ek, ek, 1184);

    uint8_t g_in[64];
    memcpy(g_in, m, 32);
    memcpy(g_in + 32, h_ek, 32);

    uint8_t g_out[64];
    myssh_sha3_512(g_in, 64, g_out);
    /* g_out = K (32) || r (32) */

    const uint8_t *K = g_out;
    const uint8_t *r = g_out + 32;

    kpke_encrypt(ct, ek, m, r);

    memcpy(ss, K, 32);
    return 0;
}

/* ─── ML-KEM.Decaps (Algorithm 21) ───────────────────────── */
int myssh_mlkem768_decaps(uint8_t ss[32], const uint8_t ct[1088],
                          const uint8_t dk[2400]) {
    /* dk = dk_PKE(1152) || ek(1184) || H(ek)(32) || z(32) */
    const uint8_t *dk_pke = dk;
    const uint8_t *ek     = dk + 1152;
    const uint8_t *h_ek   = dk + 1152 + 1184;
    const uint8_t *z      = dk + 1152 + 1184 + 32;

    /* m' = K-PKE.Decrypt(dk_PKE, c) */
    uint8_t m_prime[32];
    kpke_decrypt(m_prime, dk_pke, ct);

    /* (K', r') = G(m' || H(ek)) */
    uint8_t g_in[64];
    memcpy(g_in, m_prime, 32);
    memcpy(g_in + 32, h_ek, 32);

    uint8_t g_out[64];
    myssh_sha3_512(g_in, 64, g_out);
    const uint8_t *K_prime = g_out;
    const uint8_t *r_prime = g_out + 32;

    /* c' = K-PKE.Encrypt(ek, m', r') */
    uint8_t ct_prime[1088];
    kpke_encrypt(ct_prime, ek, m_prime, r_prime);

    /* K_bar = J(z || c) — implicit rejection */
    uint8_t j_in[32 + 1088];
    memcpy(j_in, z, 32);
    memcpy(j_in + 32, ct, 1088);

    uint8_t K_bar[32];
    J_hash(K_bar, j_in, sizeof(j_in));

    /* constant-time выбор: если c == c', берём K', иначе K_bar. */
    int diff = 0;
    for (int i = 0; i < 1088; i++) {
        diff |= ct[i] ^ ct_prime[i];
    }
    uint8_t mask = (uint8_t)((diff == 0) ? 0xFF : 0x00);
    for (int i = 0; i < 32; i++) {
        ss[i] = (K_prime[i] & mask) | (K_bar[i] & ~mask);
    }
    return 0;
}

/* ─── Тесты ───────────────────────────────────────────────── */
int myssh_mlkem_extended_test(void) {
    {
        uint8_t d[32], m[32], rnd[32];
        for (int i = 0; i < 32; i++) {
            d[i] = (uint8_t)(i * 7 + 1);
            m[i] = (uint8_t)(i * 3 + 5);
            rnd[i] = (uint8_t)(i * 11 + 9);
        }
        uint8_t ek[1184], dk[1152], ct[1088], m2[32];
        kpke_keygen(ek, dk, d);
        kpke_encrypt(ct, ek, m, rnd);
        kpke_decrypt(m2, dk, ct);
        for (int i = 0; i < 32; i++) {
            if (m[i] != m2[i]) {
                fprintf(stderr, "[T5] i=%d m=%02x m2=%02x\n", i, m[i], m2[i]);
                return -140 - (i % 10);
            }
        }
    }

    /* T6: ML-KEM KeyGen + Encaps + Decaps roundtrip */
    {
        uint8_t coins[64], enc_coins[32];
        for (int i = 0; i < 64; i++) coins[i] = (uint8_t)(i * 13 + 7);
        for (int i = 0; i < 32; i++) enc_coins[i] = (uint8_t)(i * 17 + 3);

        uint8_t ek[1184], dk[2400], ct[1088];
        uint8_t ss1[32], ss2[32];

        if (myssh_mlkem768_keygen(ek, dk, coins) != 0) return -170;
        if (myssh_mlkem768_encaps(ss1, ct, ek, enc_coins) != 0) return -171;
        if (myssh_mlkem768_decaps(ss2, ct, dk) != 0) return -172;

        for (int i = 0; i < 32; i++) {
            if (ss1[i] != ss2[i]) {
                fprintf(stderr, "[T6] ss mismatch i=%d ss1=%02x ss2=%02x\n",
                        i, ss1[i], ss2[i]);
                return -173 - (i % 10);
            }
        }
    }

    return 0;
}

int myssh_mlkem_selftest(void) {
    {
        int16_t orig[256], a[256];
        for (int i = 0; i < 256; i++) {
            orig[i] = (int16_t)(i % Q);
            a[i] = orig[i];
        }
        ntt(a);
        invntt(a);
        for (int i = 0; i < 256; i++) {
            int32_t expected = ((int32_t)orig[i] * MONT) % Q;
            int16_t x = a[i] % Q;
            if (x < 0) x = (int16_t)(x + Q);
            int16_t e = (int16_t)(expected < 0 ? expected + Q : expected);
            if (x != e) return -10 - (i % 10);
        }
    }
    return 0;
}
