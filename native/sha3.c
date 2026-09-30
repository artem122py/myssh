/* sha3.c — SHA-3 / SHAKE (FIPS 202) на чистом C.
 * Keccak-f[1600] permutation + sponge construction.
 */
#include "sha3.h"
#include <string.h>

#define KECCAK_ROUNDS 24
#define KECCAK_LANES 25

static const uint64_t keccak_rc[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccak_rot[KECCAK_LANES] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static inline uint64_t rotl64(uint64_t x, int n) {
    /* Для n=0 избегаем UB: x >> 64 неопределён. */
    return (x << n) | (x >> ((-n) & 63));
}

static inline uint64_t load64_le(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

static void keccak_f1600(uint64_t st[KECCAK_LANES]) {
    uint64_t C[5], D[5], B[KECCAK_LANES];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        /* θ */
        for (int x = 0; x < 5; x++) {
            C[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x+4) % 5] ^ rotl64(C[(x+1) % 5], 1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                st[x + 5*y] ^= D[x];
            }
        }

        /* ρ + π */
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                int nx = y;
                int ny = (2*x + 3*y) % 5;
                B[nx + 5*ny] = rotl64(st[x + 5*y], keccak_rot[x + 5*y]);
            }
        }

        /* χ */
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                st[x + 5*y] = B[x + 5*y] ^ ((~B[((x+1) % 5) + 5*y]) & B[((x+2) % 5) + 5*y]);
            }
        }

        /* ι */
        st[0] ^= keccak_rc[round];
    }
}

static void keccak_sponge(const uint8_t *data, size_t len,
                          uint8_t *out, size_t outlen,
                          size_t rate_bytes, uint8_t pad_byte) {
    uint64_t st[KECCAK_LANES];
    memset(st, 0, sizeof(st));

    size_t off = 0;
    while (len - off >= rate_bytes) {
        for (size_t i = 0; i < rate_bytes / 8; i++) {
            st[i] ^= load64_le(data + off + i*8);
        }
        keccak_f1600(st);
        off += rate_bytes;
    }

    uint8_t block[200];
    memset(block, 0, sizeof(block));
    size_t rem = len - off;
    if (rem > 0) memcpy(block, data + off, rem);
    block[rem] = pad_byte;
    block[rate_bytes - 1] |= 0x80;

    for (size_t i = 0; i < rate_bytes / 8; i++) {
        st[i] ^= load64_le(block + i*8);
    }
    keccak_f1600(st);

    size_t produced = 0;
    while (produced < outlen) {
        size_t chunk = rate_bytes;
        if (outlen - produced < chunk) chunk = outlen - produced;
        for (size_t i = 0; i < chunk; i++) {
            out[produced + i] = (uint8_t)(st[i/8] >> (8*(i%8)));
        }
        produced += chunk;
        if (produced < outlen) {
            keccak_f1600(st);
        }
    }
}

void myssh_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]) {
    keccak_sponge(data, len, out, 32, 136, 0x06);
}

void myssh_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]) {
    keccak_sponge(data, len, out, 64, 72, 0x06);
}

void myssh_shake128(const uint8_t *data, size_t len, uint8_t *out, size_t outlen) {
    keccak_sponge(data, len, out, outlen, 168, 0x1F);
}

void myssh_shake256(const uint8_t *data, size_t len, uint8_t *out, size_t outlen) {
    keccak_sponge(data, len, out, outlen, 136, 0x1F);
}

int myssh_sha3_selftest(void) {
    {
        uint8_t out[32];
        myssh_sha3_256((const uint8_t*)"", 0, out);
        static const uint8_t exp[32] = {
            0xa7,0xff,0xc6,0xf8,0xbf,0x1e,0xd7,0x66,
            0x51,0xc1,0x47,0x56,0xa0,0x61,0xd6,0x62,
            0xf5,0x80,0xff,0x4d,0xe4,0x3b,0x49,0xfa,
            0x82,0xd8,0x0a,0x4b,0x80,0xf8,0x43,0x4a
        };
        if (memcmp(out, exp, 32) != 0) return -1;
    }
    {
        uint8_t out[32];
        myssh_sha3_256((const uint8_t*)"abc", 3, out);
        static const uint8_t exp[32] = {
            0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,
            0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
            0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,
            0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
        };
        if (memcmp(out, exp, 32) != 0) return -2;
    }
    {
        uint8_t out[64];
        myssh_sha3_512((const uint8_t*)"", 0, out);
        static const uint8_t exp[64] = {
            0xa6,0x9f,0x73,0xcc,0xa2,0x3a,0x9a,0xc5,
            0xc8,0xb5,0x67,0xdc,0x18,0x5a,0x75,0x6e,
            0x97,0xc9,0x82,0x16,0x4f,0xe2,0x58,0x59,
            0xe0,0xd1,0xdc,0xc1,0x47,0x5c,0x80,0xa6,
            0x15,0xb2,0x12,0x3a,0xf1,0xf5,0xf9,0x4c,
            0x11,0xe3,0xe9,0x40,0x2c,0x3a,0xc5,0x58,
            0xf5,0x00,0x19,0x9d,0x95,0xb6,0xd3,0xe3,
            0x01,0x75,0x85,0x86,0x28,0x1d,0xcd,0x26
        };
        if (memcmp(out, exp, 64) != 0) return -3;
    }
    {
        uint8_t out[32];
        myssh_shake128((const uint8_t*)"", 0, out, 32);
        static const uint8_t exp[32] = {
            0x7f,0x9c,0x2b,0xa4,0xe8,0x8f,0x82,0x7d,
            0x61,0x60,0x45,0x50,0x76,0x05,0x85,0x3e,
            0xd7,0x3b,0x80,0x93,0xf6,0xef,0xbc,0x88,
            0xeb,0x1a,0x6e,0xac,0xfa,0x66,0xef,0x26
        };
        if (memcmp(out, exp, 32) != 0) return -4;
    }
    {
        uint8_t out[32];
        myssh_shake256((const uint8_t*)"", 0, out, 32);
        static const uint8_t exp[32] = {
            0x46,0xb9,0xdd,0x2b,0x0b,0xa8,0x8d,0x13,
            0x23,0x3b,0x3f,0xeb,0x74,0x3e,0xeb,0x24,
            0x3f,0xcd,0x52,0xea,0x62,0xb8,0x1b,0x82,
            0xb5,0x0c,0x27,0x64,0x6e,0xd5,0x76,0x2f
        };
        if (memcmp(out, exp, 32) != 0) return -5;
    }
    return 0;
}
