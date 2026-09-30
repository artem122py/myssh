/* chacha20poly1305.c — ChaCha20-Poly1305@openssh.com
 * ChaCha20 и Poly1305 — RFC 8439. OpenSSH-обёртка — по PROTOCOL.chacha20poly1305.
 */
#include "chacha20poly1305.h"
#include <string.h>

static inline uint32_t load32_le(const uint8_t *p) {
    uint32_t v;
    __builtin_memcpy(&v, p, 4);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    return v;
}
static inline void store32_le(uint8_t *p, uint32_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    __builtin_memcpy(p, &v, 4);
}
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7); \
} while (0)

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16]; int i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

/* --- OpenSSH layout: 64-bit counter (st[12..13]), 64-bit nonce (st[14..15]).
       seqbuf — 8 BE-байтов seq, читаются как два LE-слова. --- */
static void chacha20_init_ssh(uint32_t st[16], const uint8_t key[32],
                              uint64_t ctr, const uint8_t seqbuf[8]) {
    st[0] = 0x61707865; st[1] = 0x3320646e;
    st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) st[4+i] = load32_le(key + i*4);
    st[12] = (uint32_t)ctr;
    st[13] = (uint32_t)(ctr >> 32);
    st[14] = load32_le(seqbuf);
    st[15] = load32_le(seqbuf + 4);
}

static void seq_to_be_bytes(uint64_t seq, uint8_t seqbuf[8]) {
    for (int i = 0; i < 8; i++) seqbuf[i] = (uint8_t)(seq >> (56 - i*8));
}

/* XOR with OpenSSH-style ChaCha (64-bit counter, 8-byte BE seq) */
static void chacha20_ssh_xor(const uint8_t key[32], uint64_t ctr,
                             const uint8_t seqbuf[8],
                             const uint8_t *in, size_t len, uint8_t *out) {
    uint32_t st[16], blk[16];
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        chacha20_init_ssh(st, key, ctr, seqbuf);
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32_le(ks + i*4, blk[i]);
        size_t n = len - done < 64 ? len - done : 64;
        for (size_t i = 0; i < n; i++) out[done+i] = in[done+i] ^ ks[i];
        done += n; ctr++;
    }
}

/* Same, but fills `out` with keystream instead of XOR */
static void chacha20_ssh_stream(const uint8_t key[32], uint64_t ctr,
                                const uint8_t seqbuf[8],
                                uint8_t *out, size_t len) {
    uint32_t st[16], blk[16];
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        chacha20_init_ssh(st, key, ctr, seqbuf);
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32_le(ks + i*4, blk[i]);
        size_t n = len - done < 64 ? len - done : 64;
        memcpy(out + done, ks, n);
        done += n; ctr++;
    }
}

/* --- IETF layout (RFC 8439): 32-bit counter (st[12]), 96-bit nonce (st[13..15]).
       Только для self-test. --- */
static void chacha20_init_ietf(uint32_t st[16], const uint8_t key[32],
                               uint32_t ctr, const uint8_t nonce[12]) {
    st[0] = 0x61707865; st[1] = 0x3320646e;
    st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) st[4+i] = load32_le(key + i*4);
    st[12] = ctr;
    st[13] = load32_le(nonce);
    st[14] = load32_le(nonce + 4);
    st[15] = load32_le(nonce + 8);
}

static void chacha20_ietf_stream(const uint8_t key[32], uint32_t ctr,
                                 const uint8_t nonce[12],
                                 uint8_t *out, size_t len) {
    uint32_t st[16], blk[16];
    uint8_t ks[64];
    size_t done = 0;
    while (done < len) {
        chacha20_init_ietf(st, key, ctr, nonce);
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32_le(ks + i*4, blk[i]);
        size_t n = len - done < 64 ? len - done : 64;
        memcpy(out + done, ks, n);
        done += n; ctr++;
    }
}

/* ========================================================================
 * Poly1305 (poly1305-donna-32)
 * ======================================================================== */
typedef struct { uint32_t r[5], h[5], pad[4]; } poly1305_ctx;

static void poly_init(poly1305_ctx *c, const uint8_t key[32]) {
    c->r[0] = (load32_le(key +  0)      ) & 0x3ffffff;
    c->r[1] = (load32_le(key +  3) >>  2) & 0x3ffff03;
    c->r[2] = (load32_le(key +  6) >>  4) & 0x3ffc0ff;
    c->r[3] = (load32_le(key +  9) >>  6) & 0x3f03fff;
    c->r[4] = (load32_le(key + 12) >>  8) & 0x00fffff;
    c->pad[0] = load32_le(key + 16);
    c->pad[1] = load32_le(key + 20);
    c->pad[2] = load32_le(key + 24);
    c->pad[3] = load32_le(key + 28);
    c->h[0] = c->h[1] = c->h[2] = c->h[3] = c->h[4] = 0;
}

static void poly_blocks(poly1305_ctx *c, const uint8_t *m, size_t bytes,
                        uint32_t hibit) {
    uint32_t r0=c->r[0], r1=c->r[1], r2=c->r[2], r3=c->r[3], r4=c->r[4];
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    uint32_t h0=c->h[0], h1=c->h[1], h2=c->h[2], h3=c->h[3], h4=c->h[4];
    while (bytes >= 16) {
        h0 += (load32_le(m +  0)      ) & 0x3ffffff;
        h1 += (load32_le(m +  3) >>  2) & 0x3ffffff;
        h2 += (load32_le(m +  6) >>  4) & 0x3ffffff;
        h3 += (load32_le(m +  9) >>  6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >>  8) | hibit;
        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;
        uint32_t cc;
        cc=(uint32_t)(d0>>26); h0=(uint32_t)d0&0x3ffffff; d1+=cc;
        cc=(uint32_t)(d1>>26); h1=(uint32_t)d1&0x3ffffff; d2+=cc;
        cc=(uint32_t)(d2>>26); h2=(uint32_t)d2&0x3ffffff; d3+=cc;
        cc=(uint32_t)(d3>>26); h3=(uint32_t)d3&0x3ffffff; d4+=cc;
        cc=(uint32_t)(d4>>26); h4=(uint32_t)d4&0x3ffffff; h0+=cc*5;
        cc=h0>>26; h0&=0x3ffffff; h1+=cc;
        m += 16; bytes -= 16;
    }
    c->h[0]=h0; c->h[1]=h1; c->h[2]=h2; c->h[3]=h3; c->h[4]=h4;
}

static void poly_finish(poly1305_ctx *c, uint8_t mac[16]) {
    uint32_t h0=c->h[0], h1=c->h[1], h2=c->h[2], h3=c->h[3], h4=c->h[4], cc;
    cc=h1>>26; h1&=0x3ffffff; h2+=cc;
    cc=h2>>26; h2&=0x3ffffff; h3+=cc;
    cc=h3>>26; h3&=0x3ffffff; h4+=cc;
    cc=h4>>26; h4&=0x3ffffff; h0+=cc*5;
    cc=h0>>26; h0&=0x3ffffff; h1+=cc;
    uint32_t g0=h0+5; cc=g0>>26; g0&=0x3ffffff;
    uint32_t g1=h1+cc; cc=g1>>26; g1&=0x3ffffff;
    uint32_t g2=h2+cc; cc=g2>>26; g2&=0x3ffffff;
    uint32_t g3=h3+cc; cc=g3>>26; g3&=0x3ffffff;
    uint32_t g4=h4+cc-(1u<<26);
    uint32_t mask=(g4>>31)-1;
    g0&=mask; g1&=mask; g2&=mask; g3&=mask; g4&=mask;
    mask=~mask;
    h0=(h0&mask)|g0; h1=(h1&mask)|g1; h2=(h2&mask)|g2;
    h3=(h3&mask)|g3; h4=(h4&mask)|g4;
    h0=(h0      )|(h1<<26);
    h1=(h1>>  6)|(h2<<20);
    h2=(h2>> 12)|(h3<<14);
    h3=(h3>> 18)|(h4<< 8);
    uint64_t f;
    f=(uint64_t)h0+c->pad[0]; store32_le(mac+ 0,(uint32_t)f);
    f=(uint64_t)h1+c->pad[1]+(f>>32); store32_le(mac+ 4,(uint32_t)f);
    f=(uint64_t)h2+c->pad[2]+(f>>32); store32_le(mac+ 8,(uint32_t)f);
    f=(uint64_t)h3+c->pad[3]+(f>>32); store32_le(mac+12,(uint32_t)f);
}

static void poly1305_auth(uint8_t mac[16], const uint8_t *m, size_t n,
                          const uint8_t key[32]) {
    poly1305_ctx c;
    poly_init(&c, key);
    size_t full = n & ~(size_t)15;
    if (full) poly_blocks(&c, m, full, 1u << 24);
    size_t rem = n - full;
    if (rem) {
        uint8_t buf[16] = {0};
        memcpy(buf, m + full, rem);
        buf[rem] = 1;
        poly_blocks(&c, buf, 16, 0);
    }
    poly_finish(&c, mac);
}

/* ========================================================================
 * OpenSSH chacha20-poly1305@openssh.com
 * key = K2(32) || K1(32). K1 — length, K2 — payload + poly_key.
 * ======================================================================== */
int myssh_chacha20_poly1305_encrypt(const uint8_t key[64], uint64_t seq,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *out) {
    const uint8_t *K2 = key;         /* key[0..31]: payload + poly */
    const uint8_t *K1 = key + 32;    /* key[32..63]: length */
    uint8_t seqbuf[8];
    seq_to_be_bytes(seq, seqbuf);

    uint8_t poly_key[32];
    chacha20_ssh_stream(K2, 0, seqbuf, poly_key, 32);

    uint32_t plen = (uint32_t)pt_len;
    uint8_t len_pt[4] = {
        (uint8_t)(plen >> 24), (uint8_t)(plen >> 16),
        (uint8_t)(plen >>  8), (uint8_t)(plen)
    };
    chacha20_ssh_xor(K1, 0, seqbuf, len_pt, 4, out);

    /* payload: K2 stream starting at ctr=0 block, byte 32
       (OpenSSH: ks_left=32 after poly_key, продолжает тот же блок). */
    uint8_t ks[64];
    size_t done = 0;
    uint64_t ctr = 0;
    {
        uint32_t st[16], blk[16];
        chacha20_init_ssh(st, K2, ctr, seqbuf);
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32_le(ks + i*4, blk[i]);
        size_t n = pt_len < 32 ? pt_len : 32;
        for (size_t i = 0; i < n; i++) out[4 + i] = pt[i] ^ ks[32 + i];
        done = n; ctr++;
    }
    while (done < pt_len) {
        uint32_t st[16], blk[16];
        chacha20_init_ssh(st, K2, ctr, seqbuf);
        chacha20_block(blk, st);
        for (int i = 0; i < 16; i++) store32_le(ks + i*4, blk[i]);
        size_t n = (pt_len - done) < 64 ? (pt_len - done) : 64;
        for (size_t i = 0; i < n; i++) out[4 + done + i] = pt[done + i] ^ ks[i];
        done += n; ctr++;
    }

    /* tag over enc_len || enc_payload */
    poly1305_auth(out + 4 + pt_len, out, 4 + pt_len, poly_key);
    return 0;
}

int myssh_chacha20_poly1305_length(const uint8_t key[64], uint64_t seq,
                                   const uint8_t ct_len[4],
                                   uint32_t *out_len) {
    const uint8_t *K1 = key + 32;
    uint8_t seqbuf[8];
    seq_to_be_bytes(seq, seqbuf);
    uint8_t pt[4];
    chacha20_ssh_xor(K1, 0, seqbuf, ct_len, 4, pt);
    *out_len = ((uint32_t)pt[0] << 24) | ((uint32_t)pt[1] << 16) |
               ((uint32_t)pt[2] <<  8) |  (uint32_t)pt[3];
    return 0;
}

int myssh_chacha20_poly1305_decrypt(const uint8_t key[64], uint64_t seq,
                                    const uint8_t *in, size_t in_len,
                                    uint8_t *out) {
    if (in_len < 20) return -1;
    const uint8_t *K2 = key;
    size_t pt_len = in_len - 20;   /* enc_len(4) + enc_payload + tag(16) */
    const uint8_t *tag = in + 4 + pt_len;

    uint8_t seqbuf[8];
    seq_to_be_bytes(seq, seqbuf);

    uint8_t poly_key[32];
    chacha20_ssh_stream(K2, 0, seqbuf, poly_key, 32);

    /* tag over enc_len || enc_payload */
    uint8_t expected[16];
    poly1305_auth(expected, in, 4 + pt_len, poly_key);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    if (diff != 0) return -1;

    /* payload: K2, counter=1, с начала блока */
    {
        uint8_t ks[64];
        size_t done = 0;
        uint64_t ctr = 1;
        while (done < pt_len) {
            uint32_t st[16], blk[16];
            chacha20_init_ssh(st, K2, ctr, seqbuf);
            chacha20_block(blk, st);
            for (int i = 0; i < 16; i++) store32_le(ks + i*4, blk[i]);
            size_t n = (pt_len - done) < 64 ? (pt_len - done) : 64;
            for (size_t i = 0; i < n; i++) out[done + i] = in[4 + done + i] ^ ks[i];
            done += n; ctr++;
        }
    }
    return 0;
}


/* ========================================================================
 * Self-test: RFC 8439 vectors
 * ======================================================================== */
int myssh_chacha20_selftest(void) {
    /* RFC 8439 §2.4.2 — ChaCha20 block function, IETF layout */
    {
        const uint8_t key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const uint8_t nonce[12] = {0,0,0,0x09, 0,0,0,0x4a, 0,0,0,0};
        uint8_t ks[64];
        chacha20_ietf_stream(key, 1, nonce, ks, 64);
        const uint8_t exp[64] = {
            0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
            0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
            0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
            0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
            0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
            0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
            0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
            0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
        };
        if (memcmp(ks, exp, 64) != 0) return -1;
    }
    /* RFC 8439 §2.5.2 — Poly1305 */
    {
        const uint8_t key[32] = {
            0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
            0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
            0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
            0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
        };
        const uint8_t msg[] = "Cryptographic Forum Research Group";
        uint8_t tag[16];
        poly1305_auth(tag, msg, sizeof(msg) - 1, key);
        const uint8_t exp[16] = {
            0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
            0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
        };
        if (memcmp(tag, exp, 16) != 0) return -1;
    }
    /* Self-consistency: encrypt → decrypt, разные длины */
    {
        uint8_t key[64];
        for (int i = 0; i < 64; i++) key[i] = (uint8_t)(i * 7 + 1);
        const size_t lens[] = {1, 4, 16, 20, 63, 64, 65, 100, 200};
        static uint8_t pt[200], ct[216], rt[200];
        for (int i = 0; i < 200; i++) pt[i] = (uint8_t)(i ^ 0xa5);
        for (size_t k = 0; k < sizeof(lens)/sizeof(lens[0]); k++) {
            size_t n = lens[k];
            myssh_chacha20_poly1305_encrypt(key, 0, pt, n, ct);
            uint32_t got_len = 0;
            myssh_chacha20_poly1305_length(key, 0, ct, &got_len);
            if (got_len != n) return -2;
            int rc = myssh_chacha20_poly1305_decrypt(key, 0, ct + 4, n + 16, rt);
            if (rc != 0) return -3;
            if (memcmp(pt, rt, n) != 0) return -4;
        }
    }
    return 0;
}
