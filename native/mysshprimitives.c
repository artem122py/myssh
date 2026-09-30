/* mysshprimitives.c — криптопримитивы myssh.
 * Автоматически сгенерирован bootstrap.py. Не редактируй вручную.
 */
#include "mysshprimitives.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 * SHA-256 (FIPS 180-4)
 * ═══════════════════════════════════════════════════════════════════ */
static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_block(uint32_t s[8], const uint8_t b[64]) {
    uint32_t W[64], a,b_,c,d,e,f,g,h,t1,t2; int i;
    for (i=0;i<16;i++) W[i]=((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)
                          |((uint32_t)b[i*4+2]<<8)|(uint32_t)b[i*4+3];
    for (i=16;i<64;i++) {
        uint32_t x=W[i-15],y=W[i-2];
        uint32_t S0=ROR32(x,7)^ROR32(x,18)^(x>>3);
        uint32_t S1=ROR32(y,17)^ROR32(y,19)^(y>>10);
        W[i]=W[i-16]+S0+W[i-7]+S1;
    }
    a=s[0];b_=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for (i=0;i<64;i++) {
        uint32_t S1=ROR32(e,6)^ROR32(e,11)^ROR32(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t S0=ROR32(a,2)^ROR32(a,13)^ROR32(a,22);
        uint32_t mj=(a&b_)^(a&c)^(b_&c);
        t1=h+S1+ch+K256[i]+W[i]; t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b_;b_=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=b_;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
typedef struct { uint32_t s[8]; uint64_t bl; uint8_t buf[64]; size_t n; } sha256_ctx;
static void sha256_init(sha256_ctx*c){
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
    c->bl=0;c->n=0;
}
static void sha256_update(sha256_ctx*c,const uint8_t*d,size_t l){
    c->bl += (uint64_t)l*8;
    while (l) { size_t k=64-c->n; if (k>l) k=l; memcpy(c->buf+c->n,d,k); c->n+=k; d+=k; l-=k;
        if (c->n==64) { sha256_block(c->s,c->buf); c->n=0; } }
}
static void sha256_final(sha256_ctx*c,uint8_t out[32]){
    uint64_t bl=c->bl; uint8_t p=0x80,z=0;
    sha256_update(c,&p,1); while (c->n!=56) sha256_update(c,&z,1);
    uint8_t L[8]; for (int i=0;i<8;i++) L[i]=(uint8_t)(bl>>(56-i*8));
    sha256_update(c,L,8);
    for (int i=0;i<8;i++) { out[i*4]=(uint8_t)(c->s[i]>>24); out[i*4+1]=(uint8_t)(c->s[i]>>16);
        out[i*4+2]=(uint8_t)(c->s[i]>>8); out[i*4+3]=(uint8_t)c->s[i]; }
}
void myssh_sha256(const uint8_t*d,size_t n,uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c,d,n); sha256_final(&c,out);
}

/* ═══════════════════════════════════════════════════════════════════
 * SHA-512 (FIPS 180-4)
 * ═══════════════════════════════════════════════════════════════════ */
static const uint64_t K512[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
#define ROR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
static void sha512_block(uint64_t s[8], const uint8_t b[128]) {
    uint64_t W[80],a,b_,c,d,e,f,g,h,t1,t2; int i,j;
    for (i=0;i<16;i++){W[i]=0;for(j=0;j<8;j++)W[i]=(W[i]<<8)|b[i*8+j];}
    for (i=16;i<80;i++){uint64_t x=W[i-15],y=W[i-2];
        uint64_t S0=ROR64(x,1)^ROR64(x,8)^(x>>7);
        uint64_t S1=ROR64(y,19)^ROR64(y,61)^(y>>6);
        W[i]=W[i-16]+S0+W[i-7]+S1;}
    a=s[0];b_=s[1];c=s[2];d=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for (i=0;i<80;i++){uint64_t S1=ROR64(e,14)^ROR64(e,18)^ROR64(e,41);
        uint64_t ch=(e&f)^(~e&g);
        uint64_t S0=ROR64(a,28)^ROR64(a,34)^ROR64(a,39);
        uint64_t mj=(a&b_)^(a&c)^(b_&c);
        t1=h+S1+ch+K512[i]+W[i]; t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b_;b_=a;a=t1+t2;}
    s[0]+=a;s[1]+=b_;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
typedef struct { uint64_t s[8],hi,lo; uint8_t buf[128]; size_t n; } sha512_ctx;
static void sha512_init(sha512_ctx*c){
    c->s[0]=0x6a09e667f3bcc908ULL;c->s[1]=0xbb67ae8584caa73bULL;
    c->s[2]=0x3c6ef372fe94f82bULL;c->s[3]=0xa54ff53a5f1d36f1ULL;
    c->s[4]=0x510e527fade682d1ULL;c->s[5]=0x9b05688c2b3e6c1fULL;
    c->s[6]=0x1f83d9abfb41bd6bULL;c->s[7]=0x5be0cd19137e2179ULL;
    c->hi=c->lo=0;c->n=0;
}
static void sha512_addlen(sha512_ctx*c,uint64_t a){
    uint64_t lo=c->lo+a; if (lo<c->lo) c->hi++; c->lo=lo;
}
static void sha512_update(sha512_ctx*c,const uint8_t*d,size_t l){
    sha512_addlen(c,(uint64_t)l*8);
    while (l) { size_t k=128-c->n; if (k>l) k=l; memcpy(c->buf+c->n,d,k); c->n+=k; d+=k; l-=k;
        if (c->n==128) { sha512_block(c->s,c->buf); c->n=0; } }
}
static void sha512_final(sha512_ctx*c,uint8_t out[64]){
    uint64_t hi=c->hi,lo=c->lo; uint8_t p=0x80,z=0;
    sha512_update(c,&p,1); while (c->n!=112) sha512_update(c,&z,1);
    uint8_t L[16];
    for (int i=0;i<8;i++) L[i]  =(uint8_t)(hi>>(56-i*8));
    for (int i=0;i<8;i++) L[i+8]=(uint8_t)(lo>>(56-i*8));
    sha512_update(c,L,16);
    for (int i=0;i<8;i++) for (int j=0;j<8;j++) out[i*8+j]=(uint8_t)(c->s[i]>>(56-j*8));
}
void myssh_sha512(const uint8_t*d,size_t n,uint8_t out[64]) {
    sha512_ctx c; sha512_init(&c); sha512_update(&c,d,n); sha512_final(&c,out);
}

/* ═══════════════════════════════════════════════════════════════════
 * Field GF(2^255-19) radix 2^51 + X25519
 * ═══════════════════════════════════════════════════════════════════ */
typedef uint64_t fe[5];
#define MASK51 ((uint64_t)((1ULL << 51) - 1))
static void fe_0(fe h) { h[0]=h[1]=h[2]=h[3]=h[4]=0; }
static void fe_1(fe h) { h[0]=1; h[1]=h[2]=h[3]=h[4]=0; }
static void fe_copy(fe h, const fe f) { for (int i=0;i<5;i++) h[i]=f[i]; }
static void fe_add(fe h, const fe f, const fe g) { for (int i=0;i<5;i++) h[i]=f[i]+g[i]; }
static void fe_sub(fe h, const fe f, const fe g) {
    h[0] = f[0] + 0xFFFFFFFFFFFDAULL - g[0];
    h[1] = f[1] + 0xFFFFFFFFFFFFEULL - g[1];
    h[2] = f[2] + 0xFFFFFFFFFFFFEULL - g[2];
    h[3] = f[3] + 0xFFFFFFFFFFFFEULL - g[3];
    h[4] = f[4] + 0xFFFFFFFFFFFFEULL - g[4];
}
static void fe_mul(fe h, const fe f, const fe g) {
    uint64_t f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    uint64_t g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    uint64_t g1_19 = 19*g1, g2_19 = 19*g2, g3_19 = 19*g3, g4_19 = 19*g4;
    __uint128_t t0 = (__uint128_t)f0*g0 + (__uint128_t)f1*g4_19 + (__uint128_t)f2*g3_19 + (__uint128_t)f3*g2_19 + (__uint128_t)f4*g1_19;
    __uint128_t t1 = (__uint128_t)f0*g1 + (__uint128_t)f1*g0 + (__uint128_t)f2*g4_19 + (__uint128_t)f3*g3_19 + (__uint128_t)f4*g2_19;
    __uint128_t t2 = (__uint128_t)f0*g2 + (__uint128_t)f1*g1 + (__uint128_t)f2*g0  + (__uint128_t)f3*g4_19 + (__uint128_t)f4*g3_19;
    __uint128_t t3 = (__uint128_t)f0*g3 + (__uint128_t)f1*g2 + (__uint128_t)f2*g1 + (__uint128_t)f3*g0 + (__uint128_t)f4*g4_19;
    __uint128_t t4 = (__uint128_t)f0*g4 + (__uint128_t)f1*g3 + (__uint128_t)f2*g2 + (__uint128_t)f3*g1 + (__uint128_t)f4*g0;
    uint64_t c;
    c=(uint64_t)(t0>>51); t0&=MASK51; t1+=c;
    c=(uint64_t)(t1>>51); t1&=MASK51; t2+=c;
    c=(uint64_t)(t2>>51); t2&=MASK51; t3+=c;
    c=(uint64_t)(t3>>51); t3&=MASK51; t4+=c;
    c=(uint64_t)(t4>>51); t4&=MASK51; t0+=(__uint128_t)c*19;
    c=(uint64_t)(t0>>51); t0&=MASK51; t1+=c;
    h[0]=(uint64_t)t0; h[1]=(uint64_t)t1; h[2]=(uint64_t)t2; h[3]=(uint64_t)t3; h[4]=(uint64_t)t4;
}
static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }
static void fe_mul121665(fe h, const fe f) {
    __uint128_t t; uint64_t c;
    t=(__uint128_t)f[0]*121665; uint64_t r0=(uint64_t)t&MASK51; c=(uint64_t)(t>>51);
    t=(__uint128_t)f[1]*121665 + c; uint64_t r1=(uint64_t)t&MASK51; c=(uint64_t)(t>>51);
    t=(__uint128_t)f[2]*121665 + c; uint64_t r2=(uint64_t)t&MASK51; c=(uint64_t)(t>>51);
    t=(__uint128_t)f[3]*121665 + c; uint64_t r3=(uint64_t)t&MASK51; c=(uint64_t)(t>>51);
    t=(__uint128_t)f[4]*121665 + c; uint64_t r4=(uint64_t)t&MASK51; c=(uint64_t)(t>>51);
    r0 += c*19; c = r0>>51; r0&=MASK51; r1+=c;
    h[0]=r0; h[1]=r1; h[2]=r2; h[3]=r3; h[4]=r4;
}
static void fe_cswap(fe f, fe g, uint64_t b) {
    uint64_t m = (uint64_t)0 - b;
    for (int i=0;i<5;i++) { uint64_t x = (f[i] ^ g[i]) & m; f[i] ^= x; g[i] ^= x; }
}
static void fe_cmov(fe f, const fe g, uint64_t b) {
    uint64_t m = (uint64_t)0 - b;
    for (int i=0;i<5;i++) f[i] = (f[i] & ~m) | (g[i] & m);
}
static void fe_frombytes(fe h, const uint8_t s[32]) {
    uint64_t t0,t1,t2,t3;
    memcpy(&t0, s,      8); memcpy(&t1, s +  8, 8);
    memcpy(&t2, s + 16, 8); memcpy(&t3, s + 24, 8);
    h[0] = t0 & MASK51;
    h[1] = ((t0 >> 51) | (t1 << 13)) & MASK51;
    h[2] = ((t1 >> 38) | (t2 << 26)) & MASK51;
    h[3] = ((t2 >> 25) | (t3 << 39)) & MASK51;
    h[4] = (t3 >> 12) & MASK51;
}
static void fe_tobytes(uint8_t s[32], const fe hh) {
    uint64_t t[5]; for (int i=0;i<5;i++) t[i]=hh[i];
    uint64_t c;
    c=t[0]>>51; t[0]&=MASK51; t[1]+=c;
    c=t[1]>>51; t[1]&=MASK51; t[2]+=c;
    c=t[2]>>51; t[2]&=MASK51; t[3]+=c;
    c=t[3]>>51; t[3]&=MASK51; t[4]+=c;
    c=t[4]>>51; t[4]&=MASK51; t[0]+=c*19;
    c=t[0]>>51; t[0]&=MASK51; t[1]+=c;
    uint64_t q[5];
    q[0]=t[0]+19; c=q[0]>>51; q[0]&=MASK51;
    q[1]=t[1]+c;  c=q[1]>>51; q[1]&=MASK51;
    q[2]=t[2]+c;  c=q[2]>>51; q[2]&=MASK51;
    q[3]=t[3]+c;  c=q[3]>>51; q[3]&=MASK51;
    q[4]=t[4]+c;  c=q[4]>>51; q[4]&=MASK51;
    uint64_t mask = (uint64_t)0 - c;
    for (int i=0;i<5;i++) t[i] = (t[i] & ~mask) | (q[i] & mask);
    uint64_t o0 =  t[0]        | (t[1] << 51);
    uint64_t o1 = (t[1] >> 13) | (t[2] << 38);
    uint64_t o2 = (t[2] >> 26) | (t[3] << 25);
    uint64_t o3 = (t[3] >> 39) | (t[4] << 12);
    memcpy(s,      &o0, 8); memcpy(s +  8, &o1, 8);
    memcpy(s + 16, &o2, 8); memcpy(s + 24, &o3, 8);
}
static void fe_invert(fe out, const fe z) {
    fe t0,t1,t2,t3;
    fe_sq(t0,z); fe_sq(t1,t0); fe_sq(t1,t1); fe_mul(t1,z,t1); fe_mul(t0,t0,t1);
    fe_sq(t2,t0); fe_mul(t1,t1,t2); fe_sq(t2,t1);
    for (int i=1;i<5;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t2,t1);
    for (int i=1;i<10;i++) fe_sq(t2,t2); fe_mul(t2,t2,t1);
    fe_sq(t3,t2);
    for (int i=1;i<20;i++) fe_sq(t3,t3); fe_mul(t2,t3,t2);
    fe_sq(t2,t2);
    for (int i=1;i<10;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t2,t1);
    for (int i=1;i<50;i++) fe_sq(t2,t2); fe_mul(t2,t2,t1);
    fe_sq(t3,t2);
    for (int i=1;i<100;i++) fe_sq(t3,t3); fe_mul(t2,t3,t2);
    fe_sq(t2,t2);
    for (int i=1;i<50;i++) fe_sq(t2,t2); fe_mul(t1,t2,t1);
    fe_sq(t1,t1);
    for (int i=1;i<5;i++) fe_sq(t1,t1); fe_mul(out,t1,t0);
}
int myssh_x25519_scalarmult(const uint8_t k[32], const uint8_t p[32], uint8_t out[32]) {
    uint8_t e[32]; memcpy(e, k, 32);
    e[0] &= 248; e[31] &= 127; e[31] |= 64;
    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB;
    fe_frombytes(x1, p); fe_1(x2); fe_0(z2); fe_copy(x3, x1); fe_1(z3);
    uint64_t swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t b = (e[pos >> 3] >> (pos & 7)) & 1u;
        swap ^= b;
        fe_cswap(x2, x3, swap); fe_cswap(z2, z3, swap); swap = b;
        fe_add(A, x2, z2);   fe_sq(AA, A);
        fe_sub(B, x2, z2);   fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);   fe_sub(D, x3, z3);
        fe_mul(DA, D, A);    fe_mul(CB, C, B);
        fe_add(A, DA, CB);   fe_sq(x3, A);
        fe_sub(B, DA, CB);   fe_sq(B, B); fe_mul(z3, x1, B);
        fe_mul(x2, AA, BB);  fe_mul121665(C, E);
        fe_add(C, AA, C);    fe_mul(z2, E, C);
    }
    fe_cswap(x2, x3, swap); fe_cswap(z2, z3, swap);
    fe_invert(z2, z2); fe_mul(x2, x2, z2); fe_tobytes(out, x2);
    uint8_t zero[32] = {0};
    if (memcmp(out, zero, 32) == 0) return -1;
    return 0;
}
int myssh_x25519_scalarmult_base(const uint8_t k[32], uint8_t out[32]) {
    static const uint8_t base[32] = {9};
    return myssh_x25519_scalarmult(k, base, out);
}

/* ═══════════════════════════════════════════════════════════════════
 * AES-256 (FIPS-197) + GCM
 * ═══════════════════════════════════════════════════════════════════ */
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static uint8_t XT(uint8_t a, uint8_t b) {
    uint8_t p=0;
    for (int i=0;i<8;i++) { if (b&1) p^=a; uint8_t h=a&0x80; a<<=1; if (h) a^=0x1B; b>>=1; }
    return p;
}
typedef struct { uint32_t rk[60]; int nr; } aes256_ctx;
static void aes_expand(aes256_ctx *c, const uint8_t key[32]) {
    uint8_t w[240]; memcpy(w,key,32);
    uint8_t rc=1; int nk=8, nr=14; c->nr = nr;
    for (int i=nk; i<4*(nr+1); i++) {
        uint8_t t[4] = {w[4*(i-1)],w[4*(i-1)+1],w[4*(i-1)+2],w[4*(i-1)+3]};
        if (i % nk == 0) {
            uint8_t u=t[0];
            t[0]=SBOX[t[1]]^rc; t[1]=SBOX[t[2]]; t[2]=SBOX[t[3]]; t[3]=SBOX[u];
            rc = XT(rc, 2);
        } else if (nk>6 && i%nk==4) {
            for (int j=0;j<4;j++) t[j]=SBOX[t[j]];
        }
        for (int j=0;j<4;j++) w[4*i+j] = w[4*(i-nk)+j] ^ t[j];
    }
    for (int i=0;i<60;i++)
        c->rk[i] = ((uint32_t)w[4*i]<<24) | ((uint32_t)w[4*i+1]<<16)
                 | ((uint32_t)w[4*i+2]<<8) | (uint32_t)w[4*i+3];
}
static void aes_encrypt_block(const aes256_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16]; memcpy(s,in,16);
    for (int j=0;j<4;j++) {
        s[4*j+0] ^= (uint8_t)(c->rk[j] >> 24);
        s[4*j+1] ^= (uint8_t)(c->rk[j] >> 16);
        s[4*j+2] ^= (uint8_t)(c->rk[j] >>  8);
        s[4*j+3] ^= (uint8_t)(c->rk[j]      );
    }
    for (int r = 1; r < c->nr; r++) {
        for (int i=0;i<16;i++) s[i]=SBOX[s[i]];
        uint8_t t[16]; memcpy(t,s,16);
        s[0]=t[0]; s[1]=t[5]; s[2]=t[10]; s[3]=t[15];
        s[4]=t[4]; s[5]=t[9]; s[6]=t[14]; s[7]=t[3];
        s[8]=t[8]; s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
        s[12]=t[12]; s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
        for (int c2=0;c2<4;c2++) {
            uint8_t a0=s[4*c2],a1=s[4*c2+1],a2=s[4*c2+2],a3=s[4*c2+3];
            s[4*c2+0]=XT(a0,2)^XT(a1,3)^a2^a3;
            s[4*c2+1]=a0^XT(a1,2)^XT(a2,3)^a3;
            s[4*c2+2]=a0^a1^XT(a2,2)^XT(a3,3);
            s[4*c2+3]=XT(a0,3)^a1^a2^XT(a3,2);
        }
        for (int j=0;j<4;j++) {
            s[4*j+0] ^= (uint8_t)(c->rk[4*r+j] >> 24);
            s[4*j+1] ^= (uint8_t)(c->rk[4*r+j] >> 16);
            s[4*j+2] ^= (uint8_t)(c->rk[4*r+j] >>  8);
            s[4*j+3] ^= (uint8_t)(c->rk[4*r+j]      );
        }
    }
    for (int i=0;i<16;i++) s[i]=SBOX[s[i]];
    uint8_t t[16]; memcpy(t,s,16);
    s[0]=t[0]; s[1]=t[5]; s[2]=t[10]; s[3]=t[15];
    s[4]=t[4]; s[5]=t[9]; s[6]=t[14]; s[7]=t[3];
    s[8]=t[8]; s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
    s[12]=t[12]; s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
    for (int j=0;j<4;j++) {
        s[4*j+0] ^= (uint8_t)(c->rk[4*c->nr+j] >> 24);
        s[4*j+1] ^= (uint8_t)(c->rk[4*c->nr+j] >> 16);
        s[4*j+2] ^= (uint8_t)(c->rk[4*c->nr+j] >>  8);
        s[4*j+3] ^= (uint8_t)(c->rk[4*c->nr+j]      );
    }
    memcpy(out,s,16);
}
static void ghash_mul(uint64_t Z[2], const uint64_t X[2], const uint64_t Y[2]) {
    uint64_t z0=0, z1=0, v0=Y[0], v1=Y[1];
    for (int i=0;i<128;i++) {
        uint64_t bit = (i<64) ? ((X[0]>>(63-i)) & 1) : ((X[1]>>(127-i)) & 1);
        uint64_t mask = (uint64_t)0 - bit;
        z0 ^= v0 & mask; z1 ^= v1 & mask;
        uint64_t lsb = v1 & 1;
        v1 = (v1 >> 1) | (v0 << 63);
        v0 = (v0 >> 1) ^ (0xE100000000000000ULL & ((uint64_t)0 - lsb));
    }
    Z[0]=z0; Z[1]=z1;
}
static uint64_t BE64(const uint8_t *b) { uint64_t v=0; for (int i=0;i<8;i++) v=(v<<8)|b[i]; return v; }
static void WR64(uint8_t *b, uint64_t v) { for (int i=0;i<8;i++) b[i]=(uint8_t)(v>>(56-i*8)); }
static void ghash(const uint8_t H[16], const uint8_t *aad, size_t al,
                  const uint8_t *ct, size_t cl, uint8_t out[16]) {
    uint64_t h[2] = {BE64(H), BE64(H+8)};
    uint64_t Y[2] = {0,0};
    uint8_t blk[16];
    for (size_t i=0;i<al;i+=16) {
        memset(blk,0,16); size_t n=(al-i<16)?(al-i):16; memcpy(blk,aad+i,n);
        uint64_t X[2]={Y[0]^BE64(blk), Y[1]^BE64(blk+8)};
        ghash_mul(Y,X,h);
    }
    for (size_t i=0;i<cl;i+=16) {
        memset(blk,0,16); size_t n=(cl-i<16)?(cl-i):16; memcpy(blk,ct+i,n);
        uint64_t X[2]={Y[0]^BE64(blk), Y[1]^BE64(blk+8)};
        ghash_mul(Y,X,h);
    }
    WR64(blk,(uint64_t)al*8); WR64(blk+8,(uint64_t)cl*8);
    uint64_t X[2]={Y[0]^BE64(blk), Y[1]^BE64(blk+8)};
    ghash_mul(Y,X,h);
    WR64(out,Y[0]); WR64(out+8,Y[1]);
}
static void gctr(const aes256_ctx *c, const uint8_t icb[16],
                 const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t ctr[16]; memcpy(ctr, icb, 16);
    for (size_t i=0; i<n; i+=16) {
        uint8_t ks[16]; aes_encrypt_block(c, ctr, ks);
        size_t k = (n-i<16) ? (n-i) : 16;
        for (size_t j=0;j<k;j++) out[i+j] = in[i+j] ^ ks[j];
        for (int j=15;j>=0;j--) { if (++ctr[j]) break; }
    }
}
int myssh_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t al,
                             const uint8_t *pt, size_t pl, uint8_t *out) {
    aes256_ctx c; aes_expand(&c, key);
    uint8_t H[16]; { uint8_t z[16]={0}; aes_encrypt_block(&c, z, H); }
    uint8_t J0[16] = {0}; memcpy(J0, nonce, 12); J0[15]=1;
    uint8_t icb[16]; memcpy(icb, J0, 16);
    for (int j=15;j>=0;j--) { if (++icb[j]) break; }
    gctr(&c, icb, pt, pl, out);
    uint8_t S[16]; ghash(H, aad, al, out, pl, S);
    uint8_t T[16]; gctr(&c, J0, S, 16, T);
    memcpy(out+pl, T, 16);
    return 0;
}
int myssh_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t al,
                             const uint8_t *in, size_t il, uint8_t *out) {
    if (il < 16) return -1;
    size_t pl = il - 16;
    const uint8_t *T = in + pl;
    aes256_ctx c; aes_expand(&c, key);
    uint8_t H[16]; { uint8_t z[16]={0}; aes_encrypt_block(&c, z, H); }
    uint8_t J0[16] = {0}; memcpy(J0, nonce, 12); J0[15]=1;
    uint8_t S[16]; ghash(H, aad, al, in, pl, S);
    uint8_t Tc[16]; gctr(&c, J0, S, 16, Tc);
    if (memcmp(Tc, T, 16) != 0) return -1;
    uint8_t icb[16]; memcpy(icb, J0, 16);
    for (int j=15;j>=0;j--) { if (++icb[j]) break; }
    gctr(&c, icb, in, pl, out);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Blowfish + bcrypt_pbkdf
 * ═══════════════════════════════════════════════════════════════════ */


/* AES-256-CTR (для openssh-key-v1). iv — 16 байт, big-endian счётчик. */
int myssh_aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                     const uint8_t *in, size_t inlen, uint8_t *out) {
    aes256_ctx c;
    aes_expand(&c, key);
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    for (size_t i = 0; i < inlen; i += 16) {
        uint8_t ks[16];
        aes_encrypt_block(&c, ctr, ks);
        size_t k = (inlen - i < 16) ? (inlen - i) : 16;
        for (size_t j = 0; j < k; j++) out[i+j] = in[i+j] ^ ks[j];
        for (int j = 15; j >= 0; j--) { if (++ctr[j]) break; }
    }
    return 0;
}

#include "blowfish_tables.h"
typedef struct { uint32_t P[18]; uint32_t S[4][256]; } bf_ctx;
static inline uint32_t bf_F(const bf_ctx *c, uint32_t x) {
    uint32_t y = c->S[0][(x >> 24) & 0xFF] + c->S[1][(x >> 16) & 0xFF];
    y ^= c->S[2][(x >> 8) & 0xFF];
    y += c->S[3][x & 0xFF];
    return y;
}
static inline void bf_encipher(const bf_ctx *c, uint32_t *xl, uint32_t *xr) {
    uint32_t Xl = *xl, Xr = *xr;
    for (int i = 0; i < 16; i += 2) {
        Xl ^= c->P[i];   Xr ^= bf_F(c, Xl);
        Xr ^= c->P[i+1]; Xl ^= bf_F(c, Xr);
    }
    Xl ^= c->P[16]; Xr ^= c->P[17];
    *xl = Xr; *xr = Xl;
}
static inline uint32_t s2w(const uint8_t *data, size_t dlen, size_t *j) {
    uint32_t w = 0;
    for (int k = 0; k < 4; k++) { if (*j >= dlen) *j = 0; w = (w << 8) | data[*j]; (*j)++; }
    return w;
}
static void bf_expandstate(bf_ctx *c, const uint8_t *data, size_t dlen,
                           const uint8_t *key, size_t klen) {
    memcpy(c->P, BF_P, sizeof(BF_P)); memcpy(c->S, BF_S, sizeof(BF_S));
    size_t j = 0;
    for (int i = 0; i < 18; i++) c->P[i] ^= s2w(key, klen, &j);
    j = 0; uint32_t dl = 0, dr = 0;
    for (int i = 0; i < 18; i += 2) {
        dl ^= s2w(data, dlen, &j); dr ^= s2w(data, dlen, &j);
        bf_encipher(c, &dl, &dr); c->P[i] = dl; c->P[i+1] = dr;
    }
    for (int b = 0; b < 4; b++) {
        for (int k = 0; k < 256; k += 2) {
            dl ^= s2w(data, dlen, &j); dr ^= s2w(data, dlen, &j);
            bf_encipher(c, &dl, &dr); c->S[b][k] = dl; c->S[b][k+1] = dr;
        }
    }
}
static void bf_expand0state(bf_ctx *c, const uint8_t *key, size_t klen) {
    size_t j = 0;
    for (int i = 0; i < 18; i++) c->P[i] ^= s2w(key, klen, &j);
    uint32_t dl = 0, dr = 0;
    for (int i = 0; i < 18; i += 2) { bf_encipher(c, &dl, &dr); c->P[i] = dl; c->P[i+1] = dr; }
    for (int b = 0; b < 4; b++)
        for (int k = 0; k < 256; k += 2) { bf_encipher(c, &dl, &dr); c->S[b][k] = dl; c->S[b][k+1] = dr; }
}
static const uint8_t BCRYPT_MAGIC[32] = "OxychromaticBlowfishSwatDynamite";
static void bcrypt_hash(const uint8_t sha2pass[64], const uint8_t sha2salt[64], uint8_t out[32]) {
    bf_ctx st;
    bf_expandstate(&st, sha2salt, 64, sha2pass, 64);
    for (int i = 0; i < 64; i++) { bf_expand0state(&st, sha2salt, 64); bf_expand0state(&st, sha2pass, 64); }
    uint32_t cdata[8];
    for (int i = 0; i < 8; i++)
        cdata[i] = ((uint32_t)BCRYPT_MAGIC[i*4]<<24)|((uint32_t)BCRYPT_MAGIC[i*4+1]<<16)
                 | ((uint32_t)BCRYPT_MAGIC[i*4+2]<<8)|(uint32_t)BCRYPT_MAGIC[i*4+3];
    for (int i = 0; i < 64; i++)
        for (int k = 0; k < 8; k += 2) bf_encipher(&st, &cdata[k], &cdata[k+1]);
    for (int i = 0; i < 8; i++) {
        out[i*4+0]=(uint8_t)(cdata[i]); out[i*4+1]=(uint8_t)(cdata[i]>>8);
        out[i*4+2]=(uint8_t)(cdata[i]>>16); out[i*4+3]=(uint8_t)(cdata[i]>>24);
    }
}
int myssh_bcrypt_pbkdf(const uint8_t *password, size_t plen,
                       const uint8_t *salt, size_t slen,
                       uint8_t *key, size_t keylen, uint32_t rounds) {
    if (!password || !salt || !key || !plen || !slen || !keylen || rounds < 1) return -1;
    uint8_t sha2pass[64];
    myssh_sha512(password, plen, sha2pass);
    size_t stride = (keylen + 31) / 32;
    size_t amt = (keylen + stride - 1) / stride;
    size_t orig = keylen;
    memset(key, 0, keylen);
    uint32_t count = 1;
    size_t remaining = keylen;
    uint8_t countsalt[512];
    if (slen + 4 > sizeof(countsalt)) return -1;
    while (remaining > 0) {
        memcpy(countsalt, salt, slen);
        countsalt[slen+0]=(uint8_t)(count>>24); countsalt[slen+1]=(uint8_t)(count>>16);
        countsalt[slen+2]=(uint8_t)(count>>8);  countsalt[slen+3]=(uint8_t)(count);
        uint8_t sha2salt[64]; myssh_sha512(countsalt, slen + 4, sha2salt);
        uint8_t tmpout[32], out[32];
        bcrypt_hash(sha2pass, sha2salt, tmpout);
        memcpy(out, tmpout, 32);
        for (uint32_t i = 1; i < rounds; i++) {
            myssh_sha512(tmpout, 32, sha2salt);
            bcrypt_hash(sha2pass, sha2salt, tmpout);
            for (int j = 0; j < 32; j++) out[j] ^= tmpout[j];
        }
        size_t amt2 = (amt < remaining) ? amt : remaining;
        size_t written = 0;
        for (size_t i = 0; i < amt2; i++) {
            size_t dest = i * stride + (count - 1);
            if (dest >= orig) break;
            key[dest] = out[i]; written = i + 1;
        }
        remaining -= written; count++;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * Ed25519 (RFC 8032)
 * ═══════════════════════════════════════════════════════════════════ */
static void fe_neg(fe h, const fe f) { fe zero; fe_0(zero); fe_sub(h, zero, f); }
static int fe_isnegative(const fe f) {
    uint8_t s[32]; fe_tobytes(s, f); return s[0] & 1;
}
static int fe_isnonzero(const fe f) {
    uint8_t s[32]; fe_tobytes(s, f); uint8_t r=0;
    for (int i=0;i<32;i++) r|=s[i]; return r!=0;
}
static void fe_pow22523(fe out, const fe z) {
    fe t0,t1,t2; int i;
    fe_sq(t0, z);
    fe_sq(t1, t0); fe_sq(t1, t1); fe_mul(t1, z, t1); fe_mul(t0, t0, t1);
    fe_sq(t0, t0); fe_mul(t0, t1, t0); fe_sq(t1, t0);
    for (i=1;i<5;i++) fe_sq(t1, t1); fe_mul(t0, t1, t0); fe_sq(t1, t0);
    for (i=1;i<10;i++) fe_sq(t1, t1); fe_mul(t1, t1, t0); fe_sq(t2, t1);
    for (i=1;i<20;i++) fe_sq(t2, t2); fe_mul(t1, t2, t1); fe_sq(t1, t1);
    for (i=1;i<10;i++) fe_sq(t1, t1); fe_mul(t0, t1, t0); fe_sq(t1, t0);
    for (i=1;i<50;i++) fe_sq(t1, t1); fe_mul(t1, t1, t0); fe_sq(t2, t1);
    for (i=1;i<100;i++) fe_sq(t2, t2); fe_mul(t1, t2, t1); fe_sq(t1, t1);
    for (i=1;i<50;i++) fe_sq(t1, t1); fe_mul(t0, t1, t0);
    fe_sq(t0, t0); fe_sq(t0, t0); fe_mul(out, t0, z);
}
static const fe ED_D = {929955233495203ULL, 466365720129213ULL, 1662059464998953ULL, 2033849074728123ULL, 1442794654840575ULL};
static const fe ED_D2 = {1859910466990425ULL, 932731440258426ULL, 1072319116312658ULL, 1815898335770999ULL, 633789495995903ULL};
static const fe ED_SQRTM1 = {1718705420411056ULL, 234908883556509ULL, 2233514472574048ULL, 2117202627021982ULL, 765476049583133ULL};
static const fe ED_Bx = {1738742601995546ULL, 1146398526822698ULL, 2070867633025821ULL, 562264141797630ULL, 587772402128613ULL};
static const fe ED_By = {1801439850948184ULL, 1351079888211148ULL, 450359962737049ULL, 900719925474099ULL, 1801439850948198ULL};
static const uint8_t ED_L[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
    0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
};
typedef struct { fe X,Y,Z,T; } ge_p3;
static void ge_p3_0(ge_p3 *p) { fe_0(p->X); fe_1(p->Y); fe_1(p->Z); fe_0(p->T); }
static void ge_add(ge_p3 *r, const ge_p3 *p, const ge_p3 *q) {
    fe A,B,C,D,E,F,G,H,t;
    fe_sub(A, p->Y, p->X); fe_sub(t, q->Y, q->X); fe_mul(A, A, t);
    fe_add(B, p->Y, p->X); fe_add(t, q->Y, q->X); fe_mul(B, B, t);
    fe_mul(C, p->T, q->T); fe_mul(C, C, ED_D2);
    fe_mul(D, p->Z, q->Z); fe_add(D, D, D);
    fe_sub(E, B, A); fe_sub(F, D, C); fe_add(G, D, C); fe_add(H, B, A);
    fe_mul(r->X, E, F); fe_mul(r->Y, H, G); fe_mul(r->Z, G, F); fe_mul(r->T, E, H);
}
static void ge_dbl(ge_p3 *r, const ge_p3 *p) {
    fe A,B,C,D,E,F,G,H;
    fe_sq(A, p->X); fe_sq(B, p->Y);
    fe_sq(C, p->Z); fe_add(C, C, C);
    fe_neg(D, A);
    fe_add(E, p->X, p->Y); fe_sq(E, E); fe_sub(E, E, A); fe_sub(E, E, B);
    fe_add(G, D, B); fe_sub(F, G, C); fe_sub(H, D, B);
    fe_mul(r->X, E, F); fe_mul(r->Y, G, H); fe_mul(r->Z, F, G); fe_mul(r->T, E, H);
}
static void ge_scalarmult(ge_p3 *r, const uint8_t e[32], const ge_p3 *P) {
    ge_p3 Q; ge_p3_0(&Q);
    for (int i = 255; i >= 0; i--) {
        ge_dbl(&Q, &Q);
        uint64_t bit = (e[i >> 3] >> (i & 7)) & 1u;
        ge_p3 T; ge_add(&T, &Q, P);
        fe_cmov(Q.X, T.X, bit); fe_cmov(Q.Y, T.Y, bit);
        fe_cmov(Q.Z, T.Z, bit); fe_cmov(Q.T, T.T, bit);
    }
    *r = Q;
}
static void ge_scalarmult_base(ge_p3 *r, const uint8_t e[32]) {
    ge_p3 B;
    fe_copy(B.X, ED_Bx); fe_copy(B.Y, ED_By);
    fe_1(B.Z); fe_mul(B.T, ED_Bx, ED_By);
    ge_scalarmult(r, e, &B);
}
static void ge_tobytes(uint8_t s[32], const ge_p3 *p) {
    fe recip, x, y;
    fe_invert(recip, p->Z); fe_mul(x, p->X, recip); fe_mul(y, p->Y, recip);
    fe_tobytes(s, y); s[31] ^= (uint8_t)(fe_isnegative(x) << 7);
}
static int fe_frombytes_neg_x(fe h, const uint8_t s[32]) {
    fe u, v, v3, vxx, check, one;
    fe_frombytes(h, s); fe_1(one);
    fe_sq(u, h);
    fe_mul(v, u, ED_D);
    fe_sub(u, u, one);
    fe_add(v, v, one);
    fe_sq(v3, v); fe_mul(v3, v3, v);
    fe_sq(h, v3); fe_mul(h, h, v); fe_mul(h, h, u);
    fe_pow22523(h, h);
    fe_mul(h, h, v3); fe_mul(h, h, u);
    fe_sq(vxx, h); fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u);
        if (fe_isnonzero(check)) return -1;
        fe_mul(h, h, ED_SQRTM1);
    }
    if ((fe_isnegative(h) ? 1 : 0) != (s[31] >> 7)) fe_neg(h, h);
    return 0;
}
static void sc_reduce(uint8_t out[32], const uint8_t in[64]) {
    uint8_t r[32]; memset(r, 0, 32);
    for (int i = 511; i >= 0; i--) {
        uint8_t carry = 0;
        for (int j = 0; j < 32; j++) {
            uint8_t nv = (uint8_t)((r[j] << 1) | carry);
            carry = (uint8_t)(r[j] >> 7); r[j] = nv;
        }
        uint8_t bit = (in[i >> 3] >> (i & 7)) & 1;
        r[0] |= bit;
        int cmp = 0;
        for (int j = 31; j >= 0; j--)
            if (r[j] != ED_L[j]) { cmp = (r[j] > ED_L[j]) ? 1 : -1; break; }
        if (cmp >= 0) {
            int borrow = 0;
            for (int j = 0; j < 32; j++) {
                int diff = (int)r[j] - (int)ED_L[j] - borrow;
                if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0;
                r[j] = (uint8_t)diff;
            }
        }
    }
    memcpy(out, r, 32);
}
void myssh_ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32]) {
    uint8_t h[64]; myssh_sha512(seed, 32, h);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    ge_p3 A; ge_scalarmult_base(&A, h); ge_tobytes(pub, &A);
}
int myssh_ed25519_sign(const uint8_t seed[32], const uint8_t *m, size_t mlen, uint8_t sig[64]) {
    uint8_t h[64]; myssh_sha512(seed, 32, h);
    uint8_t a[32]; memcpy(a, h, 32);
    a[0] &= 248; a[31] &= 127; a[31] |= 64;
    uint8_t prefix[32]; memcpy(prefix, h + 32, 32);
    ge_p3 A; ge_scalarmult_base(&A, a);
    uint8_t Abytes[32]; ge_tobytes(Abytes, &A);
    sha512_ctx sctx; sha512_init(&sctx);
    sha512_update(&sctx, prefix, 32);
    if (mlen) sha512_update(&sctx, m, mlen);
    uint8_t rhash[64]; sha512_final(&sctx, rhash);
    uint8_t r[32]; sc_reduce(r, rhash);
    ge_p3 R; ge_scalarmult_base(&R, r);
    uint8_t Rbytes[32]; ge_tobytes(Rbytes, &R);
    sha512_ctx kctx; sha512_init(&kctx);
    sha512_update(&kctx, Rbytes, 32); sha512_update(&kctx, Abytes, 32);
    if (mlen) sha512_update(&kctx, m, mlen);
    uint8_t khash[64]; sha512_final(&kctx, khash);
    uint8_t k[32]; sc_reduce(k, khash);
    uint8_t t[64]; memset(t, 0, 64);
    for (int i = 0; i < 32; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < 32; j++) {
            uint32_t v = (uint32_t)t[i+j] + (uint32_t)k[i]*(uint32_t)a[j] + carry;
            t[i+j] = (uint8_t)(v & 0xFF); carry = v >> 8;
        }
        int pos = i + 32;
        while (carry && pos < 64) {
            uint32_t v = (uint32_t)t[pos] + carry;
            t[pos] = (uint8_t)(v & 0xFF); carry = v >> 8; pos++;
        }
    }
    uint32_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t v = (uint32_t)t[i] + (uint32_t)r[i] + carry;
        t[i] = (uint8_t)(v & 0xFF); carry = v >> 8;
    }
    int pos = 32;
    while (carry && pos < 64) {
        uint32_t v = (uint32_t)t[pos] + carry;
        t[pos] = (uint8_t)(v & 0xFF); carry = v >> 8; pos++;
    }
    uint8_t S[32]; sc_reduce(S, t);
    memcpy(sig, Rbytes, 32); memcpy(sig + 32, S, 32);
    return 0;
}
int myssh_ed25519_verify(const uint8_t pub[32], const uint8_t *m, size_t mlen, const uint8_t sig[64]) {
    uint8_t Abytes[32], Rbytes[32], S[32];
    memcpy(Abytes, pub, 32); memcpy(Rbytes, sig, 32); memcpy(S, sig + 32, 32);
    int cmp = 0;
    for (int i = 31; i >= 0; i--)
        if (S[i] != ED_L[i]) { cmp = (S[i] > ED_L[i]) ? 1 : -1; break; }
    if (cmp >= 0) return 0;
    fe Ax, Ay, Rx, Ry;
    if (fe_frombytes_neg_x(Ax, Abytes) != 0) return 0;
    { uint8_t y[32]; memcpy(y, Abytes, 32); y[31] &= 0x7F; fe_frombytes(Ay, y); }
    if (fe_frombytes_neg_x(Rx, Rbytes) != 0) return 0;
    { uint8_t y[32]; memcpy(y, Rbytes, 32); y[31] &= 0x7F; fe_frombytes(Ry, y); }
    sha512_ctx kctx; sha512_init(&kctx);
    sha512_update(&kctx, Rbytes, 32); sha512_update(&kctx, Abytes, 32);
    if (mlen) sha512_update(&kctx, m, mlen);
    uint8_t khash[64]; sha512_final(&kctx, khash);
    uint8_t k[32]; sc_reduce(k, khash);
    ge_p3 Ap, Rp;
    fe_copy(Ap.X, Ax); fe_copy(Ap.Y, Ay); fe_1(Ap.Z); fe_mul(Ap.T, Ap.X, Ap.Y);
    fe_copy(Rp.X, Rx); fe_copy(Rp.Y, Ry); fe_1(Rp.Z); fe_mul(Rp.T, Rp.X, Rp.Y);
    ge_p3 SB; ge_scalarmult_base(&SB, S);
    ge_p3 kA; ge_scalarmult(&kA, k, &Ap);
    ge_p3 rhs; ge_add(&rhs, &Rp, &kA);
    uint8_t lb[32], rb[32];
    ge_tobytes(lb, &SB); ge_tobytes(rb, &rhs);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= lb[i] ^ rb[i];
    return diff == 0 ? 1 : 0;
}
