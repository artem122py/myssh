/* rsa.c — RSA-1024/2048/3072/4096, PKCS#1 v1.5 подписи.
 *
 * Всё на uint32_t big-int (little-endian limbs).
 * Modexp — square-and-multiply с окном 4 бита.
 * Никаких зависимостей.
 *
 * PKCS#1 v1.5:
 *   EM = 0x00 || 0x01 || 0xFF...(k - tLen - 3) || 0x00 || T
 *   где T = DigestInfo (DER с OID хеша) || hash
 */
#include "rsa.h"
#include <stdio.h>
#include <string.h>

/* =====================================================================
 * Bignum: uint32_t limbs, little-endian.
 * ===================================================================== */
#define BN_LIMBS ((MYSSH_RSA_MAX_BITS / 32) + 2)

typedef struct {
    uint32_t d[BN_LIMBS];
    int n;              /* число занятых лимбов */
} bn_t;

static void bn_zero(bn_t *a) { memset(a, 0, sizeof(*a)); }

static void bn_copy(bn_t *r, const bn_t *a) {
    memcpy(r->d, a->d, sizeof(a->d));
    r->n = a->n;
}

static int bn_cmp(const bn_t *a, const bn_t *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}

static void bn_trim(bn_t *a) {
    while (a->n > 0 && a->d[a->n - 1] == 0) a->n--;
}

/* r = a + b */
static void bn_add(bn_t *r, const bn_t *a, const bn_t *b) {
    int n = a->n > b->n ? a->n : b->n;
    uint64_t carry = 0;
    for (int i = 0; i < n; i++) {
        uint64_t sum = carry + (i < a->n ? a->d[i] : 0)
                             + (i < b->n ? b->d[i] : 0);
        r->d[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    r->n = n;
    if (carry && n < BN_LIMBS) r->d[r->n++] = (uint32_t)carry;
    bn_trim(r);
}

/* r = a - b, требует a >= b */
static void bn_sub(bn_t *r, const bn_t *a, const bn_t *b) {
    int64_t borrow = 0;
    int n = a->n;
    for (int i = 0; i < n; i++) {
        int64_t diff = (int64_t)a->d[i] - (i < b->n ? b->d[i] : 0) - borrow;
        if (diff < 0) { diff += 0x100000000LL; borrow = 1; } else borrow = 0;
        r->d[i] = (uint32_t)diff;
    }
    r->n = n;
    bn_trim(r);
}

/* r = a * b (школьный алгоритм) */
static void bn_mul(bn_t *r, const bn_t *a, const bn_t *b) {
    bn_zero(r);
    if (a->n == 0 || b->n == 0) return;
    int rn = a->n + b->n;
    if (rn > BN_LIMBS) rn = BN_LIMBS;
    for (int i = 0; i < a->n && i < rn; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->n && i + j < rn; j++) {
            uint64_t prod = (uint64_t)a->d[i] * b->d[j]
                          + r->d[i + j] + carry;
            r->d[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        int k = i + b->n;
        while (carry && k < rn) {
            uint64_t s = (uint64_t)r->d[k] + carry;
            r->d[k] = (uint32_t)s;
            carry = s >> 32;
            k++;
        }
    }
    r->n = rn;
    bn_trim(r);
}

/* r = a mod m (деление школьное, побитовое вычитание сдвигов) */
static int _mod_calls = 0;
/* r = a mod m — побитовое деление (медленное, но корректное) */
static void bn_mod(bn_t *r, const bn_t *a, const bn_t *m) {
    if (m->n == 0) { bn_zero(r); return; }
    if (bn_cmp(a, m) < 0) { bn_copy(r, a); return; }

    bn_t rem;
    bn_zero(&rem);

    /* Найдём старший установленный бит в a */
    int top_bit = -1;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->d[i] != 0) {
            uint32_t v = a->d[i];
            int b = 31;
            while (!((v >> b) & 1)) b--;
            top_bit = i * 32 + b;
            break;
        }
    }
    if (top_bit < 0) { bn_zero(r); return; }

    for (int i = top_bit; i >= 0; i--) {
        /* rem <<= 1 */
        uint32_t carry = 0;
        for (int j = 0; j < rem.n; j++) {
            uint32_t nc = rem.d[j] >> 31;
            rem.d[j] = (rem.d[j] << 1) | carry;
            carry = nc;
        }
        if (carry) {
            if (rem.n < BN_LIMBS) rem.d[rem.n++] = carry;
        }
        /* rem |= bit i из a */
        int limb = i / 32;
        int bit = i % 32;
        if (limb < a->n && ((a->d[limb] >> bit) & 1)) {
            rem.d[0] |= 1;
            if (rem.n == 0) rem.n = 1;
        }
        /* if rem >= m: rem -= m */
        if (bn_cmp(&rem, m) >= 0) {
            bn_sub(&rem, &rem, m);
        }
    }
    bn_copy(r, &rem);
    bn_trim(r);
}

/* =====================================================================
 * Montgomery modexp (basics): r = base^exp mod m
 * Используем простой square-and-multiply с mod на каждом шаге.
 * ===================================================================== */
static void bn_modexp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *m) {

    bn_t b, e, t;
    bn_copy(&b, base);
    bn_copy(&e, exp);
    bn_zero(r);
    r->d[0] = 1;
    r->n = 1;

    int total_bits = e.n * 32;
    int iterations = 0;
    for (int i = 0; i < e.n; i++) {
        uint32_t word = e.d[i];
        for (int bit = 0; bit < 32; bit++) {
            iterations++;
            if (iterations <= 5) {
            }
            if (word & 1) {
                bn_mul(&t, r, &b);
                bn_mod(r, &t, m);
            }
            bn_mul(&t, &b, &b);
            bn_mod(&b, &t, m);
            word >>= 1;
        }
    }
}
/* =====================================================================
 * Разбор SSH mpint / blob
 * ===================================================================== */
static int read_ssh_string(const uint8_t *buf, size_t buf_len, size_t *off,
                           const uint8_t **out, size_t *out_len) {
    if (*off + 4 > buf_len) return -1;
    uint32_t n = ((uint32_t)buf[*off] << 24) | ((uint32_t)buf[*off+1] << 16)
               | ((uint32_t)buf[*off+2] << 8) | (uint32_t)buf[*off+3];
    *off += 4;
    if (*off + n > buf_len) return -1;
    *out = buf + *off;
    *out_len = n;
    *off += n;
    return 0;
}

/* mpint (big-endian) -> bn_t (little-endian) */
static int bn_from_mpint(bn_t *r, const uint8_t *be, size_t len) {
    bn_zero(r);
    /* Пропускаем ведущие нули */
    while (len > 0 && *be == 0) { be++; len--; }
    int limb = 0;
    for (size_t i = len; i > 0; ) {
        size_t take = (i >= 4) ? 4 : i;
        uint32_t word = 0;
        for (size_t j = 0; j < take; j++) {
            word = (word << 8) | be[i - take + j];
        }
        r->d[limb++] = word;
        i -= take;
        if (limb >= BN_LIMBS) break;
    }
    r->n = limb;
    bn_trim(r);
    return 0;
}

/* bn_t -> mpint big-endian, без ведущих нулей, с 0x00 если старший бит 1 */
static int bn_to_mpint(uint8_t *out, size_t *out_len, const bn_t *a) {
    if (a->n == 0) { out[0] = 0; *out_len = 1; return 0; }

    /* Найдём старший значащий бит */
    int top_bit = -1;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->d[i] != 0) {
            int b = 31;
            while (b >= 0 && !((a->d[i] >> b) & 1)) b--;
            top_bit = i * 32 + b;
            break;
        }
    }
    if (top_bit < 0) { out[0] = 0; *out_len = 1; return 0; }

    size_t nbytes = (size_t)(top_bit / 8) + 1;
    size_t pad = ((top_bit % 8) == 7) ? 1 : 0;

    size_t off = 0;
    if (pad) out[off++] = 0;

    for (size_t k = nbytes; k > 0; k--) {
        size_t byte_idx = k - 1;
        size_t limb_idx = byte_idx / 4;
        size_t byte_in_limb = byte_idx % 4;
        uint32_t word = (limb_idx < (size_t)a->n) ? a->d[limb_idx] : 0;
        out[off++] = (uint8_t)((word >> (byte_in_limb * 8)) & 0xFF);
    }
    *out_len = off;
    return 0;
}

/* =====================================================================
 * PKCS#1 v1.5 DigestInfo prefixes
 * ===================================================================== */
static const uint8_t SHA256_PREFIX[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,
    0x05,0x00,0x04,0x20
};
static const uint8_t SHA512_PREFIX[] = {
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,
    0x05,0x00,0x04,0x40
};

/* =====================================================================
 * sign / verify
 * ===================================================================== */
int myssh_rsa_sign(const uint8_t *priv_blob, size_t priv_len,
                   int hash_algo,
                   const uint8_t *msg_hash, size_t hash_len,
                   uint8_t *sig, size_t *sig_len) {
    if (hash_algo != MYSSH_RSA_HASH_SHA256 && hash_algo != MYSSH_RSA_HASH_SHA512)
        return -1;
    if (hash_algo == MYSSH_RSA_HASH_SHA256 && hash_len != 32) return -1;
    if (hash_algo == MYSSH_RSA_HASH_SHA512 && hash_len != 64) return -1;

    /* Парсим приватный blob: n, e, d, iqmp, p, q */
    size_t off = 0;
    const uint8_t *be; size_t bl;

    if (read_ssh_string(priv_blob, priv_len, &off, &be, &bl) < 0) return -1;
    bn_t n; bn_from_mpint(&n, be, bl);
    if (read_ssh_string(priv_blob, priv_len, &off, &be, &bl) < 0) return -1;
    bn_t e; bn_from_mpint(&e, be, bl);
    if (read_ssh_string(priv_blob, priv_len, &off, &be, &bl) < 0) return -1;
    bn_t d; bn_from_mpint(&d, be, bl);
    if (read_ssh_string(priv_blob, priv_len, &off, &be, &bl) < 0) return -1;
    bn_t iqmp; bn_from_mpint(&iqmp, be, bl);
    if (read_ssh_string(priv_blob, priv_len, &off, &be, &bl) < 0) return -1;
    bn_t p; bn_from_mpint(&p, be, bl);
    if (read_ssh_string(priv_blob, priv_len, &off, &be, &bl) < 0) return -1;
    bn_t q; bn_from_mpint(&q, be, bl);

    /* k = длина n в байтах */
    size_t k = (n.n > 0) ? (n.n - 1) * 4 : 0;
    if (n.n > 0) {
        uint32_t top = n.d[n.n - 1];
        while (top) { k++; top >>= 8; }
    }
    if (k == 0 || k > MYSSH_RSA_MAX_BYTES) {
        return -1;
    }

    /* EM = 0x00 || 0x01 || 0xFF...(k - tLen - 3) || 0x00 || T */
    const uint8_t *prefix = (hash_algo == MYSSH_RSA_HASH_SHA256)
                             ? SHA256_PREFIX : SHA512_PREFIX;
    size_t prefix_len = (hash_algo == MYSSH_RSA_HASH_SHA256)
                         ? sizeof(SHA256_PREFIX) : sizeof(SHA512_PREFIX);
    size_t tlen = prefix_len + hash_len;
    if (k < tlen + 11) return -1;

    uint8_t em[MYSSH_RSA_MAX_BYTES];
    em[0] = 0x00;
    em[1] = 0x01;
    size_t ps_len = k - tlen - 3;
    memset(em + 2, 0xFF, ps_len);
    em[2 + ps_len] = 0x00;
    memcpy(em + 3 + ps_len, prefix, prefix_len);
    memcpy(em + 3 + ps_len + prefix_len, msg_hash, hash_len);

    /* m = OS2IP(EM) */
    bn_t m; bn_zero(&m);
    for (size_t i = 0; i < k; i++) {
        /* big-endian em -> bn little-endian */
        size_t idx = (k - 1 - i);
        int limb = (int)(i / 4);
        int shift = (int)((i % 4) * 8);
        m.d[limb] |= ((uint32_t)em[idx]) << shift;
    }
    m.n = (int)((k + 3) / 4);
    bn_trim(&m);

    /* s = m^d mod n */
    bn_t s; bn_modexp(&s, &m, &d, &n);

    /* s -> bytes в sig, padded до k */
    uint8_t tmp[MYSSH_RSA_MAX_BYTES];
    size_t tmp_len = 0;
    bn_to_mpint(tmp, &tmp_len, &s);

    /* Убираем ведущий 0x00 если он есть (это mpint-pad) */
    if (tmp_len > 0 && tmp[0] == 0x00 && tmp_len - 1 <= k) {
        memmove(tmp, tmp + 1, tmp_len - 1);
        tmp_len--;
    }
    if (tmp_len > k) return -1;
    if (tmp_len > k) return -1;
    memset(sig, 0, k - tmp_len);
    memcpy(sig + (k - tmp_len), tmp, tmp_len);
    *sig_len = k;
    return 0;
}

int myssh_rsa_verify(const uint8_t *pub_blob, size_t pub_len,
                     int hash_algo,
                     const uint8_t *msg_hash, size_t hash_len,
                     const uint8_t *sig, size_t sig_len) {
    if (hash_algo != MYSSH_RSA_HASH_SHA256 && hash_algo != MYSSH_RSA_HASH_SHA512)
        return 0;
    if (hash_algo == MYSSH_RSA_HASH_SHA256 && hash_len != 32) return 0;
    if (hash_algo == MYSSH_RSA_HASH_SHA512 && hash_len != 64) return 0;

    size_t off = 0;
    const uint8_t *be; size_t bl;
    if (read_ssh_string(pub_blob, pub_len, &off, &be, &bl) < 0) return 0;
    bn_t e; bn_from_mpint(&e, be, bl);
    if (read_ssh_string(pub_blob, pub_len, &off, &be, &bl) < 0) return 0;
    bn_t n; bn_from_mpint(&n, be, bl);

    /* k = размер n в байтах */
    size_t k = (n.n > 0) ? (n.n - 1) * 4 : 0;
    if (n.n > 0) {
        uint32_t top = n.d[n.n - 1];
        while (top) { k++; top >>= 8; }
    }
    if (k == 0 || sig_len != k) return 0;

    /* s = OS2IP(sig) */
    bn_t s; bn_zero(&s);
    for (size_t i = 0; i < k; i++) {
        size_t idx = k - 1 - i;
        int limb = (int)(i / 4);
        int shift = (int)((i % 4) * 8);
        s.d[limb] |= ((uint32_t)sig[idx]) << shift;
    }
    s.n = (int)((k + 3) / 4);
    bn_trim(&s);

    /* m = s^e mod n */
    bn_t m; bn_modexp(&m, &s, &e, &n);

    /* m -> EM, padded до k */
    uint8_t em[MYSSH_RSA_MAX_BYTES];
    uint8_t tmp[MYSSH_RSA_MAX_BYTES];
    size_t tmp_len = 0;
    bn_to_mpint(tmp, &tmp_len, &m);
    if (tmp_len > 0 && tmp[0] == 0x00 && tmp_len - 1 <= k) {
        memmove(tmp, tmp + 1, tmp_len - 1);
        tmp_len--;
    }
    if (tmp_len > k) return 0;
    memset(em, 0, k - tmp_len);
    memcpy(em + (k - tmp_len), tmp, tmp_len);

    /* Проверим EM: 0x00 || 0x01 || 0xFF... || 0x00 || T */
    const uint8_t *prefix = (hash_algo == MYSSH_RSA_HASH_SHA256)
                             ? SHA256_PREFIX : SHA512_PREFIX;
    size_t prefix_len = (hash_algo == MYSSH_RSA_HASH_SHA256)
                         ? sizeof(SHA256_PREFIX) : sizeof(SHA512_PREFIX);
    size_t tlen = prefix_len + hash_len;
    if (k < tlen + 11) return 0;

    if (em[0] != 0x00 || em[1] != 0x01) return 0;
    size_t ps_len = k - tlen - 3;
    for (size_t i = 0; i < ps_len; i++) {
        if (em[2 + i] != 0xFF) {
            return 0;
        }
    }
    if (em[2 + ps_len] != 0x00) return 0;

    /* constant-time compare T */
    uint8_t diff = 0;
    for (size_t i = 0; i < prefix_len; i++)
        diff |= em[3 + ps_len + i] ^ prefix[i];
    for (size_t i = 0; i < hash_len; i++)
        diff |= em[3 + ps_len + prefix_len + i] ^ msg_hash[i];
    return diff == 0 ? 1 : 0;
}

/* =====================================================================
 * keygen (для тестов; в реальности ключи подсовываются из Python)
 * Пока не реализован — заглушка возвращает -1.
 * Генерацию делаем в Python: secrets + sympy-стиль Миллера-Рабина.
 * ===================================================================== */
int myssh_rsa_keygen(int bits, uint8_t *pub_blob, size_t *pub_len,
                     uint8_t *priv_blob, size_t *priv_len) {
    (void)bits; (void)pub_blob; (void)pub_len;
    (void)priv_blob; (void)priv_len;
    return -1;
}
