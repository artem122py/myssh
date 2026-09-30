#ifndef MYSSH_RSA_H
#define MYSSH_RSA_H
#include <stdint.h>
#include <stddef.h>

/* Размеры в битах: 1024, 2048, 3072, 4096. */
#define MYSSH_RSA_MAX_BITS   4096
#define MYSSH_RSA_MAX_BYTES  (MYSSH_RSA_MAX_BITS / 8)

/* Кодирование PKCS#1 v1.5 EMSA */
#define MYSSH_RSA_HASH_SHA256 1
#define MYSSH_RSA_HASH_SHA512 2

/* ---- публичный API ----
 * Все ключи — в виде SSH mpint blob:
 *   n, e для public
 *   n, e, d, iqmp, p, q для private
 *
 * sign:      принимает приватный блоб, hash_algo (SHA256/512), msg_hash
 *            (уже посчитанный хеш сообщения), возвращает подпись
 * verify:    принимает публичный блоб, hash_algo, msg_hash, sig
 *            возвращает 1 при успехе, 0 иначе
 * keygen:    генерирует новую пару, возвращает priv_blob, pub_blob
 */

int myssh_rsa_sign(const uint8_t *priv_blob, size_t priv_len,
                   int hash_algo,
                   const uint8_t *msg_hash, size_t hash_len,
                   uint8_t *sig, size_t *sig_len);

int myssh_rsa_verify(const uint8_t *pub_blob, size_t pub_len,
                     int hash_algo,
                     const uint8_t *msg_hash, size_t hash_len,
                     const uint8_t *sig, size_t sig_len);

int myssh_rsa_keygen(int bits, uint8_t *pub_blob, size_t *pub_len,
                     uint8_t *priv_blob, size_t *priv_len);

#endif
