#ifndef MYSSH_PRIMITIVES_H
#define MYSSH_PRIMITIVES_H
#include <stddef.h>
#include <stdint.h>
#include <stddef.h>

/* SHA-3 / SHAKE */
#include "sha3.h"

/* ML-KEM */
#include "mlkem.h"
#ifdef __cplusplus
extern "C" {
#endif

/* SHA-2 (FIPS 180-4) */
void myssh_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void myssh_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/* X25519 (RFC 7748) */
int myssh_x25519_scalarmult_base(const uint8_t k[32], uint8_t out[32]);
int myssh_x25519_scalarmult(const uint8_t k[32], const uint8_t p[32], uint8_t out[32]);

/* AES-256-GCM */
int myssh_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *pt,  size_t pt_len,
                             uint8_t *out);
int myssh_aes256_ctr(const uint8_t key[32], const uint8_t iv[16],
                     const uint8_t *in, size_t inlen, uint8_t *out);

int myssh_aes256_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *in,  size_t in_len,
                             uint8_t *out);

/* bcrypt_pbkdf (OpenSSH KDF) */
int myssh_bcrypt_pbkdf(const uint8_t *password, size_t plen,
                       const uint8_t *salt,     size_t slen,
                       uint8_t       *key,      size_t keylen,
                       uint32_t rounds);

/* Ed25519 (RFC 8032) */
void myssh_ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32]);
int  myssh_ed25519_sign  (const uint8_t seed[32],
                          const uint8_t *msg, size_t msglen,
                          uint8_t sig[64]);
int  myssh_ed25519_verify(const uint8_t pub[32],
                          const uint8_t *msg, size_t msglen,
                          const uint8_t sig[64]);

#ifdef __cplusplus
}
#endif
#endif
