#ifndef MYSSH_CHACHA_H
#define MYSSH_CHACHA_H
#include <stdint.h>
#include <stddef.h>

int myssh_chacha20_poly1305_encrypt(const uint8_t key[64], uint64_t seq,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *out);
int myssh_chacha20_poly1305_length (const uint8_t key[64], uint64_t seq,
                                    const uint8_t ct_len[4],
                                    uint32_t *out_len);
int myssh_chacha20_poly1305_decrypt(const uint8_t key[64], uint64_t seq,
                                    const uint8_t *in, size_t in_len,
                                    uint8_t *out);
/* Самотест: проверка ChaCha20/Poly1305 против RFC 8439. Возвращает 0=ok */
int myssh_chacha20_selftest(void);
#endif
