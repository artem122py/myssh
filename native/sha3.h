#ifndef MYSSH_SHA3_H
#define MYSSH_SHA3_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void myssh_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);
void myssh_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]);
void myssh_shake128(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
void myssh_shake256(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
int myssh_sha3_selftest(void);

#ifdef __cplusplus
}
#endif
#endif
