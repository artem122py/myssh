#ifndef MYSSH_MLKEM_H
#define MYSSH_MLKEM_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ML-KEM-768 (FIPS 203) */
#define MLKEM768_PUBLICKEYBYTES   1184
#define MLKEM768_SECRETKEYBYTES   2400
#define MLKEM768_CIPHERTEXTBYTES  1088
#define MLKEM768_SSBYTES            32
#define MLKEM768_KEYPAIRCOINBYTES   64
#define MLKEM768_ENCCOINBYTES       32

/* NTT (низкоуровневый API, для тестов) */
void myssh_mlkem_ntt(int16_t a[256]);
void myssh_mlkem_invntt(int16_t a[256]);
void myssh_mlkem_basemul(int16_t r[256],
                         const int16_t a[256],
                         const int16_t b[256]);

/* KEM API */
int myssh_mlkem768_keygen(uint8_t ek[MLKEM768_PUBLICKEYBYTES],
                          uint8_t dk[MLKEM768_SECRETKEYBYTES],
                          const uint8_t coins[MLKEM768_KEYPAIRCOINBYTES]);

int myssh_mlkem768_encaps(uint8_t ss[MLKEM768_SSBYTES],
                          uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                          const uint8_t ek[MLKEM768_PUBLICKEYBYTES],
                          const uint8_t coins[MLKEM768_ENCCOINBYTES]);

int myssh_mlkem768_decaps(uint8_t ss[MLKEM768_SSBYTES],
                          const uint8_t ct[MLKEM768_CIPHERTEXTBYTES],
                          const uint8_t dk[MLKEM768_SECRETKEYBYTES]);

/* Самотест NTT. 0=ok, отрицательное=fail */
void myssh_mlkem_dbg_basemul_roundtrip(const int16_t a[256], const int16_t b[256], int16_t out[256]);
void myssh_mlkem_dbg_ntt(const int16_t in[256], int16_t out[256]);
void myssh_mlkem_dbg_invntt(const int16_t in[256], int16_t out[256]);
int16_t myssh_mlkem_dbg_fqmul(int16_t a, int16_t b);
void myssh_mlkem_dbg_sample_ntt(const uint8_t rho[32], uint8_t j, uint8_t i, int16_t out[256]);
int myssh_mlkem_selftest(void);
int myssh_mlkem_extended_test(void);

#ifdef __cplusplus
}
#endif
#endif
