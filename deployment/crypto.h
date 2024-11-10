#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define KEY_SIZE 16 // 128 bits
#define BLOCK_SIZE 16

int aes_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key);
int aes_decrypt(const uint8_t *ciphertext, uint8_t *plaintext, const uint8_t *key);

#endif // CRYPTO_H
