#include <tinycrypt/aes.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/cbc_mode.h>
#include <tinycrypt/utils.h>

#define KEY_SIZE 16 // 128 bits
#define BLOCK_SIZE 16

// AES 128 encryption
int aes_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key) {
    struct tc_aes_key_sched_struct sched;
    
    int RESULT = tc_aes128_set_encrypt_key(&sched, key);

    if (RESULT != TC_CRYPTO_SUCCESS) {
        return -1;
    }

    RESULT = tc_aes_encrypt(ciphertext, plaintext, &sched);

    if (RESULT != TC_CRYPTO_SUCCESS) {
        return -1;
    }

    return 0; // Success
}

// AES 128 decryption
int aes_decrypt(const uint8_t *ciphertext, uint8_t *plaintext, const uint8_t *key) {
    struct tc_aes_key_sched_struct sched;
    
    int RESULT = tc_aes128_set_encrypt_key(&sched, key);

    if (RESULT != TC_CRYPTO_SUCCESS) {
        return -1;
    }

    RESULT = tc_aes_decrypt(plaintext, ciphertext, &sched);

    if (RESULT != TC_CRYPTO_SUCCESS) {
        return -1;
    }

    return 0; // Success
}
