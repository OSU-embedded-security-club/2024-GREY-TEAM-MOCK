#include <tinycrypt/aes.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/cbc_mode.h>
#include <tinycrypt/utils.h>
#include <internal.h>

// AES 128 encryption
int aes_encrypt(const uint8_t *plaintext, uint8_t *ciphertext, const uint8_t *key) {
    struct tc_aes_key_sched_struct aes_key_sched;
    uint8_t iv[TC_AES_BLOCK_SIZE] = {0}; // Initialization vector
    uint8_t temp[TC_AES_BLOCK_SIZE];

    // Set the key
    if (tc_aes128_set_encrypt_key(key, &aes_key_sched) != TC_CRYPTO_SUCCESS) {
        return -1; // Key setup failed
    }

    // Encrypt each block
    for (size_t i = 0; i < AES_BLOCK_SIZE; i += TC_AES_BLOCK_SIZE) {
        memcpy(temp, &plaintext[i], TC_AES_BLOCK_SIZE);
        tc_aes_encrypt(temp, ciphertext + i, &aes_key_sched);
    }

    return 0; // Success
}

// AES 128 decryption
int aes_decrypt(const uint8_t *ciphertext, uint8_t *plaintext, const uint8_t *key) {
    struct tc_aes_key_sched_struct aes_key_sched;
    uint8_t iv[TC_AES_BLOCK_SIZE] = {0}; // Initialization vector
    uint8_t temp[TC_AES_BLOCK_SIZE];

    // Set the key
    if (tc_aes128_set_decrypt_key(key, &aes_key_sched) != TC_CRYPTO_SUCCESS) {
        return -1; // Key setup failed
    }

    // Decrypt each block
    for (size_t i = 0; i < AES_BLOCK_SIZE; i += TC_AES_BLOCK_SIZE) {
        memcpy(temp, &ciphertext[i], TC_AES_BLOCK_SIZE);
        tc_aes_decrypt(temp, plaintext + i, &aes_key_sched);
    }

    return 0; // Success
}

