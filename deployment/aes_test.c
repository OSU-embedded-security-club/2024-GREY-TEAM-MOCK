#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/cbc_mode.h>
#include <tinycrypt/utils.h>
#include <stdio.h>

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

int main() {
    // Test key and plaintext
    uint8_t key[KEY_SIZE] = { 0x34, 0x72, 0xCA, 0xC4, 0xB3, 0x2D, 0xCD, 0x56, 0x40, 0x79, 0xB0, 0x7A, 0x05, 0x09, 0x28, 0x67 };
    uint8_t plaintext[BLOCK_SIZE] = "Secret Message!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    printf("Original plaintext: %s\n", plaintext);

    // Encrypt the plaintext
    if (aes_encrypt(plaintext, ciphertext, key) != 0) {
        printf("Encryption failed!\n");
        return -1;
    }
    printf("Ciphertext: ");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    if (aes_decrypt(ciphertext, decrypted, key) != 0) {
        printf("Decryption failed!\n");
        return -1;
    }
    printf("Decrypted text: %s\n", decrypted);

    // Verify if decryption matches the original plaintext
    if (memcmp(plaintext, decrypted, BLOCK_SIZE) == 0) {
        printf("Success: Decrypted text matches original plaintext!\n");
    } else {
        printf("Failure: Decrypted text does not match original plaintext.\n");
    }

    return 0;
}