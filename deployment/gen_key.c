#include <stdio.h>
#include "../tinycrypt/lib/include/tinycrypt/aes.h"
#include "../tinycrypt/lib/include/tinycrypt/constants.h"
#include "../tinycrypt/lib/include/tinycrypt/ctr_prng.h"
#include <string.h>

#define KEY_LENGTH 16 // AES-128 key length in bytes

int main(void) {
    TCCtrPrng_t ctx;
    uint8_t entropy[TC_AES_KEY_SIZE + TC_AES_BLOCK_SIZE]; // For entropy
    uint8_t key[KEY_LENGTH];
    int result;

    // Initialize the entropy (this should be securely generated in a real application)
    for (int i = 0; i < sizeof(entropy); i++) {
        entropy[i] = (uint8_t)(i + 1); // Placeholder for actual entropy
    }

    // Initialize the PRNG
    result = tc_ctr_prng_init(&ctx, entropy, sizeof(entropy), NULL, 0);
    if (result != TC_CRYPTO_SUCCESS) {
        printf("PRNG initialization failed\n");
        return 1;
    }

    // Generate a random key
    result = tc_ctr_prng_generate(&ctx, NULL, 0, key, sizeof(key));
    if (result != TC_CRYPTO_SUCCESS) {
        printf("Key generation failed\n");
        return 1;
    }

    // Write the key to global_secrets.h
    FILE *file = fopen("global_secrets.h", "w");
    if (file == NULL) {
        printf("Failed to open global_secrets.h for writing\n");
        return 1;
    }
    fprintf(file, "#define SECRET { ");
    for (int i = 0; i < KEY_LENGTH; i++) {
        fprintf(file, "0x%02X", key[i]);
        if (i < KEY_LENGTH - 1) {
            fprintf(file, ", ");
        }
    }
    fprintf(file, " }\n");
    fclose(file);

    return 0;
}