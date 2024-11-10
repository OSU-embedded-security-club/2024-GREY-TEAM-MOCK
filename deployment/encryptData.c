#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/cbc_mode.h>
#include <tinycrypt/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "global_secrets.h"

#define INPUT_FILE "../component/inc/ectf_params.h"
#define MAX_LINE_SIZE 256

int extract_text(char *line, char *target) {
    char *start = strstr(line, "\"");
    if (!start) return -1;
    char *end = strstr(start + 1, "\"");
    if (!end) return -1;

    strncpy(target, start + 1, end - start - 1);
    target[end - start - 1] = '\0';
    return 0;
}

int encrypt_value(const char *target_def) {
    FILE *input = fopen(INPUT_FILE, "r");
    if (input == NULL) {
        perror("Error opening file");
        return -1;
    }

    uint8_t key[KEY_SIZE] = SECRET;
    char target[BLOCK_SIZE] = {0};  
    uint8_t ciphertext[BLOCK_SIZE] = {0};
    char decrypted_text[BLOCK_SIZE] = {0};
    char *file_content = NULL;
    size_t file_size = 0;

    // Load the entire file into memory
    fseek(input, 0, SEEK_END);
    file_size = ftell(input);
    fseek(input, 0, SEEK_SET);
    file_content = malloc(file_size + 1);
    if (!file_content) {
        perror("Memory allocation failed");
        fclose(input);
        return -1;
    }
    fread(file_content, 1, file_size, input);
    file_content[file_size] = '\0';
    fclose(input);

    // Locate and replace the target line
    char *target_line = strstr(file_content, target_def);
    if (!target_line || extract_text(target_line, target) != 0) {
        printf("Failed to find or extract target\n");
        free(file_content);
        return -1;
    }

    printf("Original Value: %s\n", target);

    // Encrypt the target
    if (aes_encrypt((uint8_t *)target, ciphertext, key) != 0) {
        printf("Encryption failed!\n");
        free(file_content);
        return -1;
    }

    // Print the encrypted text in hex format
    printf("Encrypted target (hex): ");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("0x%02X ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    if (aes_decrypt(ciphertext, (uint8_t *)decrypted_text, key) != 0) {
        printf("Decryption failed!\n");
        free(file_content);
        return -1;
    }

    printf("Decrypted Value: %s\n", decrypted_text);

    // Prepare the new value line
    char encrypted_pin_line[MAX_LINE_SIZE];
    snprintf(encrypted_pin_line, sizeof(encrypted_pin_line), "#define %s ", target_def + 8);
    for (int i = 0; i < BLOCK_SIZE; i++) {
        char hex_value[6];
        snprintf(hex_value, sizeof(hex_value), "0x%02X", ciphertext[i]);
        strcat(encrypted_pin_line, hex_value);
        if (i < BLOCK_SIZE - 1) {
            strcat(encrypted_pin_line, ", ");
        }
    }
    strcat(encrypted_pin_line, "\n");

    // Replace the target_line in file content
    char *next_line = strchr(target_line, '\n');
    size_t offset = next_line ? (next_line - file_content) + 1 : file_size;
    size_t before_pin_size = target_line - file_content;
    size_t after_pin_size = file_size - offset;

    FILE *output = fopen(INPUT_FILE, "w");
    if (output == NULL) {
        perror("Error opening file for writing");
        free(file_content);
        return -1;
    }

    // Write modified content back to the file
    fwrite(file_content, 1, before_pin_size, output);
    fwrite(encrypted_pin_line, 1, strlen(encrypted_pin_line), output);
    fwrite(file_content + offset, 1, after_pin_size, output);

    fclose(output);
    free(file_content);
    printf("Value updated successfully with encrypted value in %s.\n", INPUT_FILE);
    return 0;
}

int main() {
    encrypt_value("#define ATTESTATION_LOC");
    encrypt_value("#define ATTESTATION_DATE");
    encrypt_value("#define ATTESTATION_CUSTOMER");
    return 0;
}
