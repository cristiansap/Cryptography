#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>


void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *base64_decode(const char *input, int *output_len) {
    int input_len = strlen(input);
    int decoded_len = (input_len * 3) / 4;  // Estimation of decoded length (every 3 bytes of original data are represented with 4 Base64 characters)
    unsigned char *output = malloc(decoded_len);
    
    if (!output) {
        printf("\nError with the allocation of the output string!\n");
        return NULL;  // Error
    }

    // Perform decoding
    int actual_len = EVP_DecodeBlock(output, (const unsigned char *)input, input_len);
    
    if (actual_len < 0) { 
        free(output);
        return NULL;  // Error
    }

    // Remove any '=' padding from the actual length
    while (input[input_len - 1] == '=') {
        actual_len--;
        input_len--;
    }

    *output_len = actual_len;
    return output;
}


int main() {
    unsigned char b64_ciphertext[] = "jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==";  // Base64 encoded (every 3 bytes of original data are represented with 4 Base64 characters)
    unsigned char key_hex[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    unsigned char iv_hex[] = "11111111111111112222222222222222";

    // Convert the hex key into bytes
    unsigned char key[strlen(key_hex)/2], iv[strlen(iv_hex)/2];
    for (int i = 0; i < strlen(key_hex)/2; i++) {
        sscanf(&key_hex[2 * i], "%2hhx", &key[i]);
    }

    // Convert the hex iv into bytes
    for (int i = 0; i < strlen(iv_hex)/2; i++) {
        sscanf(&iv_hex[2 * i], "%2hhx", &iv[i]);
    }

    int ciphertex_len;
    unsigned char *ciphertext = base64_decode(b64_ciphertext, &ciphertex_len);
    unsigned char plaintext[ciphertex_len];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CipherInit(ctx, EVP_chacha20(), key, iv, 0))   // use chacha20() like the file 'code.c' does
        handle_errors();

    int out_len;
    if (!EVP_CipherUpdate(ctx, plaintext, &out_len, ciphertext, ciphertex_len))
        handle_errors();

    int final_len;
    if (!EVP_CipherFinal_ex(ctx, plaintext + out_len, &final_len))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    
    plaintext[out_len + final_len] = '\0';
    printf("Decrypted flag: %s\n", plaintext);
    return 0;
}
