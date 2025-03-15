#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

typedef struct {
    unsigned char *ciphertext;
    int ciphertext_len;
} Info;

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

void to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char) str[i]);
    }
}

char *get_evp_method_name(const char *algorithm_name) {
    char *formatted = strdup(EVP_CIPHER_name(EVP_get_cipherbyname(algorithm_name)));
    to_lowercase(formatted);

    // Replacing "-" with "_"
    for (char *p = formatted; *p != '\0'; p++) {
        if (*p == '-')
            *p = '_';
    }

    return formatted;
}

void try_to_decrypt(const char *algorithm_name, unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv) {
    int out_len, final_len;
    unsigned char plaintext[ciphertext_len];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!EVP_CipherInit(ctx, EVP_get_cipherbyname(algorithm_name), key, iv, DECRYPT)) {
        //printf("Error: CipherInit failed for %s\n", algorithm_name);
        return;
    }
    if (!EVP_CipherUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len)) {
        //printf("Error: CipherUpdate failed for %s\n", algorithm_name);
        return;
    }
    if (!EVP_CipherFinal_ex(ctx, plaintext + out_len, &final_len)) {
        //printf("Error: CipherFinal_ex failed for %s\n", algorithm_name);
        return;
    }

    plaintext[out_len + final_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);

    // Printing out the result only if all the characters of the decrypted content are (human) readable
    int flag = 1;
    for (int i=0; i < strlen((const char *)plaintext); i++) {
        if (!(plaintext[i] >= 32 && plaintext[i] <= 126))   // ASCII readable characters go from 32 to 126
            flag = 0;   // unreadable character detected...
    }

    if (out_len + final_len > 0 && flag == 1)
        printf("Flag: CRYPTO25{%sEVP_%s}\n", plaintext, get_evp_method_name(algorithm_name));
}

// Callback to iterate over encryption algorithms
void cipher_callback(const OBJ_NAME *obj, void *ciphertext_info) {
    unsigned char key[] = "0123456789ABCDEF";   // it should NOT be interpreted as hex_string
    unsigned char iv[] = "0123456789ABCDEF";    // it should NOT be interpreted as hex_string
    
    // Cast to the correct structure type
    Info *info = (Info *)ciphertext_info;

    printf("Tried algorithm: %s\n", obj->name);
    try_to_decrypt(obj->name, info->ciphertext, info->ciphertext_len, key, iv);
}

int main() {
    unsigned char b64_ciphertext[] = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";  // Base64 encoded (every 3 bytes of original data are represented with 4 Base64 characters)
    int ciphertext_len;
    unsigned char *ciphertext = base64_decode((const char*)b64_ciphertext, &ciphertext_len);

    printf("Ciphertext decoded: %s\n", ciphertext);

    // Struct to hold ciphertext info for callback
    Info info = {ciphertext, ciphertext_len};

    // Iterate over all available encryption algorithms
    OpenSSL_add_all_ciphers();
    OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, cipher_callback, (void *)&info);

    free(ciphertext);
    
    return 0;
}
