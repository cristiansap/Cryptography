#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

    char key_str[] = "012340123401234012340123401234012340123401234012";
    char iv_str[]  = "ABCDEFABCDEFABCDEFABCDEFABCDEFAB";
    unsigned char iv[strlen(iv_str)/2];
    unsigned char key[strlen(key_str)/2];

    for(int i = 0; i < strlen(key_str)/2;i++){
       sscanf(&key_str[2*i],"%2hhx", &key[i]);
    }
    for(int i = 0; i < strlen(iv_str)/2;i++){
       sscanf(&iv_str[2*i],"%2hhx", &iv[i]);
    }

    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx, EVP_camellia_192_cbc(), key, iv, ENCRYPT))
        handle_errors();

    int update_length, final_len;
    unsigned char ciphertext[MAX_BUFFER+16];

    int n_read;
    int ciphertext_len = 0;
    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer, 1, MAX_BUFFER, stdin)) > 0){
        if(!EVP_CipherUpdate(ctx, ciphertext + ciphertext_len, &update_length, buffer, n_read))
            handle_errors();
        
        fwrite(ciphertext, 1, update_length, stdout);
        ciphertext_len += update_length;
    }
            
    if(!EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &final_len))
        handle_errors();
 
    fwrite(ciphertext, 1, final_len, stdout);

    ciphertext_len += final_len;
    
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

