#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv) {
  
    if (argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
        exit(1);
    }

    FILE *f_in1, *f_in2;
    if ((f_in1 = fopen(argv[1], "r")) == NULL || (f_in2 = fopen(argv[2], "r")) == NULL) {
            fprintf(stderr,"Couldn't open the first input file, try again\n");
            exit(1);
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

	EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();

    unsigned char key[] = "keykeykeykeykeykey";
    EVP_PKEY *hkey;
    hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));  // BEWARE: the last parameter has to be the length of the key (while in the professor's code is a fixed number, just for that example) !!!
 
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
        handle_errors();

    size_t n;
    unsigned char buffer[MAXBUF];

    while((n = fread(buffer, 1, MAXBUF, f_in1)) > 0){
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
            handle_errors();
    }

    while((n = fread(buffer, 1, MAXBUF, f_in2)) > 0){
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
            handle_errors();
    }

    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    size_t hmac_len = EVP_MD_size(EVP_sha256());

    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();


    printf("FLAG: CRYPTO25{");
    for(int i = 0; i < hmac_len; i++)
		printf("%02x", hmac_value[i]);
    printf("}\n");


    EVP_MD_CTX_free(hmac_ctx);
    fclose(f_in1);
    fclose(f_in2);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

	return 0;
}