#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv) {
    FILE *f_in;
    unsigned char secret[] = "this_is_my_secret";
      
    if (argc != 2) {
        fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
        exit(1);
    }

    if ((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

    ERR_load_crypto_strings();// deprecated since version 1.1.0
    OpenSSL_add_all_algorithms();// deprecated since version 1.1.0

	EVP_MD_CTX *md = EVP_MD_CTX_new();

    if (!EVP_DigestInit(md, EVP_sha512()))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];

    EVP_DigestUpdate(md, secret, strlen((const char *)secret));

    while((n_read = fread(buffer,1,MAXBUF,f_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    EVP_DigestUpdate(md, secret, strlen((const char *)secret));

    unsigned char md_value[EVP_MD_size(EVP_sha512())];
    int md_len;

    if (!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    EVP_MD_CTX_free(md);

    printf("FLAG: CRYPTO25{");
    for(int i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
    printf("}\n");

    CRYPTO_cleanup_all_ex_data();// deprecated since version 1.1.0
    ERR_free_strings();// deprecated since version 1.1.0

	return 0;
}