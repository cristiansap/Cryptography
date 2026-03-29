#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

/* 
   NOTE: This exercise is the Exercise 1 at slide 8 in 02_OpenSSL_Moreinfo.pdf
*/

#define BIT_LENGTH 128
#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {

    /* 1) Generate two strong random 128-bit integers; name them rand1 and rand2 */
    BIGNUM *rand1 = BN_new();
    BIGNUM *rand2 = BN_new();

    BN_rand(rand1, BIT_LENGTH, 0, 1);
    BN_rand(rand2, BIT_LENGTH, 0, 1);

    /* 2) Obtain the first key as: k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128 */
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k1 = BN_new(), *k2 = BN_new(), *op1 = BN_new(), *op2 = BN_new(), *final_op = BN_new(), *mod = BN_new();
    
    BIGNUM *a = BN_new(), *b = BN_new();
    BN_set_word(a, 2);
    BN_set_word(b, BIT_LENGTH);
    BN_exp(mod, a, b, ctx);
    
    BN_add(op1, rand1, rand2);
    BN_sub(op2, rand1, rand2);
    BN_mul(final_op, op1, op2, ctx);
    BN_mod(k1, final_op, mod, ctx);

    printf("\nk1: ");
    BN_print_fp(stdout, k1);

    /* 3) Obtain the second key as: k2 = (rand1 * rand2) + (rand1 - rand2) mod 2^128 */

    BN_mul(op1, rand1, rand2, ctx);
    BN_add(final_op, op1, op2);
    BN_mod(k2, final_op, mod, ctx);

    printf("\nk2: ");
    BN_print_fp(stdout, k2);

    /* 4) Encrypt k2 using k1 using a strong encryption algorithm (and mode) of your choice
          (but choose a good one); call it enc_k2 
    */

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    int update_len, final_len;
    int ciphertext_len = 0;
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();

    unsigned char iv[BIT_LENGTH];
    unsigned char *key = (unsigned char *)BN_bn2hex(k1);
    RAND_load_file("/dev/random", 128);
    RAND_bytes(iv, BIT_LENGTH);

    if (!EVP_CipherInit(cipher_ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    unsigned char *plaintext = (unsigned char *)BN_bn2hex(k2);
    unsigned char ciphertext[BIT_LENGTH];

    if (!EVP_CipherUpdate(cipher_ctx, ciphertext, &update_len, plaintext, strlen(plaintext)))
        handle_errors();

    ciphertext_len += update_len;

    if (!EVP_CipherFinal_ex(cipher_ctx, ciphertext + ciphertext_len, &final_len))
        handle_errors();

    ciphertext_len += final_len;
    EVP_CIPHER_CTX_free(cipher_ctx);

    printf("\nCiphertext length = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");


    /* 5) Generate an RSA keypair with a 2048-bit modulus */
    EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;

    if ((rsa_keypair = EVP_RSA_gen(bits)) == NULL) 
        handle_errors();

    // save public key
    FILE *rsa_public_file = NULL;
    if ((rsa_public_file = fopen("public.pem","w")) == NULL) {
        fprintf(stderr,"Couldn't create the private key file.\n");
        abort();
    }
    if (!PEM_write_PUBKEY(rsa_public_file, rsa_keypair))
        handle_errors();
    fclose(rsa_public_file);

    // save private key (without encrypting it on disk)
    FILE *rsa_private_file = NULL;
        if((rsa_private_file = fopen("private.pem","w")) == NULL) {
                fprintf(stderr,"Couldn't create the private key file.\n");
                abort();
        }
    if (!PEM_write_PrivateKey(rsa_private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    fclose(rsa_public_file);


    /* 6) Encrypt enc_k2 using the just generated RSA key */

    size_t pri_len;  // Length of private key
    size_t pub_len;  // Length of public key

    // Create and initialize a new context for encryption.
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);

    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0)
        handle_errors();
    
    // Specific configurations can be performed through the initialized context
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_errors();

    // Determine the size of the output
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_msg_len, ciphertext, strlen(ciphertext)) <= 0) {
        handle_errors();
    }

    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_msg, &encrypted_msg_len, ciphertext, strlen(ciphertext)) <= 0) {
        handle_errors();
    }

    // save the message to a file
    FILE *fout = fopen("out.bin", "w");
    if(fwrite(encrypted_msg, 1, encrypted_msg_len, fout) < EVP_PKEY_size(rsa_keypair))
        handle_errors();
    fclose(fout);
    
    printf("Encrypted message written to file.\n");

    EVP_PKEY_free(rsa_keypair);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
