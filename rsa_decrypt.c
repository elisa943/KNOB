#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define PADDING RSA_PKCS1_OAEP_PADDING
#define ENCRYPTED_FILE "encrypted.bin"

void handleErrors() {
    fprintf(stderr, "An error occurred.\n");
    exit(1);
}

EVP_PKEY *load_private_key(const char *priv_key_file) {
    FILE *fp = fopen(priv_key_file, "r");
    if (!fp) {
        perror("Error opening private key file");
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

int rsa_decrypt(EVP_PKEY *key, const unsigned char *encrypted, size_t encrypted_len, unsigned char **decrypted) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted, encrypted_len) <= 0) handleErrors();

    *decrypted = malloc(outlen);
    if (!*decrypted) handleErrors();

    if (EVP_PKEY_decrypt(ctx, *decrypted, &outlen, encrypted, encrypted_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int main() {
    const char *priv_key_file = "private.pem";

    EVP_PKEY *priv_key = load_private_key(priv_key_file);
    if (!priv_key) {
        fprintf(stderr, "Failed to load private key.\n");
        return 1;
    }

    // Lecture du fichier contenant le message chiffré
    FILE *fp = fopen(ENCRYPTED_FILE, "rb");
    if (!fp) {
        perror("Error opening encrypted file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long encrypted_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *encrypted = malloc(encrypted_len);
    fread(encrypted, 1, encrypted_len, fp);
    fclose(fp);

    unsigned char *decrypted = NULL;
    int decrypted_len = rsa_decrypt(priv_key, encrypted, encrypted_len, &decrypted);

    printf("Decrypted message: %.*s\n", decrypted_len, decrypted);

    free(encrypted);
    free(decrypted);
    EVP_PKEY_free(priv_key);

    return 0;
}
