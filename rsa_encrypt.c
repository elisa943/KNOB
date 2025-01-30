#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define PADDING RSA_PKCS1_OAEP_PADDING
#define ENCRYPTED_FILE "encrypted.bin"

void handleErrors() {
    fprintf(stderr, "An error occurred.\n");
    exit(1);
}

EVP_PKEY *load_public_key(const char *pub_key_file) {
    FILE *fp = fopen(pub_key_file, "r");
    if (!fp) {
        perror("Error opening public key file");
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

int rsa_encrypt(EVP_PKEY *key, const unsigned char *message, size_t message_len, unsigned char **encrypted) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, message, message_len) <= 0) handleErrors();

    *encrypted = malloc(outlen);
    if (!*encrypted) handleErrors();

    if (EVP_PKEY_encrypt(ctx, *encrypted, &outlen, message, message_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_to_encrypt>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *pub_key_file = "public.pem";

    // Charger la clé publique
    EVP_PKEY *pub_key = load_public_key(pub_key_file);
    if (!pub_key) {
        fprintf(stderr, "Failed to load public key.\n");
        return 1;
    }

    // Lire le fichier d'entrée
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        perror("Error opening input file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *message = malloc(file_size);
    fread(message, 1, file_size, fp);
    fclose(fp);

    // Chiffrer le fichier
    unsigned char *encrypted = NULL;
    int encrypted_len = rsa_encrypt(pub_key, message, file_size, &encrypted);

    // Sauvegarde dans un fichier
    fp = fopen(ENCRYPTED_FILE, "wb");
    if (!fp) {
        perror("Error opening output file");
        return 1;
    }
    fwrite(encrypted, 1, encrypted_len, fp);
    fclose(fp);

    printf("Encrypted file saved to '%s'\n", ENCRYPTED_FILE);

    free(message);
    free(encrypted);
    EVP_PKEY_free(pub_key);

    return 0;
}
