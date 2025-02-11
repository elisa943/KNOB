#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 1024  // Taille de bloc en octets (1 Ko)
#define KEY_SIZE 32      // Taille de clé (256 bits)

// Déclaration de la clé statique FK
static unsigned char fk[KEY_SIZE];

// Structures de données
typedef struct {
    unsigned char *data;
    size_t size;
} Block;

// --- Fonctions ---

// 1. Initialiser la clé de fichier (FK)
void initialize_file_key() {
    static int initialized = 0;

    if (!initialized) {
        if (!RAND_bytes(fk, KEY_SIZE)) {
            fprintf(stderr, "Erreur : génération de la clé aléatoire échouée\n");
            exit(EXIT_FAILURE);
        }
        initialized = 1;
    }
}

// 2. Chiffrer le fichier avec AES-256 en mode CBC
int encrypt_file(const char *input_file, const char *output_file) {
    unsigned char iv[KEY_SIZE];  // Vecteur d'initialisation (IV)
    RAND_bytes(iv, KEY_SIZE);

    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (!in || !out) {
        fprintf(stderr, "Erreur : ouverture des fichiers\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Erreur : création du contexte de chiffrement\n");
        return -1;
    }

    // Initialisation du chiffrement
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, fk, iv);

    unsigned char buffer[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int len, ciphertext_len;

    // Écrire le vecteur d'initialisation dans le fichier de sortie
    fwrite(iv, 1, KEY_SIZE, out);

    // Lire et chiffrer les blocs du fichier d'entrée
    while ((len = fread(buffer, 1, BLOCK_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len);
        fwrite(ciphertext, 1, ciphertext_len, out);
    }

    // Finaliser le chiffrement
    EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len);
    fwrite(ciphertext, 1, ciphertext_len, out);

    // Libération des ressources
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

// 3. Diviser le fichier chiffré en blocs
Block* divide_into_blocks(const char *ciphertext_file, int *num_blocks) {
    FILE *file = fopen(ciphertext_file, "rb");
    if (!file) {
        fprintf(stderr, "Erreur : ouverture du fichier chiffré\n");
        return NULL;
    }

    // Déterminer la taille du fichier
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    *num_blocks = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;  // Calcul du nombre de blocs
    Block *blocks = malloc(*num_blocks * sizeof(Block));

    for (int i = 0; i < *num_blocks; i++) {
        blocks[i].data = malloc(BLOCK_SIZE);
        blocks[i].size = fread(blocks[i].data, 1, BLOCK_SIZE, file);
    }

    fclose(file);
    return blocks;
}

// 4. Identifier les super blocs
void identify_super_blocks(Block *blocks, int num_blocks, int *super_block_indices, int num_super_blocks) {
    // Exemple simple : sélection aléatoire de super blocs
    for (int i = 0; i < num_super_blocks; i++) {
        super_block_indices[i] = rand() % num_blocks;
    }
}


// --- Fonction principale ---
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage : %s <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Initialiser la clé FK une seule fois
    initialize_file_key();

    // Étape 1 : Chiffrement du fichier d'entrée
    if (encrypt_file(argv[1], argv[2]) != 0) {
        fprintf(stderr, "Erreur lors du chiffrement du fichier\n");
        return EXIT_FAILURE;
    }

    // Étape 2 : Division en blocs
    int num_blocks;
    Block *blocks = divide_into_blocks(argv[2], &num_blocks);

    if (blocks == NULL) {
        fprintf(stderr, "Erreur lors de la division en blocs\n");
        return EXIT_FAILURE;
    }

    // Étape 3 : Identification des super blocs
    int super_block_indices[2];  // Exemple avec deux super blocs
    identify_super_blocks(blocks, num_blocks, super_block_indices, 2);

    // Affichage des super blocs sélectionnés
    printf("Super blocs sélectionnés : %d, %d\n", super_block_indices[0], super_block_indices[1]);

    // Libération de la mémoire
    for (int i = 0; i < num_blocks; i++) {
        free(blocks[i].data);
    }
    free(blocks);

    return EXIT_SUCCESS;
}

