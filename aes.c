#include <stdint.h>
#include <stdio.h>

// Macro pour la rotation circulaire à gauche sur 8 bits
#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
// Macro pour la taille d'un message (128 bits = 16 octets)
#define AES_BLOCK_SIZE 16
// Macro pour la taille de la clé AES-256 (256 bits = 32 octets)
#define AES_KEY_SIZE 32

// Déclaration de la S-Box (statique)
static uint8_t sbox[256];
static int sbox_initialized = 0;

// Déclaration de la S-Box inverse (statique)
static uint8_t inv_sbox[256];
static int inv_sbox_initialized = 0;

// Fonction pour initialiser la S-Box
void initialize_aes_sbox() {
    if (sbox_initialized) {
        return;
    }

    uint8_t p = 1, q = 1;

    /* Loop invariant: p * q == 1 in the Galois field */
    do {
        /* Multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        /* Divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        /* Compute the affine transformation */
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

        sbox[p] = xformed ^ 0x63;
    } while (p != 1);

    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63;
    sbox_initialized = 1;
}

// Rcon (table des constantes de tour)
static const uint32_t rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000
};

// Fonction RotWord : rotation circulaire à gauche d'un mot (32 bits)
uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

// Fonction SubWord : substitution des octets d'un mot avec la S-Box
uint32_t SubWord(uint32_t word) {
    return (sbox[(word >> 24) & 0xFF] << 24) |
           (sbox[(word >> 16) & 0xFF] << 16) |
           (sbox[(word >> 8) & 0xFF] << 8) |
           (sbox[word & 0xFF]);
}

// Fonction d'expansion de clé pour AES-256
void KeyExpansion(const uint8_t *key, uint32_t *expandedKeys) {
    // Les 8 premiers mots viennent directement de la clé maîtresse
    for (int i = 0; i < 8; i++) {
        expandedKeys[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                          (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    // Générer les mots restants
    for (int i = 8; i < 60; i++) {
        uint32_t temp = expandedKeys[i - 1];

        if (i % 8 == 0) {
            temp = SubWord(RotWord(temp)) ^ rcon[(i / 8) - 1];
        } else if (i % 4 == 0) {
            temp = SubWord(temp);
        }

        expandedKeys[i] = expandedKeys[i - 8] ^ temp;
    }
}

// Fonction de substitution des octets : applique la substitution avec la S-Box
void SubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

// Fonction shiftRows : décalage des lignes 
void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Décalage de la 2ème ligne d'une position à gauche
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Décalage de la 3ème ligne de deux positions à gauche
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Décalage de la 4ème ligne de trois positions à gauche
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

uint8_t multiplyGalois(uint8_t x, uint8_t multiplier) {
    switch(multiplier) {
        case 0: 
            return 0;
        case 1:
            return x;
        case 2: // La multiplication par 2 revient à effectuer une décalage à gauche (<< 1)
            if (x < 0x80) { // si le bit de poids fort est à 0
                return x << 1;
            } else {
                return (x << 1) ^ 0x1B; // 0x1B = 00011011
            }
        case 3:
            return multiplyGalois(x, 2) ^ x;
        case 9: {
            uint8_t x2 = multiplyGalois(x,2) ;
            uint8_t x4 = multiplyGalois(x2,2) ;
            uint8_t x8 = multiplyGalois(x4,2) ;
            return x8 ^ x; }
        case 11: {
            uint8_t x2 = multiplyGalois(x,2) ;
            uint8_t x4 = multiplyGalois(x2,2) ;
            uint8_t x8 = multiplyGalois(x4,2) ;
            return x8 ^ x2 ^ x ; }
        case 13: {
            uint8_t x2 = multiplyGalois(x,2) ;
            uint8_t x4 = multiplyGalois(x2,2) ;
            uint8_t x8 = multiplyGalois(x4,2) ;
            return x8 ^ x4 ^ x ; }
        case 14: {
            uint8_t x2 = multiplyGalois(x,2) ;
            uint8_t x4 = multiplyGalois(x2,2) ;
            uint8_t x8 = multiplyGalois(x4,2) ;
            return x8 ^ x4 ^ x2 ; }
        default:
            return 0;
    }
}

// Fonction MixColumns : multiplication par la matrice fixe
void MixColumns(uint8_t state[4][4]) {
    for (int j = 0; j < 4; j++) { // parcoure les colonnes 
        uint8_t a[4];
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][j]; // stocke la ième colonne de state
        }
        state[0][j] = multiplyGalois(a[0], 2) ^ multiplyGalois(a[1], 3) ^ a[2]                    ^ a[3];
        state[1][j] = a[0]                    ^ multiplyGalois(a[1], 2) ^ multiplyGalois(a[2], 3) ^ a[3];
        state[2][j] = a[0]                    ^ a[1]                    ^ multiplyGalois(a[2], 2) ^ multiplyGalois(a[3], 3);
        state[3][j] = multiplyGalois(a[0], 3) ^ a[1]                    ^ a[2]                    ^ multiplyGalois(a[3], 2);
    }
}

// Fonction AddRoundKey : applique une clé de tour au bloc d'état
void AddRoundKey(uint8_t state[4][4], uint32_t expandedKeys[4]) {
    for (int i = 0; i < 4; i++) {
        uint32_t key = expandedKeys[i];
        for (int j = 0; j < 4; j++) {
            uint8_t cle = (key >> (8 * (3 - j))) & 0xFF;
            state[i][j] ^= cle;
        }
    }
}

void affichage_etat(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

// Fonction pour lire une clé AES-256 depuis un fichier .pem
int lire_cle_aes(const char *filename, uint8_t *key) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Erreur d'ouverture du fichier clé");
        return -1;
    }

    char hexKey[AES_KEY_SIZE * 2 + 1]; // 32 octets * 2 caractères hex + '\0'
    if (fgets(hexKey, sizeof(hexKey), file) == NULL) {
        perror("Erreur de lecture du fichier clé");
        fclose(file);
        return -1;
    }
    fclose(file);

    // Convertir la clé hexadécimale en tableau de bytes
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        sscanf(hexKey + (i * 2), "%2hhx", &key[i]);
    }

    return 0;
}

// Fonction principale de chiffrement AES-256
void chiffrement(uint8_t *input, uint8_t *output, uint32_t expandedKeys[60]) {
    uint8_t state[4][4];

    // Copier l'entrée dans la matrice d'état (state)
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i % 4][i / 4] = input[i];
    }

    // Étape initiale : AddRoundKey
    AddRoundKey(state, expandedKeys);

    // N-1 tours principaux
    for (int round = 1; round < 14; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &expandedKeys[round * 4]);
    }

    // Dernier tour (sans MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &expandedKeys[14 * 4]);

    // Copier la matrice d'état dans la sortie
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        output[i] = state[i % 4][i / 4];
    }
}

void affiche_s_box(uint8_t sbox[256]) {
    // Affiche la s-Box et les entêtes de chaque ligne / colonne (0 à F)
    printf("S-Box :\n");
    printf("    ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", i);
    }
    for (int i = 0; i < 256; i++) {
        if (i % 16 == 0) {
            printf("\n%02x  ", i / 16);
        }
        printf("%02x ", sbox[i]);
    }
    printf("\n");
}

// Fonction pour initialiser la sbox inverse pour le déchiffrement
void initialize_aes_inv_sbox() {
    if (inv_sbox_initialized) {
        return;
    }
    for (int i = 0; i < 256 ; i++) {
        inv_sbox[sbox[i]] = i ;
    }
    inv_sbox_initialized = 1;
}

// Fonction InvSubBytes : applique l'inverse de la s-box
void InvSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}

// Fonction InvShiftRows : décale les lignes dans la direction opposée à ShiftRows
void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Décalage inverse de la 2ème ligne d'une position à droite
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Décalage inverse de la 3ème ligne de deux positions à droite
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Décalage inverse de la 4ème ligne de trois positions à droite
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// Fonction InvMixColumns : transforme les colonnes à l'aide de la matrice inverse de MixColumns
void InvMixColumns(uint8_t state[4][4]) {
    for (int j = 0; j < 4; j++) {
        uint8_t a[4];
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][j];
        }
        state[0][j] = multiplyGalois(a[0], 14) ^ multiplyGalois(a[1], 11) ^
                      multiplyGalois(a[2], 13) ^ multiplyGalois(a[3], 9);
        state[1][j] = multiplyGalois(a[0], 9) ^ multiplyGalois(a[1], 14) ^
                      multiplyGalois(a[2], 11) ^ multiplyGalois(a[3], 13);
        state[2][j] = multiplyGalois(a[0], 13) ^ multiplyGalois(a[1], 9) ^
                      multiplyGalois(a[2], 14) ^ multiplyGalois(a[3], 11);
        state[3][j] = multiplyGalois(a[0], 11) ^ multiplyGalois(a[1], 13) ^
                      multiplyGalois(a[2], 9) ^ multiplyGalois(a[3], 14);
    }
}

// Fonction principale de déchiffrement AES-256
void dechiffrement(uint8_t *input, uint8_t *output, uint32_t expandedKeys[60]) {
    uint8_t state[4][4];

    // Copier l'entrée dans la matrice d'état
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i % 4][i / 4] = input[i];
    }

    // Étape initiale : AddRoundKey avec la dernière clé
    AddRoundKey(state, &expandedKeys[14 * 4]);

    // 13 tours principaux inversés
    for (int round = 13; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &expandedKeys[round * 4]);
        InvMixColumns(state);
    }

    // Dernier tour inversé (sans InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expandedKeys);

    // Copier la matrice d'état dans la sortie
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        output[i] = state[i % 4][i / 4];
    }
}

// -----------------------------------------------------------------------------
// 6) Fonction : chiffrement_fichier
//    - Lit un fichier par blocs de 16 octets
//    - Affiche bloc en hex avant chiffrement
//    - Chiffre
//    - Affiche bloc chiffré en hex
//    - Déchiffre
//    - Affiche bloc déchiffré en hex
//    - Écrit le bloc chiffré dans un autre fichier
// -----------------------------------------------------------------------------

// Petit helper de "zero-padding" (pour combler si bloc < 16)
static void zero_padding(uint8_t *block, size_t nbOctetsLus) {
    // On complète par des 0 la portion non lue
    for (size_t i = nbOctetsLus; i < AES_BLOCK_SIZE; i++) {
        block[i] = 0x00;
    }
}

int chiffrement_fichier(const char *inFilename, 
                        const char *outFilename,
                        const uint8_t key[32])
{
    // 1) Initialiser la S-Box et l'inverse (si pas déjà fait)
    initialize_aes_sbox();
    initialize_aes_inv_sbox();

    // 2) Faire l'expansion de la clé
    uint32_t expandedKeys[60];
    KeyExpansion(key, expandedKeys);

    // 3) Ouvrir les fichiers
    FILE *fin  = fopen(inFilename,  "rb");
    FILE *fout = fopen(outFilename, "wb");
    if (!fin || !fout) {
        printf("Erreur : impossible d'ouvrir les fichiers.\n");
        if (fin)  fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }

    // 4) Lire / chiffrer bloc par bloc
    uint8_t blocIn[16];
    uint8_t blocOut[16];
    size_t nbLus;

    while (1) {
        nbLus = fread(blocIn, 1, 16, fin);
        if (nbLus < 16) {
            if (feof(fin)) {
                // On est arrivé à la fin => on pad le dernier bloc
                zero_padding(blocIn, nbLus);
                // Chiffrement du bloc
                chiffrement(blocIn, blocOut, expandedKeys);
                fwrite(blocOut, 1, 16, fout);
            } else {
                // Erreur de lecture
                printf("Erreur de lecture.\n");
            }
            break; 
        } else {
            // Bloc complet de 16 octets
            chiffrement(blocIn, blocOut, expandedKeys);
            fwrite(blocOut, 1, 16, fout);
        }
    }

    fclose(fin);
    fclose(fout);

    printf("Chiffrement terminé : %s => %s\n", inFilename, outFilename);
    return 0;
}

int dechiffrement_fichier(const char *inFilename, 
                          const char *outFilename,
                          const uint8_t key[32])
{
    initialize_aes_sbox();
    initialize_aes_inv_sbox();

    // 2) Expansion de clé
    uint32_t expandedKeys[60];
    KeyExpansion(key, expandedKeys);

    FILE *fin  = fopen(inFilename,  "rb");
    FILE *fout = fopen(outFilename, "wb");
    if (!fin || !fout) {
        printf("Erreur : impossible d'ouvrir les fichiers.\n");
        if (fin)  fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }

    uint8_t blocIn[16];
    uint8_t blocOut[16];
    size_t nbLus;

    while ((nbLus = fread(blocIn, 1, 16, fin)) == 16) {
        // nbLus devrait toujours valoir 16 si c'est un fichier chiffré multiple de 16
        dechiffrement(blocIn, blocOut, expandedKeys);
        fwrite(blocOut, 1, 16, fout);
    }

    // Si on arrive ici, qu'on ait lu moins de 16 octets 
    // signifie soit corruption, soit fin inattendue, etc.
    if (!feof(fin)) {
        printf("Attention : le fichier %s n'est pas un multiple de 16 octets ?\n", inFilename);
    }

    fclose(fin);
    fclose(fout);

    printf("Déchiffrement terminé : %s => %s\n", inFilename, outFilename);
    return 0;
}

void affiche_fichier_hex(const char *filename, const char *titre) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Impossible d'ouvrir %s pour l'affichage.\n", filename);
        return;
    }
    printf("\n--- %s (%s) ---\n", titre, filename);

    unsigned char buffer[16];
    size_t n;
    size_t offset = 0;

    while ((n = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        // Affiche offset en hexa
        printf("%08zx  ", offset);
        offset += n;

        // Affiche n octets en hexa
        for (size_t i = 0; i < n; i++) {
            printf("%02X ", buffer[i]);
        }
        // Si on veut un alignement "type hexdump", on peut rajouter des espaces
        for (size_t i = n; i < sizeof(buffer); i++) {
            printf("   ");
        }

        // Affiche en ASCII (optionnel)
        printf(" | ");
        for (size_t i = 0; i < n; i++) {
            unsigned char c = buffer[i];
            if (c >= 32 && c < 127) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
    fclose(f);
    printf("------------------------\n\n");
}

int main(void) {
    uint8_t key[32]; // Clé AES-256

    if (lire_cle_aes("cle_aes.pem", key) != 0) {
        printf("Erreur : Impossible de charger la clé AES.\n");
        return 1;
    }

    // Fichiers de test
    const char *fichier_original   = "test.txt";
    const char *fichier_chiffre    = "test_chiffre.bin";
    const char *fichier_dechiffre  = "test_dechiffre.txt";

    // 1) Affichage du fichier ORIGINAL
    affiche_fichier_hex(fichier_original, "Fichier original");

    // 2) Chiffrement du fichier
    if (chiffrement_fichier(fichier_original, fichier_chiffre, key) != 0) {
        printf("Echec du chiffrement.\n");
        return 1;
    }

    // 3) Affichage du fichier CHIFFRÉ
    affiche_fichier_hex(fichier_chiffre, "Fichier chiffré");

    // 4) Déchiffrement du fichier chiffré
    if (dechiffrement_fichier(fichier_chiffre, fichier_dechiffre, key) != 0) {
        printf("Echec du déchiffrement.\n");
        return 1;
    }

    // 5) Affichage du fichier DÉCHIFFRÉ
    affiche_fichier_hex(fichier_dechiffre, "Fichier déchiffré");

    return 0;
}