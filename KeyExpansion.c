#include <stdint.h>
#include <stdio.h>

// Macro pour la rotation circulaire à gauche sur 8 bits
#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
// Macro pour la taille d'un message (128 bits = 16 octets)
#define AES_BLOCK_SIZE 16

// Fonction pour initialiser la S-Box
void initialize_aes_sbox(uint8_t sbox[256]) {
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
uint32_t SubWord(uint32_t word, uint8_t sbox[256]) {
    return (sbox[(word >> 24) & 0xFF] << 24) |
           (sbox[(word >> 16) & 0xFF] << 16) |
           (sbox[(word >> 8) & 0xFF] << 8) |
           (sbox[word & 0xFF]);
}

// Fonction d'expansion de clé pour AES-256
void KeyExpansion(const uint8_t *key, uint32_t *expandedKeys, uint8_t sbox[256]) {
    // Les 8 premiers mots viennent directement de la clé maîtresse
    for (int i = 0; i < 8; i++) {
        expandedKeys[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                          (key[4 * i + 2] << 8) | key[4 * i + 3];
    }

    // Générer les mots restants
    for (int i = 8; i < 60; i++) {
        uint32_t temp = expandedKeys[i - 1];

        if (i % 8 == 0) {
            temp = SubWord(RotWord(temp), sbox) ^ rcon[(i / 8) - 1];
        } else if (i % 4 == 0) {
            temp = SubWord(temp, sbox);
        }

        expandedKeys[i] = expandedKeys[i - 8] ^ temp;
    }
}

// Fonction de substitution des octets : applique la substitution avec la S-Box
void SubBytes(uint8_t state[4][4], uint8_t sbox[256]) {
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
        default: // 3
            return multiplyGalois(x, 2) ^ x;
    }
}

// Fonction MixColumns : multiplication par la matrice fixe
void MixColumns(uint8_t state[4][4]) {
    for (int j = 0; j < 4; j++) { // parcoure les colonnes 
        uint8_t a[4], b[4];
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][j]; // stocke la ième colonne de state
            b[i] = multiplyGalois(state[i][j], i); // stocke la ième colonne de state multipliée par 2
        }
        state[0][j] = multiplyGalois(a[0], 2) ^ multiplyGalois(a[1], 3) ^ multiplyGalois(a[2], 1) ^ multiplyGalois(a[3], 1);
        state[1][j] = multiplyGalois(a[0], 1) ^ multiplyGalois(a[1], 2) ^ multiplyGalois(a[2], 3) ^ multiplyGalois(a[3], 1);
        state[2][j] = multiplyGalois(a[0], 1) ^ multiplyGalois(a[1], 1) ^ multiplyGalois(a[2], 2) ^ multiplyGalois(a[3], 3);
        state[3][j] = multiplyGalois(a[0], 3) ^ multiplyGalois(a[1], 1) ^ multiplyGalois(a[2], 1) ^ multiplyGalois(a[3], 2);
    }
}

// Fonction AddRoundKey : applique une clé de tour au bloc d'état
void AddRoundKey(uint8_t state[4][4], uint32_t expandedKeys[4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= (expandedKeys[j] >> (8 * (3 - i))) & 0xFF;
        }
    }
}

// Fonction principale de chiffrement AES-256
void chiffrement(uint8_t *input, uint8_t *output, uint32_t expandedKeys[60], uint8_t sbox[256]) {
    uint8_t state[4][4];

    // Copier l'entrée dans la matrice d'état (state)
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i % 4][i / 4] = input[i];
    }

    // Étape initiale : AddRoundKey
    AddRoundKey(state, expandedKeys);

    // N-1 tours principaux
    for (int round = 1; round < 14; round++) {
        SubBytes(state, sbox);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &expandedKeys[round * 4]);
    }

    // Dernier tour (sans MixColumns)
    SubBytes(state, sbox);
    ShiftRows(state);
    AddRoundKey(state, &expandedKeys[14 * 4]);

    // Copier la matrice d'état dans la sortie
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        output[i] = state[i % 4][i / 4];
    }
}

int main() {
    // Générer la S-Box
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);

    // Exemple de clé maîtresse (256 bits)
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    // Tableau pour stocker les clés expansées
    uint32_t expandedKeys[60];

    // Expansion de la clé
    KeyExpansion(key, expandedKeys, sbox);

    // Affichage des clés générées
    printf("Clés expansées :\n");
    for (int i = 0; i < 60; i++) {
        printf("W[%d] = %08x\n", i, expandedKeys[i]);
    }

    // Test du chiffrement AES-256
    uint8_t input[AES_BLOCK_SIZE] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    uint8_t output[AES_BLOCK_SIZE];

    chiffrement(input, output, expandedKeys, sbox);

    // Affichage du message chiffré
    printf("\nMessage chiffré :\n");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x ", output[i]);
    }
    printf("\n");

    return 0;
}
