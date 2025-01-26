#include <stdint.h>
#include <stdio.h>

// Macro pour la rotation circulaire à gauche sur 8 bits
#define ROTL8(x, shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

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

    return 0;
}
