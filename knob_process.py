import os
import sys
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from xor_metadata import compute_xor_metadata

# Constantes
BLOCK_SIZE = 1024  # Taille de bloc en octets (1 Ko)
KEY_SIZE = 32      # Taille de clé (256 bits)

# Clé FK statique
file_key = None

# --- Fonctions ---

def initialize_file_key():
    """Initialise la clé FK une seule fois."""
    global file_key
    if file_key is None:
        file_key = get_random_bytes(KEY_SIZE)

def encrypt_file(input_file, output_file):
    """Chiffre un fichier avec AES-256 en mode CBC."""
    # Générer un vecteur d'initialisation (IV) de 16 octets
    iv = get_random_bytes(16)

    # Ouvrir les fichiers d'entrée et de sortie
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Écrire le vecteur d'initialisation au début du fichier de sortie
        outfile.write(iv)

        # Initialiser le chiffrement
        cipher = AES.new(file_key, AES.MODE_CBC, iv)

        # Lire et chiffrer les données par blocs
        while True:
            block = infile.read(BLOCK_SIZE)
            if len(block) == 0:
                break
            elif len(block) % 16 != 0:
                # Ajouter du padding si nécessaire
                padding_length = 16 - (len(block) % 16)
                block += bytes([padding_length] * padding_length)

            # Chiffrer le bloc et écrire dans le fichier de sortie
            encrypted_block = cipher.encrypt(block)
            outfile.write(encrypted_block)


def divide_into_blocks(ciphertext_file):
    """Divise le fichier chiffré en blocs de taille fixe."""
    blocks = []

    with open(ciphertext_file, 'rb') as infile:
        while True:
            block = infile.read(BLOCK_SIZE)
            if not block:
                break
            blocks.append(block)

    return blocks

def identify_super_blocks(blocks, num_super_blocks):
    """Sélectionne un nombre donné de super blocs de manière aléatoire."""
    if num_super_blocks > len(blocks):
        print(f"Erreur : Impossible de sélectionner {num_super_blocks} super blocs parmi {len(blocks)} blocs.")
        sys.exit(1)

    return random.sample(range(len(blocks)), num_super_blocks)


# --- Fonction principale ---
def main():
    # Vérification des arguments
    if len(sys.argv) < 3:
        print("Usage: python knob_process.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Initialiser la clé FK
    initialize_file_key()

    # Étape 1 : Chiffrement du fichier
    encrypt_file(input_file, output_file)

    # Étape 2 : Division en blocs
    blocks = divide_into_blocks(output_file)

    # Étape 3 : Formation de metaFK
    metaFK = compute_xor_metadata(blocks, file_key)

    # Sauvegarde de metaFK
    with open("metaFK.bin", "wb") as f:
        f.write(metaFK)
    
    print("MetaFK généré et stocké dans metaFK.bin")

    # Étape 4 : Identification des super blocs
    super_block_indices = identify_super_blocks(blocks, 2)
    super_blocks = [blocks[i] for i in super_block_indices]

    # Étape 5 : Formation de metaSK
    sk_key = get_random_bytes(KEY_SIZE)  # Simulation d'une clé SK (doit être gérée autrement dans l'intégration finale)
    metaSK = compute_xor_metadata(blocks, sk_key, additional_elements=super_blocks)

    # Sauvegarde de metaSK
    with open("metaSK.bin", "wb") as f:
        f.write(metaSK)

    print("MetaSK généré et stocké dans metaSK.bin")

    # Affichage des super blocs sélectionnés
    print("Super blocs sélectionnés :", super_block_indices)

# Point d'entrée du programme
if __name__ == "__main__":
    main()
