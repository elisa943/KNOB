import os
import sys
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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
    """Sélectionne un nombre donné de super blocs de manière plus aléatoire."""
    num_blocks = len(blocks)
    
    if num_super_blocks > num_blocks:
        print(f"Erreur : Impossible de sélectionner {num_super_blocks} super blocs parmi {num_blocks} blocs.")
        sys.exit(1)

    # Générer tous les indices des blocs
    indices = list(range(num_blocks))
    
    # Mélanger les indices
    random.shuffle(indices)
    
    # Sélectionner les premiers `num_super_blocks` après mélange
    return indices[:num_super_blocks]

def encrypt_super_blocks(super_blocks, key, super_block_indices, output_file):
    """Chiffre les super blocs sélectionnés avec AES-256-CBC et met à jour le fichier."""
    encrypted_super_blocks = []

    # Lire le fichier chiffré en mode lecture/écriture binaire
    with open(output_file, "r+b") as f:
        for index, block in zip(super_block_indices, super_blocks):
            iv = get_random_bytes(16)  # IV unique pour chaque super bloc
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Padding si nécessaire
            if len(block) % 16 != 0:
                padding_length = 16 - (len(block) % 16)
                block += bytes([padding_length] * padding_length)

            encrypted_block = cipher.encrypt(block)
            encrypted_super_blocks.append((iv, encrypted_block))

            # 🔥 Mise à jour du fichier `output_file` avec les super-blocs chiffrés
            f.seek(index * BLOCK_SIZE)  # Se placer au bon emplacement du super-bloc
            f.write(iv + encrypted_block)  # Écrire l'IV suivi du bloc chiffré

            print(f"✅ Super bloc {index} chiffré et réécrit dans `output_file`.")

    return encrypted_super_blocks


def adaptation_indices(num_blocks, super_block_indices) :
    indices = ['0'] * num_blocks
    for i in super_block_indices :
        indices[i] = '1'
    return indices

def encrypt_superblock_index(indices, key) :
    indices_bytes = indices.encode()

    iv = get_random_bytes(16)  # IV unique pour chaque super bloc
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Padding si nécessaire
    if len(indices_bytes) % 16 != 0:
        padding_length = 16 - (len(indices_bytes) % 16)
        indices_bytes += bytes([padding_length] * padding_length)

    encrypted_index = cipher.encrypt(indices_bytes)

    return iv + encrypted_index   

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
    print("Premiers octets de FK : ", file_key[:16])

    # Étape 1 : Chiffrement du fichier
    encrypt_file(input_file, output_file)

    # Étape 2 : Division en blocs
    blocks = divide_into_blocks(output_file)
    print("Le nombre de blocks est :", len(blocks))

    # Étape 3 : Formation de metaFK
    metaFK = compute_xor_metadata(blocks, file_key)

    # Sauvegarde de metaFK
    with open("metaFK.bin", "wb") as f:
        f.write(metaFK)
    
    print("MetaFK généré et stocké dans metaFK.bin")

    # Étape 4 : Identification des super blocs
    super_block_indices = identify_super_blocks(blocks, 2)
    super_blocks = [blocks[i] for i in super_block_indices]

    # Étape 6 : Chiffrement des super blocs avec une clé SK
    sk_key = get_random_bytes(KEY_SIZE)  # Clé SK générée 

    # Récupération de GK
    with open("gk_key", "rb") as f:
        gk_key = f.read()

    encrypted_super_blocks = encrypt_super_blocks(super_blocks, gk_key, super_block_indices, output_file)


    # Sauvegarde de metaSK avec les IV
    with open("metaSK.bin", "wb") as f:
        for iv, encrypted_block in encrypted_super_blocks:
            f.write(iv + encrypted_block)

    print("MetaSK (super blocs chiffrés) généré et stocké dans metaSK.bin")

    # Affichage des super blocs sélectionnés
    print("Les super blocs sélectionnés sont :", super_block_indices)

    # Étape 5 : Chiffrement AES des indices des superblocs
    se_index = "".join(adaptation_indices(len(blocks), super_block_indices))
    print("Les indices chiffrés sont :", se_index)

    metaIndex = encrypt_superblock_index(se_index, sk_key)

    # Sauvegarde de metaIndex
    with open("metaIndex.bin", "wb") as f:
        f.write(metaIndex)
    print("MetaIndex (se_index chiffré) généré et stocké dans metaIndex.bin")

    # Ètape 7 : Chiffrement RSA de la clé SK avec knob-pub-key
    with open("knob-pri-key", "rb") as f:
        knob_pri_key = RSA.import_key(f.read())

    knob_pub_key = knob_pri_key.publickey() 
    cipher_rsa = PKCS1_OAEP.new(knob_pub_key)
    metaSGX = cipher_rsa.encrypt(sk_key)

    # Sauvegarde de metaSGX
    with open("metaSGX.bin", "wb") as f:
        f.write(metaSGX)
    print("MetaSGX (SK chiffrée) généré et stocké dans metaSGX.bin")

# Point d'entrée du programme
if __name__ == "__main__":
    main()
