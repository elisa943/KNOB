import os
import sys
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from xor_metadata import compute_xor_metadata
from Crypto.Util.Padding import pad

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

            if len(block) < BLOCK_SIZE:  # Dernier bloc -> on ajoute du padding
                block = pad(block, BLOCK_SIZE)
            
            encrypted_block = cipher.encrypt(block)
            outfile.write(encrypted_block)

def divide_into_blocks(ciphertext_file):
    """Divise le fichier chiffré en blocs de taille fixe."""
    blocks = []
    
    with open(ciphertext_file, 'rb') as infile:
        iv = infile.read(16)
        
        while True:
            block = infile.read(BLOCK_SIZE)
            if not block:
                break
            blocks.append(block)

    return iv, blocks

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

def encrypt_super_blocks(super_blocks, key, iv):
    """Chiffre les super blocs sélectionnés avec AES-256-CBC."""
    encrypted_super_blocks = []

    for block in super_blocks:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        if len(block) < BLOCK_SIZE:
            padded = pad(block, BLOCK_SIZE)
        else: 
            padded = block
        encrypted_block = cipher.encrypt(padded)
        encrypted_super_blocks.append(encrypted_block)

    return encrypted_super_blocks

def adaptation_indices(num_blocks, super_block_indices) :
    indices = ['0'] * num_blocks
    for i in super_block_indices :
        indices[i] = '1'
    return indices

def encrypt_superblock_index(indices, key):
    indices_bytes = indices.encode()

    iv = get_random_bytes(16)  # IV unique pour chaque super bloc
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Padding standard PKCS7
    if len(indices_bytes) < AES.block_size:
        padded_indices = pad(indices_bytes, AES.block_size)  
    else: 
        padded_indices = indices_bytes

    encrypted_index = cipher.encrypt(padded_indices)

    return iv + encrypted_index

def remplace_super_block_file(file, indices, super_blocks, N_blocks):
    """ Remplace les super blocs dans le fichier par les nouveaux super blocs """
    with open(file, 'rb+') as f:
        data = f.read()
        new_data = data[:16] # On garde l'IV
        for i in range(N_blocks):
            if i in indices:
                new_data += super_blocks[indices.index(i)]
            else:
                new_data += data[16 + i * BLOCK_SIZE : 16 + (i + 1) * BLOCK_SIZE]

        # remplace les données dans le fichier
        f.seek(0)
        f.write(new_data)

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
    iv, blocks = divide_into_blocks(output_file)

    # Étape 3 : Formation de metaFK
    metaFK = compute_xor_metadata(blocks, file_key)

    # Sauvegarde de metaFK
    with open("metaFK.bin", "wb") as f:
        f.write(metaFK)
    
    print("MetaFK généré et stocké dans metaFK.bin")
    
    # Étape 4 : Identification des super blocs
    super_block_indices = identify_super_blocks(blocks, 2)
    super_block_indices.sort()
    super_blocks = [blocks[i] for i in super_block_indices]

    # Étape 6 : Chiffrement des super blocs avec une clé GK
    # Récupération de GK
    with open("gk_key", "rb") as f:
        gk_key = f.read()

    encrypted_super_blocks = encrypt_super_blocks(super_blocks, gk_key, iv)
    
    # Remplace les super blocs dans le fichier par les nouveaux super blocs
    remplace_super_block_file(output_file, super_block_indices, encrypted_super_blocks, len(blocks))

    # Sauvegarde de metaSK avec les IV
    with open("metaSK.bin", "wb") as f:
        for encrypted_block in encrypted_super_blocks:
            f.write(encrypted_block)

    print("MetaSK (super blocs chiffrés) généré et stocké dans metaSK.bin")

    # Affichage des super blocs sélectionnés
    print("Les super blocs sélectionnés sont :", super_block_indices)

    # Étape 5 : Chiffrement AES des indices des superblocs
    se_index = "".join(adaptation_indices(len(blocks), super_block_indices))
    
    sk_key = get_random_bytes(KEY_SIZE)  # Clé SK générée 
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
