import os
import sys
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from xor_metadata import compute_xor_metadata
from Crypto.Util.Padding import pad

import requests

API_URL = "http://api-server-address"
API_KEY = "1234567890abcdef"

def send_to_api(endpoint, data):
    """Envoie les fichiers et métadonnées vers l'API REST."""
    headers = {"X-API-KEY": API_KEY}
    response = requests.post(f"{API_URL}{endpoint}", headers=headers, files=data)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erreur lors de l'envoi des données à {endpoint}: {response.text}")
        sys.exit(1)


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
        print("Usage: python knob_process.py <input_file> <path> <group key>")
        sys.exit(1)

    input_file = sys.argv[1]
    path = sys.argv[2]
    gk = sys.argv[3]
    output_file = "output.bin"

    # Initialiser la clé FK
    initialize_file_key()
    
    # Étape 1 : Chiffrement du fichier
    encrypt_file(input_file, output_file)
    
    # Étape 2 : Division en blocs
    iv, blocks = divide_into_blocks(output_file)

    # Étape 3 : Formation de metaFK
    metaFK = compute_xor_metadata(blocks, file_key)
    
    # Étape 4 : Identification des super blocs
    super_block_indices = identify_super_blocks(blocks, 2)
    super_block_indices.sort()
    super_blocks = [blocks[i] for i in super_block_indices]
    
    # Étape 6 : Chiffrement des super blocs avec une clé GK
    # Récupération de GK
    with open(gk, "rb") as f:
        gk_key = f.read()

    encrypted_super_blocks = encrypt_super_blocks(super_blocks, gk_key, iv)
    for i, super_block in enumerate(encrypted_super_blocks):
        blocks[super_block_indices[i]] = super_block
    
    # Remplace les super blocs dans le fichier par les nouveaux super blocs
    remplace_super_block_file(output_file, super_block_indices, encrypted_super_blocks, len(blocks))

    # Affichage des super blocs sélectionnés
    print("Les super blocs sélectionnés sont :", super_block_indices)

    # Étape 5 : Chiffrement AES des indices des superblocs
    se_index = "".join(adaptation_indices(len(blocks), super_block_indices))
    
    sk_key = get_random_bytes(KEY_SIZE)  # Clé SK générée 
    metaIndex = encrypt_superblock_index(se_index, sk_key)

    # Ètape 7 : Chiffrement RSA de la clé SK avec knob-pub-key
    with open("knob-pri-key", "rb") as f:
        knob_pri_key = RSA.import_key(f.read())

    knob_pub_key = knob_pri_key.publickey() 
    cipher_rsa = PKCS1_OAEP.new(knob_pub_key)
    metaSGX = cipher_rsa.encrypt(sk_key)
    
    # Sauvegarde de chaque bloc dans un dossier où chaque bloc est nommé par son indice
    if not os.path.exists("blocks"):
        os.makedirs("blocks") 

    if not os.path.exists("super_blocks"):
        os.makedirs("super_blocks")

    """
    i_block = 0
    i_super_block = 0
    for i in range(len(blocks)):
        if i in super_block_indices:
            file = "super_blocks/" + str(i_super_block) + ".bin"
            i_super_block += 1
        else: 
            file = "blocks/" + str(i_block) + ".bin"
            i_block += 1
        with open(file, "wb") as f:
            f.write(blocks[i])
    """

    i_block = 0
    i_super_block = 0
    with open(output_file, "rb") as f:
        # Sauvegarde de l'IV dans le dossier blocks
        with open("blocks/iv.bin", "wb") as f_iv:
            f_iv.write(f.read(16)) # Lecture de l'IV
        
        # Sauvegarde de chaque bloc dans un fichier
        for i in range(len(blocks)):
            if i in super_block_indices:
                file = "super_blocks/" + str(i_super_block) + ".bin"
                i_super_block += 1
            else: 
                file = "blocks/" + str(i_block) + ".bin"
                i_block += 1
            
            with open(file, "wb") as f_block:
                block = f.read(BLOCK_SIZE)
                f_block.write(block)

    if (i_block + i_super_block) == len(blocks):
        print("Les blocs ont été sauvegardés dans le dossier blocks et les super blocs dans le dossier super_blocks")

    # Envoi du fichier chiffré à l'API et récupération du file_id
    encrypted_data = b"".join(blocks)
    response = send_to_api("/upload", {"file": ("encrypted_file.bin", encrypted_data)})
    file_id = response["file_id"]

    # Envoi des métadonnées à l’API
    metadata = {
        "file_id": file_id,
        "metaFK": metaFK,
        "metaSK": b''.join(encrypted_super_blocks), # TODO : ???? on est censé faire un XOR 
        "metaIndex": metaIndex,
        "metaSGX": metaSGX
    }

    send_to_api("/store_metadata", {"metadata": ("metadata.bin", str(metadata).encode())})

    print(f"Fichier {input_file} chiffré et stocké avec succès. File ID: {file_id}")


    # Suppression du fichier chiffré
    os.remove(output_file)

# Point d'entrée du programme
if __name__ == "__main__":
    main()
