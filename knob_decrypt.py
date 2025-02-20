import hashlib
import os
import sys
from xor_metadata import xor_bytes
from xor_metadata import compute_xor_metadata
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Constantes
BLOCK_SIZE = 1024  # Taille de bloc en octets (1 Ko)

def load_files(metaFK_file, metaSK_file, metaIndex_file, metaSGX_file, group_key_file, knob_priv_key_file):
    """Charge les fichiers nécessaires pour le déchiffrement."""
    
    with open(metaFK_file, "rb") as f_metaFK:
        metaFK = f_metaFK.read()
    
    with open(metaSK_file, "rb") as f_metaSK:
        metaSK = f_metaSK.read()
    
    with open(metaIndex_file, "rb") as f_metaIndex:
        metaIndex = f_metaIndex.read()
    
    with open(metaSGX_file, "rb") as f_metaSGX:
        metaSGX = f_metaSGX.read()
    
    with open(group_key_file, "rb") as f_gk:
        group_key = f_gk.read()
    
    with open(knob_priv_key_file, "rb") as f_kpk:
        knob_priv_key = RSA.import_key(f_kpk.read())
    
    return metaFK, metaSK, metaIndex, metaSGX, group_key, knob_priv_key

def load_data(path, super_block_indices, N_blocks):
    """Récupère tous les fichiers du dossier path/blocks et path/super_blocks pour reconstituer les données chiffrées."""
    if not (os.path.exists("super_blocks") and os.path.exists("blocks")):
        print("Les dossiers super_blocks et blocks n'existent pas.")
        sys.exit(1)
    
    # Nombre de blocs et de super blocs
    N_super_blocks = len(super_block_indices)

    # Récupérer les fichiers des super blocs
    super_blocks = []
    for i in range(N_super_blocks):
        file = path + "/super_blocks/" + str(i) + ".bin"
        with open(file, "rb") as f:
            super_blocks.append(f.read())
    
    data_blocks = []
    i_block = 0
    i_super_block = 0
    for i in range(N_blocks):
        if i in super_block_indices:
            data_blocks.append(super_blocks[i_super_block])
            i_super_block += 1
        else:
            file = path + "/blocks/" + str(i_block) + ".bin"
            with open(file, "rb") as f:
                data_blocks.append(f.read())
            i_block += 1
    
    # Récupération de l'IV
    with open(path + "/blocks/iv.bin", "rb") as f:
        iv = f.read()
    
    return iv, data_blocks

def aes_decrypt(encrypted_data, key, iv=None, block_size=AES.block_size, unpadd=True, cipher=None):
    # Extraire l'IV des premiers 16 octets
    if (iv is None):
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]  # Le reste est le texte chiffré
    else:
        cipher_text = encrypted_data
    
    # Initialiser le déchiffreur AES en mode CBC
    if cipher is None:
        cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(cipher_text)
    if unpadd:
        return unpad(decrypted_data, block_size)
    return decrypted_data

def divide_into_blocks(data_blocks, N_blocks): 
    data = [] # Blocs de données chiffrées (sans l'IV)
    iv = data_blocks[:16] # Extraire l'IV des premiers 16 octets
    for i in range(N_blocks):
        start = i * BLOCK_SIZE 
        end = (i + 1) * BLOCK_SIZE
        data.append(data_blocks[16+start:end+16])
    return data, iv

def get_sk(knob_priv_key, metaSGX):
    """ Utilise RSA pour récupérer SK"""
    cipher_rsa = PKCS1_OAEP.new(knob_priv_key)  # Déchiffrement avec la clé privée
    return cipher_rsa.decrypt(metaSGX)

def get_super_blocks_indices(metaIndex, sk):
    """ Récupère les indices des super blocs"""
    super_block_indices_str = aes_decrypt(metaIndex, sk).decode('utf-8') # Caractères de 0 et de 1 pour les super blocs
    N_blocks = 0
    super_block_indices = []
    for i in range(len(super_block_indices_str)):
        N_blocks += 1
        if super_block_indices_str[i] == '1':
            print("Super bloc trouvé à l'indice : ", i)
            super_block_indices.append(i)
        elif super_block_indices_str[i] != '0':
            break
    return super_block_indices, N_blocks

def get_blocks_decrypted(data, super_block_indices, group_key, iv):
    """ Récupère les blocs déchiffrés """
    super_blocs = []
    for i in super_block_indices: # Déchiffrement du super bloc avec GK 
        super_blocs.append(aes_decrypt(data[i], group_key, iv, BLOCK_SIZE, False))

    return super_blocs

def main():
    # Vérification des arguments
    if len(sys.argv) < 9:
        print("Usage: python knob_decrypt.py <path> <meta_FK> <meta_SK> <meta_index> <meta_SGX> <group key> <knob-pri-key> <output_file>")
        sys.exit(1)

    # Initialisation des fichiers
    metaFK, metaSK, metaIndex, metaSGX, group_key, knob_priv_key = load_files(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
    
    # Inverse de la deuxième AONT pour retrouver SK 
    sk = get_sk(knob_priv_key, metaSGX)
    
    # Vérification de meta_SK
    
    # Déduction des indices des super blocs
    super_block_indices, N_blocks = get_super_blocks_indices(metaIndex, sk)

    # TODO 
    iv, data = load_data(sys.argv[1], super_block_indices, N_blocks)

    # Segmentation des blocs à partir des données chiffrées
    #data, iv = divide_into_blocks(data_blocks, N_blocks)
    
    # Reconstruction des blocs complètement déchiffrés
    superBlocs = get_blocks_decrypted(data, super_block_indices, group_key, iv)
    for i in range(len(superBlocs)):
        data[super_block_indices[i]] = superBlocs[i]

    # Inverse de la première AONT pour retrouver FK
    fk = metaFK
    for i in range(len(data)):
        fk = xor_bytes(hashlib.sha256(data[i]).digest(), fk)
    
    # Déchiffrement des blocs avec FK et écriture sur le fichier de sortie 
    
    # Ecriture du fichier de sortie
    with open(sys.argv[8], "wb") as f:
        cipher = AES.new(fk, AES.MODE_CBC, iv)
        
        for i in range(len(data)):
            if i < len(data) - 1: # TODO : Gérer le cas où le dernier bloc est de bonne taille BLOCK_SIZE
                temp = aes_decrypt(data[i], fk, iv, BLOCK_SIZE, False, cipher)
            else: 
                temp = aes_decrypt(data[i], fk, iv, BLOCK_SIZE, True, cipher)

            f.write(temp)
    
    print("Fichier déchiffré avec succès -> ", sys.argv[8])

# Point d'entrée du programme
if __name__ == "__main__":
    main()