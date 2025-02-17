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

def load_files(data_blocks_file, metaFK_file, metaSK_file, metaIndex_file, metaSGX_file, group_key_file, knob_priv_key_file):
    """Charge les fichiers nécessaires pour le déchiffrement."""
    with open(data_blocks_file, "rb") as f_data:
        data_blocks = f_data.read()
    
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
    
    return data_blocks, metaFK, metaSK, metaIndex, metaSGX, group_key, knob_priv_key

def aes_decrypt(encrypted_data, key, iv=None):
    # Extraire l'IV des premiers 16 octets
    if (iv is None):
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]  # Le reste est le texte chiffré
    else:
        cipher_text = encrypted_data
    
    # Initialiser le déchiffreur AES en mode CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Déchiffrer et retirer le padding
    if (len(cipher_text) % 16 != 0):
        decrypted_data = unpad(cipher.decrypt(cipher_text), AES.block_size)
    else: # Pas besoin de padding
        decrypted_data = cipher.decrypt(cipher_text)
    return decrypted_data

def divide_into_blocks(data_blocks, N_blocks): 
    #print("IV : ", data_blocks[:16])
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
    #print("Indices des super blocs : ", super_block_indices_str)
    N_blocks = 0
    super_block_indices = []
    for i in range(len(super_block_indices_str)):
        N_blocks += 1
        if super_block_indices_str[i] == '1':
            print("Super bloc trouvé à l'indice : ", i)
            super_block_indices.append(i)
        elif super_block_indices_str[i] != '0':
            break
    return super_block_indices, N_blocks - 1

def get_blocks_decrypted(data, super_block_indices, N_blocks, group_key, iv):
    """ Récupère les blocs déchiffrés """
    super_blocs = []
    for i in range(N_blocks):
        if (i in super_block_indices): # Déchiffrement du super bloc avec GK 
            donnee = aes_decrypt(data[i], group_key, iv)
            super_blocs.append(donnee)
            print("Super bloc déchiffré (1 fois) : ", donnee[:16])

    return super_blocs

def main():
    # Vérification des arguments
    if len(sys.argv) < 9:
        print("Usage: python knob_decrypt.py <data blocks> <meta_FK> <meta_SK> <meta_index> <meta_SGX> <group key> <knob-pri-key> <output_file>")
        sys.exit(1)

    # Initialisation des fichiers
    data_blocks, metaFK, metaSK, metaIndex, metaSGX, group_key, knob_priv_key = load_files(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
    
    # Inverse de la deuxième AONT pour retrouver SK 
    sk = get_sk(knob_priv_key, metaSGX)
    
    # Vérification de meta_SK
    
    # Déduction des indices des super blocs
    super_block_indices, N_blocks = get_super_blocks_indices(metaIndex, sk)

    # Calcul du nombre de blocs
    #N_blocks = os.path.getsize((sys.argv[1]) - 16) // BLOCK_SIZE

    # Segmentation des blocs à partir des données chiffrées
    data, iv = divide_into_blocks(data_blocks, N_blocks)

    # Reconstruction des blocs complètement déchiffrés
    blocs = get_blocks_decrypted(data, super_block_indices, N_blocks, group_key, iv)

    for index in super_block_indices:
        data[index] = blocs[super_block_indices.index(index)]

    # Inverse de la première AONT pour retrouver FK
    fk = metaFK
    for i in range(len(data)):
        fk = xor_bytes(hashlib.sha256(data[i]).digest(), fk)
    print("FK : ", fk)
    
    # Déchiffrement des blocs avec FK et écriture sur le fichier de sortie 
    
    # Ecriture du fichier de sortie
    with open(sys.argv[8], "wb") as f:
        for i in range(len(data)):
            f.write(aes_decrypt(data[i], fk, iv))
    
    print("Fichier déchiffré avec succès : ", sys.argv[1], "-> ", sys.argv[8])

# Point d'entrée du programme
if __name__ == "__main__":
    main()