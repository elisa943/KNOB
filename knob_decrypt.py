import hashlib
import os
import sys
from xor_metadata import xor_bytes
from rsa_aes import rsa_decryption
from rsa_aes import aes_decrypt_file
from Crypto.PublicKey import RSA

# Constantes
BLOCK_SIZE = 1024  # Taille de bloc en octets (1 Ko)

def load_files(data_blocks_file, metaFK_file, metaSK_file, metaIndex_file, metaSGX_file, group_key_file):
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
    
    return data_blocks, metaFK, metaSK, metaIndex, metaSGX, group_key

def main():
    # Vérification des arguments
    if len(sys.argv) < 8:
        print("Usage: python knob_decrypt.py <data blocks> <meta_FK> <meta_SK> <meta_index> <meta_SGX> <group key> <output_file>")
        sys.exit(1)

    # Initialisation des fichiers
    data_blocks, metaFK, metaSK, metaIndex, metaSGX, group_key = load_files(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])

    # Calcul du nombre de blocs
    N_blocks = (os.path.getsize(sys.argv[1]) + BLOCK_SIZE - 1) // BLOCK_SIZE

    # Segmentation des data_blocks 
    data = []
    for i in range(N_blocks):
        data.append(data_blocks[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE])
    
    # Récupération de la clé publique à partir de la clé privée
    with open("knob_priv_key.pem", "rb") as f: # TODO : modifier 
        knob_priv_key = RSA.import_key(f.read())
    knob_pub_key = knob_priv_key.publickey()
    
    # Inverse de la deuxième AONT pour retrouver SK 
    sk = rsa_decrypt(metaSGX, knob_pub_key)
    
    # Vérification de meta_SK
    
    # Déduction des indices des super blocs
    super_block_indices_str = aes_decrypt(metaIndex, sk).decode('utf-8') # Caractères de 0 et de 1 pour les super blocs
    super_block_indices = []
    for i in range(len(super_block_indices_str)):
        if super_block_indices_str[i] == '1':
            super_block_indices.append(i)

    # Reconstruction des blocs complètement déchiffrés
    blocs = b''
    for i in range(N_blocks):
        if (i not in super_block_indices):
            blocs += data[i]
        else: # Déchiffrement du super bloc avec GK 
            blocs += aes_decrypt(data[i], group_key)
    
    # Inverse de la première AONT pour retrouver FK
    fk = xor_bytes(hashlib.sha256(blocs).digest(), metaFK)
    
    # Déchiffrement des blocs avec FK et écriture sur le fichier de sortie 
    file_plaintext = aes_decrypt(blocs, sys.argv[7], fk)
    
    # Ecriture du fichier de sortie
    with open(sys.argv[7], "wb") as f:
        f.write(file_plaintext)

# Point d'entrée du programme
if __name__ == "__main__":
    main()