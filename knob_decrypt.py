import hashlib
import os
import sys
from xor_metadata import xor_bytes
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

def aes_decrypt(encrypted_data, key):
    # Extraire l'IV des premiers 16 octets
    iv = encrypted_data[:16]
    cipher_text = encrypted_data[16:]  # Le reste est le texte chiffré
    
    # Initialiser le déchiffreur AES en mode CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Déchiffrer et retirer le padding
    if (len(cipher_text) % 16 != 0):
        decrypted_data = unpad(cipher.decrypt(cipher_text), AES.block_size)
    else: # Pas besoin de padding
        decrypted_data = cipher.decrypt(cipher_text)
    return decrypted_data

def main():
    # Vérification des arguments
    if len(sys.argv) < 9:
        print("Usage: python knob_decrypt.py <data blocks> <meta_FK> <meta_SK> <meta_index> <meta_SGX> <group key> <knob-pri-key> <output_file>")
        sys.exit(1)

    # Initialisation des fichiers
    data_blocks, metaFK, metaSK, metaIndex, metaSGX, group_key, knob_priv_key = load_files(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])

    # Calcul du nombre de blocs
    N_blocks = (os.path.getsize(sys.argv[1]) + BLOCK_SIZE - 1) // BLOCK_SIZE

    # Segmentation des blocs à partir des données chiffrées
    data = []
    for i in range(N_blocks):
        start = i * BLOCK_SIZE 
        end = (i + 1) * BLOCK_SIZE
        data.append(data_blocks[start:end])
    
    # Inverse de la deuxième AONT pour retrouver SK 
    cipher_rsa = PKCS1_OAEP.new(knob_priv_key)  # Déchiffrement avec la clé privée
    sk = cipher_rsa.decrypt(metaSGX)
    
    # Vérification de meta_SK
    
    # Déduction des indices des super blocs
    super_block_indices_str = aes_decrypt(metaIndex, sk).decode('utf-8') # Caractères de 0 et de 1 pour les super blocs
    print("Indices des super blocs : ", super_block_indices_str)
    
    super_block_indices = []
    for i in range(len(super_block_indices_str)):
        if super_block_indices_str[i] == '1':
            print("Super bloc trouvé à l'indice : ", i)
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
    file_plaintext = aes_decrypt(blocs, fk)
    
    # Ecriture du fichier de sortie
    with open(sys.argv[8], "wb") as f:
        f.write(file_plaintext)
    
    print("Fichier déchiffré avec succès : ", sys.argv[1], "-> ", sys.argv[8])

# Point d'entrée du programme
if __name__ == "__main__":
    main()