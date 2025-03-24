import os
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time

# Constantes
BLOCK_SIZE = 1024  # Taille d'un bloc en octets
MACRO_BLOCK_SIZE = 4096  # Taille d'un macro-bloc (4 Ko)
MINI_BLOCK_SIZE = 64  # Taille d'un mini-bloc (64 octets)
KEY_SIZE = 32  # Clé AES-256

def reencrypt_mini_block(file_path, key, output_file):
    """
    Effectue un re-chiffrement partiel à la manière de Mix&Slice en mettant à jour un mini-bloc.
    """
    
    start_time = time.time()  # Début chrono
    
    with open(file_path, "rb") as f:
        file_data = f.read()

    iv = file_data[:16]  # Lire l'IV
    encrypted_data = file_data[16:]  # Récupérer les blocs chiffrés
    
    num_macro_blocks = len(encrypted_data) // MACRO_BLOCK_SIZE

    if num_macro_blocks == 0:
        print("Erreur : Le fichier est trop petit pour Mix&Slice.")
        sys.exit(1)

    # Sélection aléatoire d'un macro-bloc à modifier
    macro_index = random.randint(0, num_macro_blocks - 1)
    macro_offset = macro_index * MACRO_BLOCK_SIZE

    # Sélection aléatoire d'un mini-bloc à re-chiffrer dans ce macro-bloc
    mini_index = random.randint(0, MACRO_BLOCK_SIZE // MINI_BLOCK_SIZE - 1)
    mini_offset = macro_offset + (mini_index * MINI_BLOCK_SIZE)

    # Récupération du mini-bloc à re-chiffrer
    mini_block = encrypted_data[mini_offset:mini_offset + MINI_BLOCK_SIZE]

    # Re-chiffrement avec une nouvelle clé aléatoire (comme si GK changeait)
    new_key = get_random_bytes(KEY_SIZE)
    cipher = AES.new(new_key, AES.MODE_CBC, iv)
    new_mini_block = cipher.encrypt(pad(mini_block, MINI_BLOCK_SIZE))

    # Mise à jour du fichier avec le mini-bloc re-chiffré
    new_data = bytearray(file_data)
    new_data[16 + mini_offset : 16 + mini_offset + MINI_BLOCK_SIZE] = new_mini_block

    # Écriture dans un nouveau fichier
    with open(output_file, "wb") as f:
        f.write(new_data)

    end_time = time.time()  # Fin chrono
    print(f"Re-chiffrement Mix&Slice terminé en {end_time - start_time:.4f} secondes.")
    print(f"Un mini-bloc a été modifié dans le macro-bloc {macro_index}.")

    # Sauvegarde de la nouvelle clé GK (simulée)
    with open("mixslice_new_key.bin", "wb") as f_key:
        f_key.write(new_key)

def main():
    if len(sys.argv) < 3:
        print("Usage: python reencrypt_mixslice.py <input_file> <output_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    output_file = sys.argv[2]

    # Charger la clé actuelle
    with open("classic_key.bin", "rb") as key_file:
        key = key_file.read()

    # Effectuer le re-chiffrement partiel
    reencrypt_mini_block(file_path, key, output_file)

if __name__ == "__main__":
    main()
