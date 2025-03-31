import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

# Constantes
BLOCK_SIZE = 1024  # Taille d'un bloc en octets (1 Ko)
MACRO_BLOCK_SIZE = 4096  # Taille d'un macro-bloc
MINI_BLOCK_SIZE = 64  # Taille d'un mini-bloc
KEY_SIZE = 32  # Clé AES-256

def reencrypt_mixslice(input_file, output_file, old_key, new_key, mini_block_index=0):
    """
    Déchiffre un fichier avec old_key, modifie un mini-bloc, et rechiffre avec new_key.
    """
    start_time = time.time()

    with open(input_file, "rb") as infile:
        iv = infile.read(16)  # Lire l'IV stocké au début du fichier
        encrypted_data = infile.read()

    num_macro_blocks = len(encrypted_data) // MACRO_BLOCK_SIZE

    if num_macro_blocks == 0:
        print("Erreur : Fichier trop petit pour Mix&Slice.")
        sys.exit(1)

    # Sélection d'un macro-bloc aléatoire
    macro_index = num_macro_blocks // 2  # On prend le bloc central pour l'exemple
    macro_offset = macro_index * MACRO_BLOCK_SIZE

    # Déchiffrement du macro-bloc avec la clé classique
    cipher = AES.new(old_key, AES.MODE_CBC, iv)
    decrypted_macro = cipher.decrypt(encrypted_data[macro_offset:macro_offset + MACRO_BLOCK_SIZE])

    # Sélection du mini-bloc à rechiffrer
    mini_offset = mini_block_index * MINI_BLOCK_SIZE
    mini_block = decrypted_macro[mini_offset:mini_offset + MINI_BLOCK_SIZE]

    # Rechiffrement avec la nouvelle clé
    cipher_new = AES.new(new_key, AES.MODE_CBC, iv)
    new_encrypted_mini_block = cipher_new.encrypt(pad(mini_block, MINI_BLOCK_SIZE))

    # Mise à jour du macro-bloc
    modified_macro = (
        decrypted_macro[:mini_offset] +
        new_encrypted_mini_block +
        decrypted_macro[mini_offset + MINI_BLOCK_SIZE:]
    )

    # Réinsertion dans les données finales
    modified_data = (
        encrypted_data[:macro_offset] +
        modified_macro +
        encrypted_data[macro_offset + MACRO_BLOCK_SIZE:]
    )

    # Écriture du fichier modifié
    with open(output_file, "wb") as outfile:
        outfile.write(iv)  # Réécriture de l'IV
        outfile.write(modified_data)

    end_time = time.time()
    print(f"Rechiffrement Mix&Slice terminé en {end_time - start_time:.4f} secondes.")

def main():
    if len(sys.argv) < 3:
        print("Usage: python reencrypt_mixslice.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Chargement des clés
    with open("classic_key.bin", "rb") as key_file:
        old_key = key_file.read()
    with open("mixslice_new_key.bin", "rb") as key_file:
        new_key = key_file.read()

    reencrypt_mixslice(input_file, output_file, old_key, new_key)

if __name__ == "__main__":
    main()
