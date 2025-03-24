import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import time

# Constantes
BLOCK_SIZE = 1024  # Taille de bloc en octets (1 Ko)
KEY_SIZE = 32      # Clé de 256 bits pour AES-256

def encrypt_classic(input_file, output_file, key):
    """Chiffre un fichier avec AES-256-CBC sans Knob."""
    
    iv = get_random_bytes(16)  # IV aléatoire

    start_time = time.time()  # Début chrono

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        outfile.write(iv)  # Écrire l'IV au début du fichier

        cipher = AES.new(key, AES.MODE_CBC, iv)

        while True:
            block = infile.read(BLOCK_SIZE)
            if len(block) == 0:
                break

            if len(block) < BLOCK_SIZE:  # Padding si dernier bloc
                block = pad(block, AES.block_size)  # AES.block_size = 16 octets


            encrypted_block = cipher.encrypt(block)
            outfile.write(encrypted_block)

    end_time = time.time()  # Fin chrono
    print(f"Chiffrement classique terminé en {end_time - start_time:.4f} secondes.")

def main():
    # Vérification des arguments
    if len(sys.argv) < 3:
        print("Usage: python encrypt_classic.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Générer une clé AES-256 aléatoire
    key = get_random_bytes(KEY_SIZE)
    
    # Chiffrement
    encrypt_classic(input_file, output_file, key)

    # Sauvegarde de la clé pour le déchiffrement
    with open("classic_key.bin", "wb") as key_file:
        key_file.write(key)

    print(f"Clé AES-256 sauvegardée dans classic_key.bin.")

# Point d'entrée du programme
if __name__ == "__main__":
    main()
