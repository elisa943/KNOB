import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

# Constantes
BLOCK_SIZE = 1024  # Taille de bloc en octets (1 Ko)
KEY_SIZE = 32      # Clé de 256 bits pour AES-256

def decrypt_classic(input_file, output_file, key):
    """Déchiffre un fichier avec AES-256-CBC sans Knob."""
    
    start_time = time.time()  # Début chrono

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        iv = infile.read(16)  # Lire l'IV stocké au début du fichier

        cipher = AES.new(key, AES.MODE_CBC, iv)

        while True:
            block = infile.read(BLOCK_SIZE)
            if len(block) == 0:
                break

            decrypted_block = cipher.decrypt(block)

            if len(block) < BLOCK_SIZE:  # Dernier bloc -> retirer le padding
                decrypted_block = unpad(decrypted_block, AES.block_size)  # AES.block_size = 16 octets


            outfile.write(decrypted_block)

    end_time = time.time()  # Fin chrono
    print(f"Déchiffrement classique terminé en {end_time - start_time:.4f} secondes.")

def main():
    # Vérification des arguments
    if len(sys.argv) < 3:
        print("Usage: python decrypt_classic.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Charger la clé AES-256
    with open("classic_key.bin", "rb") as key_file:
        key = key_file.read()
    
    # Déchiffrement
    decrypt_classic(input_file, output_file, key)

# Point d'entrée du programme
if __name__ == "__main__":
    main()
