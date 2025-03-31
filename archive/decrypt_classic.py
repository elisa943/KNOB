import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

# Constantes
BLOCK_SIZE = 1024  # Taille de lecture
KEY_SIZE = 32      # Clé AES-256

def decrypt_classic(input_file, output_file, key):
    """Déchiffre un fichier chiffré en AES-256-CBC (mode classique)."""
    
    start_time = time.time()  # Chrono début

    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        iv = infile.read(16)  # Récupération de l'IV

        cipher = AES.new(key, AES.MODE_CBC, iv)

        while True:
            block = infile.read(BLOCK_SIZE)
            if len(block) == 0:
                break

            decrypted_block = cipher.decrypt(block)

            if len(block) < BLOCK_SIZE:  # Dernier bloc → retirer le padding
                decrypted_block = unpad(decrypted_block, AES.block_size)

            outfile.write(decrypted_block)

    end_time = time.time()
    print(f"Déchiffrement classique terminé en {end_time - start_time:.4f} secondes.")

def main():
    if len(sys.argv) < 3:
        print("Usage: python decrypt_classic.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Charger la clé AES-256 depuis le fichier
    with open("classic_key.bin", "rb") as key_file:
        key = key_file.read()
    
    decrypt_classic(input_file, output_file, key)

if __name__ == "__main__":
    main()
