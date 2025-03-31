import os
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Constantes
BLOCK_SIZE = 1024
MACRO_BLOCK_SIZE = 4096
MINI_BLOCK_SIZE = 64

def decrypt_mixslice(input_file, output_file, old_key, new_key=None):
    with open(input_file, "rb") as f:
        file_data = f.read()

    iv = file_data[:16]
    encrypted_data = file_data[16:]
    decrypted_data = bytearray()

    num_macro_blocks = len(encrypted_data) // MACRO_BLOCK_SIZE

    for macro_index in range(num_macro_blocks):
        macro_offset = macro_index * MACRO_BLOCK_SIZE
        macro_block = encrypted_data[macro_offset:macro_offset + MACRO_BLOCK_SIZE]

        cipher_old = AES.new(old_key, AES.MODE_CBC, iv)
        try:
            decrypted_macro = cipher_old.decrypt(macro_block)
            decrypted_data += decrypted_macro
            continue
        except:
            pass  # Essai avec nouvelle clé (si fournie)

        if new_key is None:
            print(f" Échec : Bloc modifié détecté à l’index {macro_index}. Accès refusé (clé manquante).")
            sys.exit(1)

        # Tentative de récupération avec nouvelle clé
        decrypted_macro = bytearray(cipher_old.decrypt(macro_block))
        found = False
        for i in range(0, MACRO_BLOCK_SIZE, MINI_BLOCK_SIZE):
            mini_block = macro_block[i:i + MINI_BLOCK_SIZE]
            cipher_new = AES.new(new_key, AES.MODE_CBC, iv)
            try:
                decrypted_mini = cipher_new.decrypt(mini_block)
                unpad(decrypted_mini, MINI_BLOCK_SIZE)
                decrypted_macro[i:i + MINI_BLOCK_SIZE] = decrypted_mini
                found = True
                print(f" Mini-bloc modifié récupéré à l’offset {macro_offset + i}")
                break
            except:
                continue

        if not found:
            print(f" Échec : Bloc modifié mais non récupérable même avec la nouvelle clé.")
            sys.exit(1)

        decrypted_data += decrypted_macro

    # Tentative de suppression du padding global
    try:
        decrypted_data = unpad(decrypted_data, AES.block_size)
    except:
        pass

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f" Déchiffrement terminé avec succès → {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Déchiffrement avec ou sans nouvelle clé (Mix&Slice).")
    parser.add_argument("input_file", help="Fichier chiffré (e.g. test_reencrypted.bin)")
    parser.add_argument("output_file", help="Fichier de sortie (e.g. test_decrypted.txt)")
    parser.add_argument("--with-new-key", action="store_true", help="Utiliser mixslice_new_key.bin pour récupérer les mini-blocs modifiés")

    args = parser.parse_args()

    with open("classic_key.bin", "rb") as f:
        old_key = f.read()

    new_key = None
    if args.with_new_key:
        try:
            with open("mixslice_new_key.bin", "rb") as f:
                new_key = f.read()
        except:
            print(" Impossible de charger mixslice_new_key.bin. Le fichier est-il présent ?")
            sys.exit(1)

    decrypt_mixslice(args.input_file, args.output_file, old_key, new_key)

if __name__ == "__main__":
    main()
