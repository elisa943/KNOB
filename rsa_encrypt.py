from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys

# Définition du fichier de sortie pour le fichier chiffré
ENCRYPTED_FILE = "encrypted.bin"

def load_public_key(pub_key_file):
    """Charge une clé publique RSA depuis un fichier PEM."""
    try:
        with open(pub_key_file, "rb") as f:
            key = RSA.import_key(f.read())
        return key
    except Exception as e:
        print(f"Erreur lors du chargement de la clé publique : {e}")
        return None

def rsa_encrypt(public_key, message):
    """Chiffre un message avec une clé publique RSA en utilisant PKCS1_OAEP."""
    try:
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message)
        return encrypted
    except Exception as e:
        print(f"Erreur lors du chiffrement : {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print(f"Utilisation : {sys.argv[0]} <fichier_à_chiffrer>")
        sys.exit(1)

    input_file = sys.argv[1]
    pub_key_file = "public.pem"

    # Charger la clé publique
    public_key = load_public_key(pub_key_file)
    if not public_key:
        print("Échec du chargement de la clé publique.")
        sys.exit(1)

    # Lire le fichier d'entrée
    try:
        with open(input_file, "rb") as f:
            message = f.read()
    except Exception as e:
        print(f"Erreur lors de l'ouverture du fichier d'entrée : {e}")
        sys.exit(1)

    # Chiffrer le message
    encrypted = rsa_encrypt(public_key, message)

    # Sauvegarder le fichier chiffré
    try:
        with open(ENCRYPTED_FILE, "wb") as f:
            f.write(encrypted)
        print(f"Fichier chiffré enregistré sous '{ENCRYPTED_FILE}'")
    except Exception as e:
        print(f"Erreur lors de l'écriture du fichier de sortie : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
