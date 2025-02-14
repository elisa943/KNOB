import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_decrypt(encrypted_data, key):
    """Déchiffre des données avec AES-256 en mode CBC et retourne les données déchiffrées."""
    # Lire le vecteur d'initialisation (IV) de 16 octets
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]
    
    # Initialiser le déchiffreur
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Déchiffrer les données
    decrypted_data = cipher.decrypt(encrypted_content)
    
    # Enlever le padding PKCS7
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    
    return decrypted_data

def load_private_key(private_key_path):
    """Charge une clé privée depuis un fichier PEM."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Mettre un mot de passe si nécessaire
        )
    return private_key

def rsa_decrypt(private_key, encrypted_data):
    """Déchiffre les données RSA et retourne les données déchiffrées."""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decryption(private_key_path, input_file):
    if not os.path.exists(private_key_path):
        print(f"Error: Private key file '{private_key_path}' not found.")
        sys.exit(1)
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    private_key = load_private_key(private_key_path)
    return rsa_decrypt(private_key, input_file)