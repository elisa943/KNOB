import os
import sys
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


# --- Fonctions auxiliaires ---
def load_file(file):
    """ Charge un fichier """
    with open(file, "rb") as f:
        return f.read()

def load_key(file):
    """ Charge une clé """
    with open(file, "rb") as f:
        return RSA.import_key(f.read())

# --- Fonctions ---

def decrypt_group_keys(meta_task, admin_key, knob_pri_key):
    """ Récupère l'ancienne et la nouvelle clé de groupe """
    meta_task = load_file(meta_task)
    admin_key = load_file(admin_key)
    knob_pri_key = load_key(knob_pri_key)
    
    cipher_rsa_PSS = PKCS1_PSS.new(admin_key)
    cipher_rsa_OAEP = PKCS1_OAEP.new(knob_pri_key)
    group_keys = cipher_rsa_OAEP.decrypt(cipher_rsa_PSS.verify(meta_task))
    
    return group_keys[:32], group_keys[32:]

def encrypt_group_keys(group_key, new_group_key, knob_pri_key, admin_key):
    """ Renvoie meta_task (clés de groupe chiffrées) """
    group_key = load_file(group_key)
    new_group_key = load_file(new_group_key)
    knob_pri_key = load_key(knob_pri_key)
    admin_key = load_file(admin_key)
    
    knob_pub_key = knob_pri_key.publickey() 
    cipher_rsa_OAEP = PKCS1_OAEP.new(knob_pub_key) # Premier chiffrement OAEP
    cipher_rsa_PSS = PKCS1_PSS.new(admin_key) # Deuxième chiffrement PSS
    meta_task = cipher_rsa_PSS.sign(cipher_rsa_OAEP.encrypt(group_key + new_group_key))

    return meta_task

