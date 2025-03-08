import hashlib

def xor_bytes(a, b):
    """Effectue un XOR entre deux valeurs de même longueur."""
    return bytes(x ^ y for x, y in zip(a, b))

def compute_xor_metadata(blocks, key, additional_elements=None):
    """
    Applique un XOR successif sur les hashes des blocs et une clé.
    
    Args:
    - blocks (list): Liste des blocs de données chiffrés.
    - key (bytes): Clé de chiffrement (FK ou SK).
    - additional_elements (list, optional): Éléments additionnels à inclure (ex: super blocks).
    
    Returns:
    - bytes: Valeur XOR finale.
    """
    if not blocks:
        raise ValueError("Liste de blocs vide, impossible de calculer le XOR.")

    # Initialiser meta avec un bloc de 32 octets à 0 (taille d'un hash SHA-256)
    meta = bytes(32)

    # XOR successif des hashes des blocs
    for block in blocks:
        block_hash = hashlib.sha256(block).digest()
        meta = xor_bytes(meta, block_hash)

    # XOR successif des éléments additionnels s'ils existent (ex: super blocks)
    if additional_elements:
        for element in additional_elements:
            element_hash = hashlib.sha256(element).digest()
            meta = xor_bytes(meta, element_hash)

    # XOR final avec la clé (FK ou SK)
    meta = xor_bytes(meta, key)

    return meta
