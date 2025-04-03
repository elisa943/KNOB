# Commandes à utiliser pour appeler les scripts de chiffrement, déchiffrement et rechiffrement 

## Chiffrement 

```bash
python3 encryption.py [file]
```

Si le chemin du fichier n'est pas précisé, le script chiffre par défaut `files/sample.txt`. 

Les blocs du fichier chiffré sont envoyés dans Cassandra, tout comme son `file_id`. 

## Déchiffrement 

```bash
python3 decryption.py [file_id]
```
Si le `file_id`n'est pas précisé, le script demande à l'utilisateur de l'écrire sur la console. 

Pour l'instant, les clés de groupe sont récupérées dans le dossier `keys`. 

## Rechiffrement

```bash
python3 reencryption.py [file_id] [knob_pri_key]
```

- Si aucun argument n'est donné, le script demande à l'utilisateur de l'écrire sur la console. 
- Si seulement le `file_id` est donné, alors le script récupère la `knob-pri-key` dans le dossier `keys`. 

ATTENTION : 
- l'argument `[knob_pri_key]` correspond **exactement** à la clé `knob_pri_key` et non pas au chemin menant au fichier contenant la clé. 
- la commande `python3 reencryption.py [knob_pri_key]` ne fonctionnera pas car le script considèrera que la `knob-pri-key` est le `file_id`. Autrement dit, il faut bien respecter l'ordre. 
