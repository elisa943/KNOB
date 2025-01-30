# KNOB

## RSA | Guide pour utiliser RSA

1. Installer OpenSSL

```
sudo apt-get install libssl-dev  # Debian/Ubuntu
brew install openssl             # macOS (via Homebrew)
```

2. Génération de la clé privée RSA

```
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:4096
```

3. Génération de la clé publique RSA

```
openssl rsa -in private.pem -pubout -out public.pem
```

4. Compilation des fichiers RSA

```
make
```

5. Chiffrement d'un message

```
./rsa_encrypt file.txt
./rsa_decrypt
```