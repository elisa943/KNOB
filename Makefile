CC = gcc
CFLAGS = -I/opt/homebrew/opt/openssl/include -Wall -Wextra -Werror
LDFLAGS = -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto
SRC = rsa_encrypt.c rsa_decrypt.c aes.c
OBJ = $(SRC:.c=.o)
TARGETS = rsa_encrypt rsa_decrypt aes

all: $(TARGETS)

rsa_encrypt: rsa_encrypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

rsa_decrypt: rsa_decrypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

aes: aes.o
	openssl rand -hex 32 > cle_aes.pem
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ) $(TARGETS) *.bin
