CC := gcc
CFLAGS := -Wall -g
INCLUDE := 

openssl_target: openssl_target.c
	$(CC) $(CFLAGS) openssl_target.c -o openssl_target -lcrypto

.PHONY: clean run
clean:
	rm -rf openssl_target

run: openssl_target
	./openssl_target < ~/diff_fuzz/seeds/02.asn
