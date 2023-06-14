CC := afl-clang-fast
CFLAGS := -Wall -Wextra -g
INCLUDE := ./openssl/include

openssl_target: openssl_target.c openssl/libcrypto.a
#	$(CC) $(CFLAGS) -I$(INCLUDE) openssl_target.c openssl/libcrypto.a -o openssl_target
	$(CC) $(CFLAGS) -I$(INCLUDE) openssl_target.c -lcrypto -o openssl_target

openssl/libcrypto.a:
	./get_openssl.sh

.PHONY: clean run
clean:
	rm -rf openssl_target

run: openssl_target
	./openssl_target < ~/diff_fuzz/seeds/03.asn
