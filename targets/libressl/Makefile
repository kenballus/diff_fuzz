CC := afl-clang-fast
CFLAGS := -Wall -Wextra -g
INCLUDE := ./portable/include

openssl_target: libressl_target.c ./portable/crypto/.libs/libcrypto.a
	$(CC) $(CFLAGS) -I$(INCLUDE) libressl_target.c ./portable/crypto/.libs/libcrypto.a -o libressl_target

openssl/libcrypto.a:
	./get_openssl.sh

.PHONY: clean run patch save_patch
patch:
	patch libressl/crypto/asn1/asn1_par.c < asn1_par.patch

copy:
	cp asn1_par.c libressl/crypto/asn1/asn1_par.c

save_patch:
	diff --text --unified --new-file libressl/crypto/asn1/asn1_par.c asn1_par.c > asn1_par.patch

clean:
	rm -rf libressl_target libressl

run: libressl_target
	./libressl_target < ~/diff_fuzz/seeds/03.asn
