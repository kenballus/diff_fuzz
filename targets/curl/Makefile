CC := afl-clang-fast
CFLAGS := -Os

curl_target: curl_target.c curl/lib/.libs/libcurl.a
	$(CC) $(CFLAGS) curl_target.c curl/lib/.libs/libcurl.a -o curl_target

curl/lib/.libs/libcurl.a: get_curl.sh
	./get_curl.sh

.PHONY: clean
clean:
	rm -rf curl_target curl
