#!/bin/sh

[ ! -d curl ] || exit 0 && \
git clone https://github.com/curl/curl && \
cd curl && autoreconf -fi && \
export CC=afl-clang-fast && \
./configure --disable-ldap \
            --disable-shared \
            --without-ssl \
            --without-hyper \
            --without-zlib \
            --without-brotli \
            --without-zstd \
            --without-default-ssl-backend \
            --without-ca-bundle \
            --without-ca-path \
            --with-ca-fallback \
            --without-ca-fallback \
            --without-libpsl \
            --without-libgsasl \
            --without-librtmp \
            --without-winidn \
            --without-libidn2 \
            --without-nghttp2 \
            --without-ngtcp2 \
            --without-nghttp3 \
            --without-quiche \
            --without-msh3 && \
make -j$(nproc)
