git clone 'https://github.com/libressl/portable' libressl && cd libressl && ./autogen.sh && CC=afl-clang-fast ./configure && make -j`nproc` && cd .. && make
