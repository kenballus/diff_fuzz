#!/bin/bash

# There is no need to build boost with afl-clang because we only use the header-only portions of the library.
[ ! -d boost ] || exit 0 && git clone --recurse-submodules "https://github.com/boostorg/boost.git" && cd boost && cmake . && make -j$(nproc)
