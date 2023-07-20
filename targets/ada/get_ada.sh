#!/bin/sh
[ ! -d ada ] || exit 0 && git clone "https://github.com/ada-url/ada" && cd ada && python3 singleheader/amalgamate.py
