#!/usr/bin/env python3

import sys
import afl
afl.init()

def read_char_as_int() -> int:
    try:
        char_read: str = sys.stdin.read(1)
    except UnicodeDecodeError:
        sys.exit(255)
    if char_read == "":
        sys.exit(255)
    return ord(char_read)


def main() -> None:
    age: int = read_char_as_int()
    if age > 1:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
