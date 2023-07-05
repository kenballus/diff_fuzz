#!/usr/bin/env python3

import sys
import afl
afl.init()


def main() -> None:
    if(len(sys.argv) > 3):
        sys.exit(1)
    arg1: str = sys.argv[1]
    arg2: str = sys.argv[2]

    val1: int = int(arg1)
    if len(arg2) % 2 != 1:
        sys.exit(1)
    if len(arg2) > val1:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
