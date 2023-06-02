from sys import stdin
from os import _exit
import afl
from asn1crypto.core import load

afl.init()
asn = stdin.buffer.read()
x = load(asn, strict=True)
print(f"{x}")

_exit(0)