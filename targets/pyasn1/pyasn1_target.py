from sys import stdin, path
print(path)
from os import _exit
from pyasn1.codec.der.decoder import decode
import afl
afl.init()

asn = stdin.buffer.read()
x = decode(asn)
print(f"{x}")

_exit(0)