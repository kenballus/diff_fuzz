#!/usr/bin/env python3
from sys import stdin
from os import _exit
from pyasn1.codec.der.decoder import decode
from datetime import datetime
from base64 import b64encode
import afl

def build_tree(base) -> str:
    tag: int = base.tagSet.superTags[0][2]
    tag_json: str = f"{{\"tag\":\"{tag}\",\"value\":"
    if tag == 16 or tag == 17:
        return tag_json + "[" + ",".join(f"{build_tree(z)}" for z in base.components) + "]}"
    
    if tag == 4:
        value = bytes(base)
    elif tag == 5:
        value = None
    elif tag == 23:
        value = datetime.strptime(str(base), r'%y%m%d%H%M%S%z')
    elif tag == 24:
        value = datetime.strptime(str(base), r'%Y%m%d%H%M%S%z')
    else:
        value = base

    return tag_json + f"\"{b64encode(str(value).encode('utf-8')).decode('ascii')}\"}}"

def main() -> None:
    afl.init()
    asn = stdin.buffer.read()
    x = decode(asn)[0]
    print(f"{{\"tree\" : {build_tree(x)}}}", flush=True)

    _exit(0)

if __name__ == "__main__":
    main()
