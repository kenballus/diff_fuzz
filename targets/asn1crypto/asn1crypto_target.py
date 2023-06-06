from sys import stdin
from os import _exit
import afl
from base64 import b64encode

from asn1crypto.core import load

def build_tree(base) -> str:
    tag: int = base.tag
    tag_json: str = f"{{\"tag\":\"{tag}\",\"value\":"
    if tag == 16 or tag == 17:
        return tag_json + "[" + ",".join(f"{build_tree(base[i])}" for i in range(len(base))) + "]}"
    
    if tag == 3:
        value = ''.join(map(str, base.native))
    else:
        value = base.native

    return tag_json + f"\"{b64encode(str(value).encode('utf-8')).decode('ascii')}\"}}"

def main() -> None:
    afl.init()
    asn = stdin.buffer.read()
    x = load(asn, strict=True)
    print(f"{{\"tree\" : {build_tree(x)}}}", flush=True)

    _exit(0)

if __name__ == "__main__":
    main()
