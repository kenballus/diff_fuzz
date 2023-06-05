from sys import stdin
from os import _exit
from pyasn1.codec.der.decoder import decode
import afl

def build_tree(base) -> str:
    tag: int = base.tagSet.superTags[0][2]
    tag_json: str = f"{{\"tag\" : \"{tag}\", \"value\" : "

    if tag == 16 or tag == 17:
        return tag_json + "[" + ",".join(f"{build_tree(z)}" for z in base.components) + "]}"
    else:
        # TODO: Base-64 Value
        return tag_json + f"\"{base}\"}}"
    

def main() -> None:
    afl.init()
    asn = stdin.buffer.read()
    x = decode(asn)[0]
    print(build_tree(x))

    _exit(0)

if __name__ == "__main__":
    main()
