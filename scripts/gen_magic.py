#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate the magic file"""

import os
from warnings import filterwarnings as filter_warnings

import armour.crypt
from armour.pdb import header


def passes(txt: str, typ: str, offset: int, comma: str = ",") -> str:
    """generates passes grammar"""

    print(f" * generating grammar for {txt!r}, offset {offset}")

    return f""">{offset} le{typ} x %u {txt}
>>{offset} le{typ} =1 pass{comma}
>>{offset} le{typ} =0 passes{comma}
>>{offset} le{typ} >1 passes{comma}"""


def main() -> int:
    """entry / main function"""

    print(" * generating the `magic` file")

    with open("magic", "w") as fp:
        fp.write(
            f"""0 string {repr(header.MAGIC)[2:-1]} pDB database
>4 leshort x version %d,
"""
            + "\n".join(
                f">>6 ubyte ={idx} {halg.name}"
                for idx, halg in enumerate(armour.crypt.HASHES)
            )
            + f"""
>6 ubyte x hashing algorithm,
>>7 ubyte =0 worst compression,
>>7 ubyte <22 compression level %u,
>>7 ubyte =22 best compression,
>8 ubyte x salt length of %u B,
{passes('kdf', 'long', 9)}
{passes('secure encryption', 'short', 13)}
{passes('insecure encryption', 'short', 15, ', and')}
{passes('aes encryption', 'short', 17, '')}"""
        )

    print(" * compiling `magic` to magic.mgc")
    os.system("file -C -m magic")
    print(" * compiled, usage : file -m magic <file>.pdb")

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
