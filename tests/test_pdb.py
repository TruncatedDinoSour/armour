#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pdb"""

import os
import struct
from warnings import filterwarnings as filter_warnings

import armour.crypt
import armour.pdb

SALT: bytes = b"this is a salt used for security, in this test it will b static"
PASSWORD: bytes = b"this is my very cool password :)"
FILE: str = "pdb.pdb"
HASH_ID: int = 1
ISEC_PASSES: int = 1


def main() -> int:
    """entry / main function"""

    p: armour.pdb.header.PdbHeader

    if os.path.isfile("pdb.pdb"):
        with open(FILE, "rb") as fp:
            p = armour.pdb.header.PdbHeader.from_db(fp.read(), PASSWORD, SALT)
    else:
        p = armour.pdb.header.PdbHeader.empty(PASSWORD, SALT)
        p.hash_id = HASH_ID
        p.zstd_comp_lvl = 11
        p.isec_crypto_passes = ISEC_PASSES
        p.encrypt()

    print(
        f"""--- encrypted ---

{p.encrypt()}
"""
    )

    print(
        f"""--- decrypyed ---

{p.decrypt()}
"""
    )

    print("creating an entry")

    data: bytes = b"hello world ! " + str(armour.crypt.RAND.random()).encode()

    # > key identifers may duplicate, although the most recent one will dominate
    entry: bytes = b"a"  # entry name ( one char )
    entry += struct.pack("<L", len(data))  # data size
    entry += data  # data itself
    entry = (  # <entry hash><entry>
        armour.crypt.hash_walgo(
            HASH_ID,
            entry,
            PASSWORD,
            SALT,
            384000,
            19,
        )
        + entry
    )
    entry += b"\0"  # end of entry byte ( eoe )

    p.entries += entry  # add the entry to the entries

    print(p.entries, "")

    print(
        f"""--- pre-dump ---

{p}"""
    )

    with open(FILE, "wb") as fp:
        print(f"wrote {fp.write(p.to_pdb())} b to {fp.name}\n")

    print(
        f"""--- post-dump ---

{p}"""
    )

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
