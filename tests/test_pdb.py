#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pdb"""

import os
from warnings import filterwarnings as filter_warnings

import armour

SALT: bytes = b"this is a salt used for security, in this test it will b static"
PASSWORD: bytes = b"this is my very cool password :)"
FILE: str = "pdb.pdb"
HASH_ID: int = 2
ISEC_PASSES: int = 2


def main() -> int:
    """entry / main function"""

    p: armour.pdb.header.PdbHeader

    if os.path.isfile("pdb.pdb"):
        with open(FILE, "rb") as fp:
            p = armour.pdb.header.PdbHeader.from_db(fp.read(), PASSWORD, SALT)
    else:
        p = armour.pdb.header.PdbHeader.empty(PASSWORD, SALT)
        p.kdf_passes = 1
        p.hash_id = HASH_ID
        p.zstd_comp_lvl = 22
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

    # > key identifers may duplicate, although the most recent one will dominate
    e = armour.pdb.entries.PdbEntries(p)
    e.gather()
    pwe: armour.pdb.entries.PdbPwdEntry
    e.add_entry(
        pwe := armour.pdb.entries.PdbPwdEntry(
            p,
            fields={
                b"n": f"hello world ! {armour.crypt.RAND.randint(-100, 100)} \
{armour.crypt.RAND.random()} {len(e.ents)}".encode(),
                b"p": b"my password 124",
                b"r": b"this is my remark :)",
                b"u": b"super secret user",
            },
        ).rehash()
    )
    pwe.username = b"hi"

    print(pwe.username)
    # pwe[b"u"] = b"hello !"
    pwe.rehash()
    # print(pwe.get_field_raw(b"u"))

    print()
    print(e)
    print()

    print(
        f"""--- pre-dump ---

{p}"""
    )

    e.commit()

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
