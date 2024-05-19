#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a valid Keyfile header"""

import hashlib
import os
import struct
from io import BytesIO
from warnings import filterwarnings as filter_warnings


def main() -> int:
    """entry / main function"""

    print("Pre-genering pepper, salt and database bytes")

    pepper: bytes = b"This is pepper bytes: "
    pepper += os.urandom(64 - len(pepper))

    salt: bytes = b"This is a salt: "
    salt += os.urandom(512 - len(salt))

    db: bytes = os.urandom(64)  # Some garbage data

    bp: BytesIO = BytesIO()

    bp.write(b"pdKf")  # Magic
    bp.write(struct.pack("<H", 0))  # Version
    bp.write(struct.pack("<512s", salt))  # Salt
    bp.write(struct.pack("<H", 9))  # db_AES_crypto_passes
    bp.write(struct.pack("<H", 23))  # db_ChaCha20_Poly1305_crypto_passes
    bp.write(struct.pack("<64s", pepper))  # db_pepper

    print("Hashing resources")
    bp.write(hashlib.sha3_512(bp.getvalue()).digest())  # header_sha3_512_sum
    bp.write(hashlib.sha3_512(db).digest())  # sha3_512_sum
    bp.write(b"\0" + db)  # Lock + Keys

    with open("f:test.pkf", "wb") as fp:
        fp.write(bp.getvalue())
        print(f"Generated {fp.name}")

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
