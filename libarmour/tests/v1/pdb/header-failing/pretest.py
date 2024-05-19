#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a valid pDBv1 header."""

import hashlib
import os
import struct
from io import BytesIO
from warnings import filterwarnings as filter_warnings


def main() -> int:
    """entry / main function"""

    print("Pre-generating psalt and metadata")

    psalt: bytes = b"This is a `psalt`: " + os.urandom(256)
    metadata: bytes = b"Note: This is metadata. It should get stored as plain-text."

    bp: BytesIO = BytesIO()

    print("Generating fixed values")

    bp.write(b"pDB\xf6")  # Magic
    bp.write(struct.pack("<H", 1))  # Version
    bp.write(struct.pack("<B", 13))  # ZSTD_compression level
    bp.write(struct.pack("<B", 2))  # Argon2_type
    bp.write(struct.pack("<I", 3))  # Argon2_time_cost
    bp.write(struct.pack("<I", 2**16 + 1))  # Argon2_memory_cost
    bp.write(struct.pack("<I", len(psalt)))  # psalt_size
    bp.write(struct.pack(f"<{len(psalt)}s", psalt))  # psalt
    bp.write(struct.pack("<H", 19))  # salt_size
    bp.write(struct.pack("<H", 94))  # authentication_size
    bp.write(struct.pack("<H", 4))  # keyfile_crypto_passes
    bp.write(struct.pack("<H", 66))  # chunk_identifier_size
    bp.write(struct.pack("<H", 123))  # chunk_size

    print("Generating the metadata section")

    ms: bytes = struct.pack("<I", len(metadata))

    bp.write(
        struct.pack("<64s", hashlib.sha3_512(ms + metadata).digest())
    )  # metadata_hash_SHA3_512
    bp.write(ms)  # metadata_size
    bp.write(metadata)  # metadata

    # header_hash_SHA3_512

    print("Hashing the whole header")

    bp.seek(0)
    header_bytes: bytes = bp.read()
    bp.write(struct.pack("<64s", hashlib.sha3_512(header_bytes).digest()))

    # lock

    print("Marking database as unlocked")

    bp.write(b"\0")

    # Write final output.

    with open("f:test.pdb", "wb") as fp:
        fp.write(bp.getvalue())
        print(f"Generated {fp.name}")

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
