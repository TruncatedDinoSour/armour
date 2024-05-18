#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a pDBv1 header."""

import hashlib
import struct
import sys
from io import BytesIO
from warnings import filterwarnings as filter_warnings


def main() -> int:
    """entry / main function"""

    psalt: bytes = b"This is a `psalt`: " + bytes(range(256))
    metadata: bytes = b"Note: This is my metadata."

    fp: BytesIO = BytesIO()

    fp.write(b"pDB\xf6")  # Magic
    fp.write(struct.pack("<H", 1))  # Version
    fp.write(struct.pack("<B", 0))  # ZSTD_compression level
    fp.write(struct.pack("<B", 0))  # Argon2_type
    fp.write(struct.pack("<I", 3))  # Argon2_time_cost
    fp.write(struct.pack("<I", 2**16))  # Argon2_memory_cost
    fp.write(struct.pack("<I", len(psalt)))  # psalt_size
    fp.write(struct.pack(f"<{len(psalt)}s", psalt))  # psalt
    fp.write(struct.pack("<H", 8))  # salt_size
    fp.write(struct.pack("<H", 64))  # authentication_size
    fp.write(struct.pack("<H", 1))  # keyfile_crypto_passes
    fp.write(struct.pack("<H", 1))  # chunk_identifier_size
    fp.write(struct.pack("<H", 128))  # chunk_size

    ms: bytes = struct.pack("<I", len(metadata))

    fp.write(
        struct.pack("<64s", hashlib.sha3_512(ms + metadata).digest())
    )  # metadata_hash_SHA3_512
    fp.write(ms)  # metadata_size
    fp.write(metadata)  # metadata

    # header_hash_SHA3_512

    fp.seek(0)
    header_bytes: bytes = fp.read()
    fp.write(struct.pack("<64s", hashlib.sha3_512(header_bytes).digest()))

    # lock

    fp.write(b"\0")

    # Write final output.

    sys.stdout.buffer.write(fp.getvalue())
    sys.stdout.buffer.flush()

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
