#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exceptions

if u add any exceptions please make any following arguments after first one
optional due to multiprocessing weirdness"""

from ..crypt import HASHES


class InvalidMagicError(Exception):
    """raised when the pdb magic bytes are invalid"""

    def __init__(self, magic: bytes, valid_magic: bytes = b"") -> None:
        super().__init__(
            f"invalid pdb magic bytes -- {magic!r} ( should b {valid_magic!r} )"
        )
        self.magic: bytes = magic
        self.valid_magic: bytes = valid_magic


class VersionMismatch(Exception):
    """raised when the format of a pdb db is in one version when another is required"""

    def __init__(self, cur_v: int, db_v: int = 0) -> None:
        super().__init__(f"version mismatch -- {db_v!r} db, while parser needs {cur_v}")
        self.cur_v: int = cur_v
        self.db_v: int = db_v


class DataIntegrityError(Exception):
    """invalid data hash"""

    def __init__(self, msg: str, h: bytes = b"") -> None:
        super().__init__(msg)
        self.h: bytes = h


class InvalidHashID(Exception):
    """invalid hash id"""

    def __init__(self, hash_id: int) -> None:
        super().__init__(
            f"invalid hash_id {hash_id!r}, min hash_id is 0 and max is {len(HASHES)}"
        )
        self.hash_id: int = hash_id


class InvalidZSTDCompressionLvl(Exception):
    """invalid zstd compression level"""

    def __init__(self, lvl: int) -> None:
        super().__init__(f"invalid ZSTD compression level {lvl!r}")
        self.lvl: int = lvl


class InvalidZeroValue(Exception):
    """zero value in an invalid place"""


class StructureError(Exception):
    """raised when the structure of an entry is invalid"""

    def __init__(self, entry_id: int) -> None:
        super().__init__(f"entry #{entry_id} has invalid structure")
        self.entry_id: int = entry_id


class InvalidIdentifier(Exception):
    """raised when the identifier is invalid"""

    def __init__(self, ident: bytes, entry_id: int = 0) -> None:
        super().__init__(f"identifier {ident!r} of entry #{entry_id} is invalid")

        self.ident: bytes = ident
        self.entry_id: int = entry_id
