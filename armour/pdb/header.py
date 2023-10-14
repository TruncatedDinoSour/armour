#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pdb header"""

import typing
from dataclasses import dataclass
from io import BytesIO

import zstd

from .. import crypt
from . import exc, s

MAGIC: bytes = b"pDB\xf6"
VERSION: int = 0
KDF_PASSES: int = 1048576  # 2 ** 20
HASH_SALT_LEN: int = 64
ZSTD_MAX_COMPRESSION: int = 22


@dataclass
class PdbHeader:
    """pdb header and base parser"""

    password: bytes
    salt: bytes

    magic: bytes
    version: int
    hash_id: int
    zstd_comp_lvl: int
    hash_salt_len: int
    kdf_passes: int
    sec_crypto_passes: int
    isec_crypto_passes: int
    aes_crypto_passes: int
    entries_hash: bytes
    entries: bytes
    db_hash: bytes

    encrypted: bool = True

    @staticmethod
    def dds(hash_id: int) -> int:
        """return hash digest size"""
        return crypt.HASHES[hash_id].digest_size

    def ds(self, hash_id: typing.Optional[int] = None) -> int:
        """return the secure digest size"""

        if hash_id is None:
            hash_id = self.hash_id

        return self.hash_salt_len + self.dds(hash_id)

    @classmethod
    def empty(cls, password: bytes = b"", salt: bytes = b"") -> "PdbHeader":
        """return an empty PdbHeader w default preset values"""
        return cls(
            password=password,
            salt=salt,
            magic=MAGIC,
            version=VERSION,
            hash_id=0,
            zstd_comp_lvl=ZSTD_MAX_COMPRESSION,
            hash_salt_len=19,
            kdf_passes=384000,
            sec_crypto_passes=8,
            isec_crypto_passes=64,
            aes_crypto_passes=8,
            entries_hash=b"",
            entries=b"",
            db_hash=b"",
            encrypted=False,
        )

    @classmethod
    def from_db(
        cls,
        db: bytes,
        password: bytes = b"",
        salt: bytes = b"",
    ) -> "PdbHeader":
        """parse header from db"""

        sds: int = cls.dds(0) + HASH_SALT_LEN

        db_hash: bytes = db[-sds:]

        if not crypt.hash_walgo_compare(
            0,
            (db := db[:-sds]),
            password,
            salt,
            KDF_PASSES,
            HASH_SALT_LEN,
            db_hash,
        ):
            raise exc.DataIntegrityError(
                f"invalid database hash {db_hash!r} -- not trying to parse it",
                db_hash,
            )

        b: BytesIO = BytesIO(db)

        magic: bytes = b.read(s.MAGIC)

        if magic != MAGIC:
            raise exc.InvalidMagicError(magic, MAGIC)

        version: int = s.sunpack(s.S, b)

        if version != VERSION:
            raise exc.VersionMismatch(VERSION, version)

        hash_id: int = s.sunpack(s.B, b)

        if hash_id > len(crypt.HASHES) or hash_id < 0:
            raise exc.InvalidHashID(hash_id)

        zstd_comp_lvl: int = s.sunpack(s.B, b)

        if zstd_comp_lvl > ZSTD_MAX_COMPRESSION or zstd_comp_lvl < 0:
            raise exc.InvalidZSTDCompressionLvl(zstd_comp_lvl)

        if (hash_salt_len := s.sunpack(s.B, b)) == 0:
            raise exc.InvalidZeroValue("hash_salt_len cannot be zero")

        # secure hash prepends hash_salt_len bytes
        ds: int = hash_salt_len + crypt.HASHES[hash_id].digest_size

        if (kdf_passes := s.sunpack(s.L, b)) == 0:
            raise exc.InvalidZeroValue("kdf_passes cannot be zero")

        sec_crypto_passes: int = s.sunpack(s.S, b)
        isec_crypto_passes: int = s.sunpack(s.S, b)
        aes_crypto_passes: int = s.sunpack(s.S, b)

        entries_hash: bytes = b.read(ds)

        if not crypt.hash_walgo_compare(
            hash_id,
            (entries := b.read()),
            password,
            salt,
            kdf_passes,
            hash_salt_len,
            entries_hash,
        ):
            raise exc.DataIntegrityError(
                f"invalid entries hash {entries_hash!r}",
                entries_hash,
            )

        return cls(
            password=password,
            salt=salt,
            magic=magic,
            version=version,
            hash_id=hash_id,
            zstd_comp_lvl=zstd_comp_lvl,
            hash_salt_len=hash_salt_len,
            kdf_passes=kdf_passes,
            sec_crypto_passes=sec_crypto_passes,
            isec_crypto_passes=isec_crypto_passes,
            aes_crypto_passes=aes_crypto_passes,
            entries_hash=entries_hash,
            entries=entries,
            db_hash=db_hash,
        )

    def hash_entries(self) -> bytes:
        """hash entries and return their hash"""

        self.encrypt()

        self.entries_hash = crypt.hash_walgo(
            self.hash_id,
            self.entries,
            self.password,
            self.salt,
            self.kdf_passes,
            self.hash_salt_len,
        )

        return self.entries_hash

    def hash_db(self, db: bytes) -> bytes:
        """hash a db and return its hash"""

        self.db_hash = crypt.hash_walgo(
            0,
            db,
            self.password,
            self.salt,
            KDF_PASSES,
            HASH_SALT_LEN,
        )

        return self.db_hash

    def to_db(self) -> bytes:
        """to db"""

        self.encrypt()

        return (
            self.magic
            + s.pack(s.S, self.version)
            + s.pack(s.B, self.hash_id)
            + s.pack(s.B, self.zstd_comp_lvl)
            + s.pack(s.B, self.hash_salt_len)
            + s.pack(s.L, self.kdf_passes)
            + s.pack(s.S, self.sec_crypto_passes)
            + s.pack(s.S, self.isec_crypto_passes)
            + s.pack(s.S, self.aes_crypto_passes)
            + self.hash_entries()
            + self.entries
        )

    def to_pdb(self) -> bytes:
        """to pdb"""
        self.encrypt()
        return (db := self.to_db()) + self.hash_db(db)

    def encrypt(self) -> "PdbHeader":
        """self-encrypts"""

        if self.encrypted:
            return self

        entries: bytes = crypt.encrypt_secure(
            self.entries,
            self.password,
            self.salt,
            self.hash_id,
            self.hash_salt_len,
            self.sec_crypto_passes,
            self.kdf_passes,
            self.zstd_comp_lvl,
        )

        entries = crypt.encrypt_aes(
            entries,
            self.password,
            self.hash_id,
            self.kdf_passes,
            self.hash_salt_len,
            self.aes_crypto_passes,
        )

        entries = zstd.compress(
            entries,
            self.zstd_comp_lvl,
            zstd.ZSTD_threads_count(),
        )

        entries = crypt.encrypt_rc4(
            entries,
            self.isec_crypto_passes,
            self.password,
            self.salt,
            self.hash_salt_len,
        )

        self.entries = entries
        self.encrypted = True

        return self

    def decrypt(self) -> "PdbHeader":
        """self-decrypts"""

        if not self.encrypted:
            return self

        entries: bytes = crypt.decrypt_rc4(
            self.entries,
            self.isec_crypto_passes,
            self.password,
            self.salt,
            self.hash_salt_len,
        )

        entries = zstd.decompress(entries)

        entries = crypt.decrypt_aes(
            entries,
            self.password,
            self.hash_id,
            self.kdf_passes,
            self.hash_salt_len,
            self.aes_crypto_passes,
        )

        entries = crypt.decrypt_secure(
            entries,
            self.password,
            self.salt,
            self.hash_id,
            self.hash_salt_len,
            self.sec_crypto_passes,
            self.kdf_passes,
        )

        self.entries = entries
        self.encrypted = False

        return self

    def __str__(self) -> str:
        """shows db info"""

        sec: str = " [insecure]" if self.hash_id > 9 else ""
        p: str = f"~{self.zstd_comp_lvl / ZSTD_MAX_COMPRESSION * 100:.2f}%"

        return f"""
version             {self.version}
magic               {self.magic!r}
hash_id             {self.hash_id} ( {crypt.HASHES[self.hash_id].name!r} ){sec}
zstd_comp_lvl       {self.zstd_comp_lvl} ( {p} )
hash_salt_len       {self.hash_salt_len}
kdf_passes          {self.kdf_passes}
sec_crypto_passes   {self.sec_crypto_passes}
isec_crypto_passes  {self.isec_crypto_passes}
aes_crypto_passes   {self.aes_crypto_passes}
entries_hash        <... {len(self.entries_hash)} bytes>
entries             <... {len(self.entries)} bytes>
db_hash             <... {len(self.db_hash)} bytes>
encrypted           {self.encrypted}
digest_size         {self.ds()}
""".strip()
