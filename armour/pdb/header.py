#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pdb header"""

import struct
import typing
from dataclasses import dataclass
from io import BytesIO

import zstd

from .. import crypt
from . import exc

MAGIC: bytes = b"pDB\xf6"
VERSION: int = 0
KDF_PASSES: int = 1048576  # 2 ** 20
HASH_SALT_LEN: int = 64
ZSTD_MAX_COMPRESSION: int = 22


def unpack(fmt: str, data: bytes) -> typing.Any:
    """unpack bytes to primative types"""
    return struct.unpack(fmt, data)[0]


def pack(fmt: str, data: typing.Any) -> bytes:
    """pack bytes into bytes"""
    return struct.pack(fmt, data)


@dataclass
class PdbHeader:
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

    def ds(self, hash_id: typing.Optional[int] = None) -> int:
        """return the secure digest size"""

        if hash_id is None:
            hash_id = self.hash_id

        return self.hash_salt_len + crypt.HASHES[hash_id].digest_size

    @classmethod
    def from_db(cls, db: bytes, password: bytes, salt: bytes) -> "PdbHeader":
        """parse header from db"""

        sds: int = crypt.HASHES[0].digest_size

        if not crypt.hash_walgo_compare(
            0,
            (db := db[:-sds]),
            password,
            salt,
            KDF_PASSES,
            HASH_SALT_LEN,
            (db_hash := db[-sds:]),
        ):
            raise exc.DataIntegrityError(
                f"invalid database hash {db_hash!r} -- not trying to parse it",
                db_hash,
            )

        b: BytesIO = BytesIO(db)

        magic: bytes = b.read(4)

        if magic != MAGIC:
            raise exc.InvalidMagicError(magic, MAGIC)

        version: int = unpack("<H", b.read(2))

        if version != VERSION:
            raise exc.VersionMismatch(VERSION, version)

        hash_id: int = int(b.read(1))

        if hash_id > len(crypt.HASHES) or hash_id < 0:
            raise exc.InvalidHashID(hash_id)

        zstd_comp_lvl: int = int(b.read(1))

        if zstd_comp_lvl > ZSTD_MAX_COMPRESSION or zstd_comp_lvl < 0:
            raise exc.InvalidZSTDCompressionLvl(zstd_comp_lvl)

        if (hash_salt_len := int(b.read())) == 0:
            raise exc.InvalidZeroValue("hash_salt_len cannot be zero")

        # secure hash prepends hash_salt_len bytes
        ds: int = hash_salt_len + crypt.HASHES[hash_id].digest_size

        if (kdf_passes := unpack("<L", b.read(4))) == 0:
            raise exc.InvalidZeroValue("kdf_passes cannot be zero")

        sec_crypto_passes: int = unpack("<H", b.read(2))
        isec_crypto_passes: int = unpack("<H", b.read(2))
        aes_crypto_passes: int = unpack("<H", b.read(2))

        entries_hash: bytes = b.read(ds)

        if not crypt.hash_walgo_compare(
            hash_id,
            (entries := b.read()[:-sds]),
            password,
            salt,
            KDF_PASSES,
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

    def to_db(self) -> bytes:
        """convert a header object to the database"""

        sds: int = self.ds(0)
        ds: int = self.ds()

        db: bytes = (
            pack("<4B", self.magic)
            + pack("<H", self.version)
            + pack("<B", self.hash_id)
            + pack("<B", self.zstd_comp_lvl)
            + pack("<B", self.hash_salt_len)
            + pack("<L", self.kdf_passes)
            + pack("<H", self.sec_crypto_passes)
            + pack("<H", self.isec_crypto_passes)
            + pack("<H", self.aes_crypto_passes)
            + pack(
                f"<{ds}B",
                crypt.hash_walgo(
                    self.hash_id,
                    self.entries,
                    self.password,
                    self.salt,
                    self.kdf_passes,
                    self.hash_salt_len,
                ),
            )
            + self.entries
        )

        db += pack(
            f"<{sds}B",
            crypt.hash_walgo(
                0,
                db,
                self.password,
                self.salt,
                KDF_PASSES,
                HASH_SALT_LEN,
            ),
        )

        return db

    def encrypt(self) -> None:
        """self-encrypts"""

        if self.encrypted:
            return

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

    def decrypt(self) -> None:
        """self-decrypts"""

        if not self.encrypted:
            return

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

    def __str__(self) -> str:
        """shows db info"""

        s: str = " [insecure]" if self.hash_id > 9 else ""
        p: str = f"~{self.zstd_comp_lvl / ZSTD_MAX_COMPRESSION * 100:.2f}%"

        return f"""
version             {self.version}
magic               {self.magic!r}
hash_id             {self.hash_id} ( {crypt.HASHES[self.hash_id].name!r} ){s}
zstd_comp_lvl       {self.zstd_comp_lvl} ( {p} )
hash_salt_len       {self.hash_salt_len}
kdf_passes          {self.kdf_passes}
sec_crypto_passes   {self.sec_crypto_passes}
isec_crypto_passes  {self.isec_crypto_passes}
aes_crypto_passes   {self.aes_crypto_passes}
entries_hash        <... {len(self.entries_hash)} bytes>
entries             <... {len(self.entries)} bytes>
db_hash             <... {len(self.db_hash)} bytes>
digest_size         {self.ds()}
""".strip()