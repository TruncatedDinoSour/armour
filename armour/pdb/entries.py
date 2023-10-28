#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""entries"""

import multiprocessing as mp
from abc import ABC, abstractmethod
from contextlib import closing
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Type

from .. import crypt
from . import exc, header, s


def ___reval___(e: "PdbEntry") -> "PdbEntry":
    """revalidate entry ( do not use this, this is used in `gather` )"""
    return e.revalidate().validate_struct()


class PdbEntry(ABC):
    """entry abstract base class"""

    entry_id: int = 0

    def __init__(
        self,
        head: header.PdbHeader,
        ehash: bytes = b"",
        fields: Optional[Dict[bytes, bytes]] = None,
    ) -> None:
        self.entry_id: int = PdbEntry.entry_id
        PdbEntry.entry_id += 1

        self.head: header.PdbHeader = head
        self.ehash: bytes = ehash
        self.fields: Dict[bytes, bytes] = {}

        if fields is not None:
            for field, value in fields.items():
                self[field] = value

    def from_entry(self, entry: bytes) -> Any:
        """creates a new entry from binary data
        ( does not validate the hash )

        :rtype: Self"""

        b: BytesIO = BytesIO(entry)

        while (ident := b.read(s.BL)) != b"\0":
            self[ident] = b.read(s.sunpack(s.L, b))

        return self

    @property
    def entry(self) -> bytes:
        """return the non-full entry as bytes"""
        return b"".join(
            field + s.pack(s.L, len(data)) + data for field, data in self.fields.items()
        )

    @property
    def full_entry(self) -> bytes:
        """return the full entry ( hash + entry + NULL ) as bytes"""
        return self.ehash + self.entry + b"\0"

    def rehash(self) -> Any:
        """rehash the entry

        :rtype: Self"""

        self.ehash = crypt.hash_walgo(
            self.head.hash_id,
            self.entry,
            self.head.password,
            self.head.salt,
            self.head.kdf_passes,
            self.head.hash_salt_len,
        )

        return self

    def hash_ok(self) -> bool:
        """is the hash of the entry valid"""
        return crypt.hash_walgo_compare(
            self.head.hash_id,
            self.entry,
            self.head.password,
            self.head.salt,
            self.head.kdf_passes,
            self.head.hash_salt_len,
            self.ehash,
        )

    def revalidate(self) -> Any:
        """revalidate the hash

        :rtype: Self"""

        if not self.hash_ok():
            raise exc.DataIntegrityError(
                f"entry #{self.entry_id} has a bad hash / signature",
                self.ehash,
            )

        return self

    def set_field_raw(self, ident: bytes, value: bytes) -> Any:
        """set field ident to value

        :rtype: Self"""

        if ident == b"\0" or len(ident) != 1:
            raise exc.InvalidIdentifier(ident, self.entry_id)

        self.fields[ident] = value
        return self

    def get_field_raw(self, ident: bytes) -> bytes:
        """set field ident to value"""
        return self.fields[ident]

    def validate_struct(self) -> Any:
        """validate structure"""

        if not self.struct_valid:
            raise exc.StructureError(self.entry_id)

        return self

    @abstractmethod
    def set_field(self, ident: bytes, value: bytes) -> Any:
        """set field ident to value

        :rtype: Self"""
        return self  # for typing

    @abstractmethod
    def get_field(self, ident: bytes) -> bytes:
        """get field by ident"""

    @property
    @abstractmethod
    def struct_valid(self) -> bool:
        """check if the structure of the entry is valid"""

    @abstractmethod
    def __str__(self) -> str:
        """stringify entry"""

    def __contains__(self, ident: bytes) -> bool:
        """does the entry contain `ident` field"""
        return ident in self.fields

    def __setitem__(self, ident: bytes, value: bytes) -> None:
        """wrapper for `set_field`"""
        self.set_field(ident, value)

    def __getitem__(self, ident: bytes) -> bytes:
        """wrapper for `get_field`"""
        return self.get_field(ident)


class PdbRawEntry(PdbEntry):
    """pdb entries raw entry"""

    def set_field(self, ident: bytes, value: bytes) -> "PdbRawEntry":
        """set field ident to value

        :rtype: Self"""
        return self.set_field_raw(ident, value)

    def get_field(self, ident: bytes) -> bytes:
        """get field by ident"""
        return self.get_field_raw(ident)

    @property
    def struct_valid(self) -> bool:
        """check if the structure of the entry is valid"""
        return True

    def __str__(self) -> str:
        """shows all fields in the entry"""
        return "\n".join(
            f"field {field!r:10s} -- {data!r}" for field, data in self.fields.items()
        )


class PdbPwdEntry(PdbEntry):
    """pdb entries password entry"""

    all_fields: Tuple[bytes, ...] = b"n", b"u", b"p", b"r"
    encrypted_fields: Tuple[bytes, ...] = b"u", b"p"

    def _get_crypt(self, ident: bytes) -> bytes:
        """get an encrypted value"""
        return crypt.decrypt_secure(
            self.get_field_raw(ident),
            self.head.password,
            self.head.salt,
            self.head.hash_id,
            self.head.hash_salt_len,
            self.head.sec_crypto_passes,
            self.head.kdf_passes,
        )

    def _set_crypt(self, ident: bytes, value: bytes) -> None:
        """set an encrypted value"""

        if ident == b"\0" or len(ident) != 1:
            raise exc.InvalidIdentifier(ident, self.entry_id)

        self.set_field_raw(
            ident,
            crypt.encrypt_secure(
                value,
                self.head.password,
                self.head.salt,
                self.head.hash_id,
                self.head.hash_salt_len,
                self.head.sec_crypto_passes,
                self.head.kdf_passes,
                self.head.zstd_comp_lvl,
            ),
        )

    # name

    @property
    def name(self) -> bytes:
        """get name"""
        return self[b"n"]

    @name.setter
    def name(self, value: bytes) -> None:
        """set name"""
        self[b"n"] = value

    # username

    @property
    def username(self) -> bytes:
        """get username"""
        return self[b"u"]

    @username.setter
    def username(self, value: bytes) -> None:
        """set username"""
        self[b"u"] = value

    # password

    @property
    def password(self) -> bytes:
        """get password"""
        return self[b"p"]

    @password.setter
    def password(self, value: bytes) -> None:
        """set password"""
        self[b"p"] = value

    # remark

    @property
    def remark(self) -> bytes:
        """get remark"""
        return self[b"r"]

    @remark.setter
    def remark(self, value: bytes) -> None:
        """set remark"""
        self[b"r"] = value

    def set_field(
        self,
        ident: bytes,
        value: bytes,
    ) -> "PdbPwdEntry":
        """set field ident to value"""

        if ident in self.encrypted_fields:
            self._set_crypt(ident, value)
        else:
            self.set_field_raw(ident, value)

        return self

    def get_field(self, ident: bytes) -> bytes:
        """set field ident to value"""
        return (
            self._get_crypt(ident)
            if ident in self.encrypted_fields
            else self.get_field_raw(ident)
        )

    @property
    def struct_valid(self) -> bool:
        """check if the structure of the entry is valid"""
        return all(field in self.fields for field in PdbPwdEntry.all_fields)

    def __str__(self) -> str:
        """shows all fields in the entry"""
        return "\n".join(
            f"field {field!r:10s} -- \
{'***' if field in self.encrypted_fields else repr(data)}"
            for field, data in self.fields.items()
        )


class PdbEntries:
    """stores all entries in a database"""

    def __init__(
        self,
        head: header.PdbHeader,
    ) -> None:
        self.ents: List[PdbEntry] = []
        self.head: header.PdbHeader = head

    def gather(
        self,
        entry_t: Type[PdbEntry] = PdbPwdEntry,
        jobs: Optional[int] = None,
    ) -> "PdbEntries":
        """gather all entries from the header, uses multiprocessing"""

        self.head.decrypt()

        if not self.head.entries:
            return self

        b: BytesIO = BytesIO(self.head.entries)
        ents: List[PdbEntry] = []

        while (h := b.read(self.head.ds())) != b"":
            e: PdbEntry = entry_t(self.head, h)

            while (ident := b.read(s.BL)) != b"\0":
                e.set_field_raw(ident, b.read(s.sunpack(s.L, b)))

            ents.append(e)

        with closing(mp.Pool(processes=jobs)) as p:
            self.ents.extend(p.map(___reval___, ents))

        return self

    def clear(self) -> "PdbEntries":
        """clears all entries"""
        self.ents.clear()
        return self

    def add_entry(self, entry: PdbEntry) -> "PdbEntries":
        """add entry"""

        self.ents.append(entry.revalidate().validate_struct())
        return self

    @property
    def db_entries(self) -> bytes:
        """get all entries as bytes"""
        return b"".join(e.full_entry for e in self.ents)

    def commit(self) -> "PdbEntries":
        """push all entries to the database"""

        self.head.decrypt()
        self.head.entries = self.db_entries
        return self

    def __str__(self) -> str:
        """lists all entries"""
        return "\n\n".join(
            f"--- entry #{idx} ---\n{e}" for idx, e in enumerate(self.ents)
        )
