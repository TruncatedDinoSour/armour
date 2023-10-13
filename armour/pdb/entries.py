#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""entries"""

from io import BytesIO
from typing import Dict, List, Optional

from .. import crypt
from . import exc, header, s


class PdbEntry:
    """pdb entries entry"""

    def __init__(
        self,
        head: header.PdbHeader,
        ehash: bytes = b"",
        fields: Optional[Dict[bytes, bytes]] = None,
    ) -> None:
        self.head: header.PdbHeader = head
        self.ehash: bytes = ehash
        self.fields: Dict[bytes, bytes] = fields or {}

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

    def rehash(self) -> "PdbEntry":
        """rehash the entry"""

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

    def set_field(self, name: bytes, value: bytes) -> "PdbEntry":
        """set field name to value"""

        self.fields[name] = value
        return self

    def __setitem__(self, name: bytes, value: bytes) -> None:
        """wrapper for `set_field`"""
        self.set_field(name, value)

    def __getitem__(self, name: bytes) -> bytes:
        """gets the field value by name"""
        return self.fields[name]

    def __str__(self) -> str:
        """shows all fields in the entry"""
        return "\n".join(
            f"field {field!r:10s} -- {data!r}" for field, data in self.fields.items()
        )


class PdbEntries:
    """stores all entries in a database"""

    def __init__(self, head: header.PdbHeader) -> None:
        self.ents: List[PdbEntry] = []
        self.head: header.PdbHeader = head

    def gather(self) -> "PdbEntries":
        """gather all entries from the header"""

        self.head.decrypt()

        if not self.head.entries:
            return self

        b: BytesIO = BytesIO(self.head.entries)

        while (h := b.read(self.head.ds())) != b"":
            e: PdbEntry = PdbEntry(self.head, h)

            while (ident := b.read(s.BL)) != b"\0":
                e[ident] = b.read(s.sunpack(s.L, b))

            self.ents.append(e)

        return self

    def add_entry(self, entry: PdbEntry) -> "PdbEntries":
        """add entry"""

        if not entry.hash_ok():
            raise exc.DataIntegrityError(
                "entry has a bad hash / signature",
                entry.ehash,
            )

        self.ents.append(entry)
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
