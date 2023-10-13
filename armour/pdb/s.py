#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""structs"""

import struct
from io import BytesIO
from typing import Any, Final

S: Final[str] = "H"
SL: Final[int] = 2

B: Final[str] = "B"
BL: Final[int] = 1

MAGIC: Final[int] = BL * 4

L: Final[str] = "L"
LL: Final[int] = 4


def unpack(fmt: str, data: bytes) -> Any:
    """unpack bytes to primative types"""
    return struct.unpack(f"<{fmt}", data)[0]


def pack(fmt: str, data: Any) -> bytes:
    """pack bytes into bytes"""
    return struct.pack(f"<{fmt}", data)


def sunpack(fmt: str, b: BytesIO) -> Any:
    """unpack from a bytes stream"""
    fmt = f"<{fmt}"
    return struct.unpack(fmt, b.read(struct.calcsize(fmt)))[0]
