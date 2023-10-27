#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""armour"""

from typing import Final, Tuple

from . import crypt, gen, pdb

__version__: Final[str] = "1.0.2"

__all__: Final[Tuple[str, ...]] = "__version__", "crypt", "gen", "pdb"
