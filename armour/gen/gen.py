#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""password generator"""

import secrets
import string
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..crypt import RAND
from .info import PasswordInfo


@dataclass
class PwGenerator:
    """password generator"""

    rand: secrets.SystemRandom = RAND
    byteset: Optional[bytes] = string.printable.strip().encode()

    length: int = 128

    min_lower: int = -1
    min_upper: int = -1
    min_numbers: int = -1
    min_special: int = -1
    min_alphabet: int = -1
    max_sequences: int = -1
    max_common_patterns: int = -1
    min_entropy: int = -1
    min_strength: int = -1
    max_weakness: int = -1
    min_actual_strength: int = -1

    max_passes: Optional[int] = 1024

    def checks(self, pw: PasswordInfo) -> Tuple[Tuple[int, Callable[..., bool]], ...]:
        """returns a tuple of checks"""
        return (
            (self.min_lower, lambda: len(pw.lower) < self.min_lower),
            (self.min_upper, lambda: len(pw.upper) < self.min_upper),
            (self.min_numbers, lambda: len(pw.numbers) < self.min_upper),
            (self.min_special, lambda: len(pw.special) < self.min_special),
            (self.min_alphabet, lambda: len(pw.alphabet) < self.min_alphabet),
            (
                self.max_sequences,
                lambda: pw.sequences_count() > self.max_sequences,
            ),
            (
                self.max_common_patterns,
                lambda: len(pw.common_patterns()) > self.max_common_patterns,
            ),
            (self.min_entropy, lambda: pw.entropy() < self.min_entropy),
            (self.min_strength, lambda: pw.strength() < self.min_strength),
            (self.max_weakness, lambda: pw.weakness() > self.max_weakness),
            (
                self.min_actual_strength,
                lambda: pw.actual_strength() < self.max_weakness,
            ),
        )

    def gen_one(self, pw: PasswordInfo) -> Optional[PasswordInfo]:
        """generate the passowrd ( one pass ), returns `None` on criteria failure"""

        pw.pw = (
            self.rand.randbytes(self.length)
            if self.byteset is None
            else bytes(self.rand.choice(self.byteset) for _ in range(self.length))
        )

        for check, fn in self.checks(pw):
            if check != -1 and fn():
                return None

        return pw

    def gen(self) -> Optional[PasswordInfo]:
        """generate a password ( returns `None` if no valid one could b generated )"""

        pwi: PasswordInfo = PasswordInfo()
        pw: Optional[PasswordInfo] = None

        if self.max_passes is None:
            while (pw := self.gen_one(pwi)) is None:
                pass
        else:
            for _ in range(self.max_passes):
                if (pw := self.gen_one(pwi)) is not None:
                    return pw

        return pw
