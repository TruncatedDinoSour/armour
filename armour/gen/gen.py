#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""password generator"""

import secrets
import string
from dataclasses import dataclass
from typing import Callable, Final, Optional, SupportsInt, Tuple

from ..crypt import RAND
from .info import PasswordInfo

D: Final[int] = -1


@dataclass
class PwGenerator:
    """password generator"""

    rand: secrets.SystemRandom = RAND
    byteset: Optional[bytes] = string.printable.strip().encode()

    length: int = 128

    min_lower: int = D
    min_upper: int = D
    min_numbers: int = D
    min_special: int = D
    min_alphabet: int = D
    max_sequences: int = D
    max_common_patterns: int = D
    min_entropy: float = D
    min_strength: float = D
    max_weakness: float = D
    min_actual_strength: float = D

    max_passes: Optional[int] = 1024

    def checks(
        self, pw: PasswordInfo
    ) -> Tuple[Tuple[SupportsInt, Callable[..., bool]], ...]:
        """returns a tuple of checks"""
        return (
            (self.min_lower, lambda: len(pw.lower) < self.min_lower),
            (self.min_upper, lambda: len(pw.upper) < self.min_upper),
            (self.min_numbers, lambda: len(pw.numbers) < self.min_numbers),
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
                lambda: pw.actual_strength() < self.min_actual_strength,
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
            if check != D and fn():
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
